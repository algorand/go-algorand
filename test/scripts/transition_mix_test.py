#!/usr/bin/env python3
#
# Test for a network in transition.
# Runs a 6 node network with the following topology:
#
# New Leaf 1                           New Leaf 2
#            > New Relay - Old Relay <
# Old Leaf 1                           Old Leaf 2
#
# "New" and "Old" can mean different algod/goal/kmd binary versions.
# It can also or separately mean config.json updates. (set --old-bin
# and --new-bin to the same dir, set --new-config or --old-config to
# overlay json onto the net temlplate generated config.json of new or
# old nodes.
#
# In the test each leaf submits a simple payment transaction from its
# unlocked wallet to a dummy account '\x00...\x0N'. A few rounds are
# waited then each leaf verifies that it can see all the expected
# account values.
#
# The test then waits 100 rounds and checks that the 4 leaves are each
# a block proposer a reasonable fraction of the 100 rounds.

import argparse
import atexit
import glob
import json
import logging
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time

# pip install py-algorand-sdk
import algosdk

logger = logging.getLogger(__name__)

scriptdir = os.path.dirname(os.path.realpath(__file__))
repodir =  os.path.join(scriptdir, "..", "..")

_onbranch = 'On branch '

def getbranch(rd):
    result = subprocess.run(['git', 'status', '-b'], cwd=rd, capture_output=True, timeout=3)
    for line in result.stdout.decode().splitlines():
        if line.startswith(_onbranch):
            return line[len(_onbranch):]
    return None

def get_go_env():
    out = {}
    result = subprocess.run(['go', 'env'], capture_output=True)
    for line in result.stdout.decode().splitlines():
        line = line.strip()
        # TODO: is there a better way to parse sh-like k=v (possibly with quoting)?
        k,v = line.split('=', 1)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out

def openkmd(algodata):
    kmdnetpath = sorted(glob.glob(os.path.join(algodata,'kmd-*','kmd.net')))[-1]
    kmdnet = open(kmdnetpath, 'rt').read().strip()
    kmdtokenpath = sorted(glob.glob(os.path.join(algodata,'kmd-*','kmd.token')))[-1]
    kmdtoken = open(kmdtokenpath, 'rt').read().strip()
    kmd = algosdk.kmd.KMDClient(kmdtoken, 'http://' + kmdnet)
    return kmd

def openalgod(algodata):
    algodnetpath = os.path.join(algodata,'algod.net')
    algodnet = open(algodnetpath, 'rt').read().strip()
    algodtokenpath = os.path.join(algodata,'algod.token')
    algodtoken = open(algodtokenpath, 'rt').read().strip()
    algod = algosdk.v2client.algod.AlgodClient(algodtoken, 'http://' + algodnet)
    return algod


def maybedecode(x):
    if not x:
        return x
    if hasattr(x, 'decode'):
        return x.decode()
    return x

def reportcomms(p, stdout, stderr):
    cmdr = repr(p.args)
    if not stdout and p.stdout:
        stdout = p.stdout.read()
    if not stderr and p.stderr:
        stderr = p.stderr.read()
    if stdout:
        sys.stderr.write('output from {}:\n{}\n\n'.format(cmdr, maybedecode(stdout)))
    if stderr:
        sys.stderr.write('stderr from {}:\n{}\n\n'.format(cmdr, maybedecode(stderr)))

def xrun(cmd, *args, **kwargs):
    timeout = kwargs.pop('timeout', None)
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.STDOUT
    try:
        logger.debug('xrun: %r', cmd)
        p = subprocess.Popen(cmd, *args, **kwargs)
    except Exception as e:
        logger.error('subprocess failed {!r}'.format(cmd), exc_info=True)
        raise
    try:
        if timeout:
            stdout,stderr = p.communicate(timeout=timeout)
        else:
            stdout,stderr = p.communicate()
    except subprocess.TimeoutExpired as te:
        logger.error('subprocess timed out {!r}'.format(cmd), exc_info=True)
        reportcomms(p, stdout, stderr)
        raise
    except Exception as e:
        logger.error('subprocess exception {!r}'.format(cmd), exc_info=True)
        reportcomms(p, stdout, stderr)
        raise
    if p.returncode != 0:
        cmdr = repr(cmd)
        logger.error('cmd failed {}'.format(cmdr))
        reportcomms(p, stdout, stderr)
        raise Exception('error: cmd failed: {}'.format(cmdr))


def startdaemon(cmd):
    try:
        logger.debug('start: %r', cmd)
        p = subprocess.Popen(cmd)
        return p
    except Exception as e:
        logger.error('subprocess failed {!r}'.format(cmd), exc_info=True)
        raise

def wait_for_transaction(algod, txid, round, timeout=15):
    start = time.time()
    ti = algod.pending_transaction_info(txid)
    logger.debug('ti %s %r', txid, ti)
    while True:
        if ti and ti.get('confirmed-round'):
            # txn was committed
            return True
        if timeout and ((time.time() - start) > timeout):
            return False
        time.sleep(1)
        st = algod.status_after_block(round)
        logger.debug('st %r', st)
        round = st['last-round']
        ti = algod.pending_transaction_info(txid)
        logger.debug('ti %r', ti)

class NodeContext:
    def __init__(self, bindir, env=None, algodata=None, proc=None):
        self.proc = proc
        self.bindir = bindir
        self.algodata = algodata
        self.env = env
        if env and not algodata:
            self.algodata = env['ALGORAND_DATA']
        self.kmd = None
        self.algod = None
        self.pubw = None
        self.maxpubaddr = None
        self.lock = threading.Lock()
        return

    def _connect(self):
        # should run from inside self.lock
        if self.algod and self.kmd:
            return

        goal = os.path.join(self.bindir, 'goal')
        xrun([goal, 'kmd', 'start', '-t', '3600','-d', self.algodata], env=self.env, timeout=5)
        self.kmd = openkmd(self.algodata)
        self.algod = openalgod(self.algodata)

    def connect(self):
        with self.lock:
            self._connect()
            return self.algod, self.kmd

    def get_pub_wallet(self):
        with self.lock:
            self._connect()
            if not (self.pubw and self.maxpubaddr):
                # find private test node public wallet and its richest account
                wallets = self.kmd.list_wallets()
                pubwid = None
                for xw in wallets:
                    if xw['name'] == 'unencrypted-default-wallet':
                        pubwid = xw['id']
                pubw = self.kmd.init_wallet_handle(pubwid, '')
                pubaddrs = self.kmd.list_keys(pubw)
                pubbalances = []
                maxamount = 0
                maxpubaddr = None
                for pa in pubaddrs:
                    pai = self.algod.account_info(pa)
                    if pai['amount'] > maxamount:
                        maxamount = pai['amount']
                        maxpubaddr = pai['address']
                self.pubw = pubw
                self.maxpubaddr = maxpubaddr
            return self.pubw, self.maxpubaddr

    def terminate(self):
        self.proc.terminate()

def get_block_proposers(algod, lastRound, expected_proposers):
    oprops = {}
    for i in range(1,lastRound+1):
        try:
            b2b = algod.block_info(i, response_format='msgpack')
            b2 = algosdk.encoding.msgpack.unpackb(b2b)
            oprop = b2['cert']['prop']['oprop']
            oprops[oprop] = oprops.get(oprop, 0) + 1
        except Exception as e:
            print(e)
            break
    logger.debug('oprops %r', oprops)
    assert(len(oprops) == expected_proposers)
    mean = statistics.mean(oprops.values())
    var_limit = mean / 2
    ok = []
    bad = []
    for op,count in oprops.items():
        line = '{}\t{}'.format(algosdk.encoding.encode_address(op), count)
        if abs(count-mean) > var_limit:
            bad.append(line)
        else:
            ok.append(line)
    if bad:
        for line in ok:
            print(line)
        print("ERROR:")
        for line in bad:
            print(line)
        raise Exception("too much variance in block proposers, wanted [{} - {}]".format(mean-var_limit, mean+var_limit))
    return

def start_algod(algodata, bindir, relay_addr=None):
    algod_path = os.path.join(bindir, 'algod')
    cmd = [algod_path, '-d', algodata]
    if relay_addr:
        cmd += ['-p', relay_addr]
    proc = startdaemon(cmd)
    #atexit.register(proc.terminate)
    return NodeContext(bindir, algodata=algodata, proc=proc)


def bindir_missing(bindir):
    out = []
    for p in ('algod', 'goal', 'kmd'):
        path = os.path.join(bindir, p)
        if not os.path.exists(path):
            out.append(p)
    if not out:
        return None
    return out

def build(args, repodir, newbin, oldbin):
    curbranch = getbranch(repodir)
    goenv = get_go_env()
    gopath = goenv['GOPATH']
    newalgod = os.path.join(newbin , 'algod')
    oldalgod = os.path.join(oldbin, 'algod')
    os.makedirs(newbin, exist_ok=True)
    os.makedirs(oldbin, exist_ok=True)
    changeBack = False
    try:
        newbin_missing = bindir_missing(newbin)
        logger.debug('%s missing %r', newbin, newbin_missing)
        if newbin_missing:
            if args.no_build:
                raise Exception('new bin dir {} missing {} but --no-build set'.format(newbin, newbin_missing))
            xrun(['git', 'checkout', args.new_branch], cwd=repodir)
            changeBack = True
            xrun(['make'], cwd=repodir)
            for bn in ('algod', 'goal', 'kmd'):
                shutil.copy(os.path.join(gopath, 'bin', bn), os.path.join(newbin, bn))
        oldbin_missing = bindir_missing(oldbin)
        logger.debug('%s missing %r', oldbin, oldbin_missing)
        if oldbin_missing:
            if args.no_build:
                raise Exception('old bin dir {} missing {} but --no-build set'.format(oldbin, oldbin_missing))
            xrun(['git', 'checkout', args.old_branch], cwd=repodir)
            changeBack = True
            xrun(['make'], cwd=repodir)
            for bn in ('algod', 'goal', 'kmd'):
                shutil.copy(os.path.join(gopath, 'bin', bn), os.path.join(oldbin, bn))
    finally:
        if changeBack:
            xrun(['git', 'checkout', curbranch])

# return algod relay host:port or raise Exception
def wait_relay_addr(algodata, timeout=10):
    relay_addr_path = os.path.join(algodata, 'algod-listen.net')
    timeout = time.time() + timeout
    while True:
        if os.path.exists(relay_addr_path):
            with open(relay_addr_path) as fin:
                relay_addr = fin.read().strip()
            return relay_addr
        if time.time() > timeout:
            raise Exception('never found relay_addr at {}'.format(relay_addr_path))
        time.sleep(0.1)

# accept literal or filename
def json_arg(arg):
    if not arg:
        return None
    if arg[0] == '{':
        return json.loads(arg)
    if arg[0] == '@':
        with open(arg[1:]) as fin:
            return json.load(fin)
    if os.path.exists(arg):
        with open(arg) as fin:
            return json.load(fin)
    raise Exception("don't know how to get json from {!r}".format(arg))

def json_overlay(arg, netdir, subdirs):
    if not arg:
        return
    nc = json_arg(arg)
    if not nc:
        return
    for subdir in subdirs:
        with open(os.path.join(netdir, subdir, 'config.json')) as fin:
            config = json.load(fin)
        config.update(nc)
        with open(os.path.join(netdir, subdir, 'config.json'), 'w') as fout:
            json.dump(config, fout)

_logging_format = '%(asctime)s :%(lineno)d %(message)s'
_logging_datefmt = '%Y%m%d_%H%M%S'

def main():
    start = time.time()
    ap = argparse.ArgumentParser()
    ap.add_argument('--new-branch', default=None, help='`git checkout {new-branch}` and build')
    ap.add_argument('--old-branch', default=None, help='`git checkout {new-branch}` and build')
    ap.add_argument('--new-config', help='json to overlay on config.json, json literal or filename')
    ap.add_argument('--old-config', help='json to overlay on config.json, json literal or filename')
    ap.add_argument('--new-bin', help='path to directory holding new version of algod,kmd,goal')
    ap.add_argument('--old-bin', help='path to directory holding old version of algod,kmd,goal')
    ap.add_argument('--no-build', default=False, action='store_true')
    ap.add_argument('--work-dir')
    ap.add_argument('--keep-temps', default=False, action='store_true', help='if set, keep all the test files')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(format=_logging_format, datefmt=_logging_datefmt, level=logging.DEBUG)
    else:
        logging.basicConfig(format=_logging_format, datefmt=_logging_datefmt, level=logging.INFO)

    # TODO: default old_branch to the highest git tag like 'v3.5.1-stable'
    # TODO: default new_branch to whatever is currently checked out

    # start with a copy when making env for child processes
    env = dict(os.environ)

    tempdir = args.work_dir
    if not tempdir:
        tempdir = os.getenv('TEMPDIR')
    if not tempdir:
        tempdir = tempfile.mkdtemp()
        env['TEMPDIR'] = tempdir
        logger.info('created TEMPDIR %r', tempdir)
        if not args.keep_temps:
            # If we created a tmpdir and we're not keeping it, clean it up.
            # If an outer process specified $TEMPDIR, let them clean it up.
            atexit.register(shutil.rmtree, tempdir, onerror=lambda efn, epath, excinfo: logger.error('rmtree error %r %r %s', efn, epath, excinfo))
        else:
            atexit.register(print, 'keeping temps. to clean up:\nrm -rf {}'.format(tempdir))

    newbin = args.new_bin or os.path.join(tempdir, 'newbin')
    oldbin = args.old_bin or os.path.join(tempdir, 'oldbin')
    build(args, repodir, newbin, oldbin)

    netdir = os.path.join(tempdir, 'net')
    run_test6(args, netdir, oldbin, newbin)
    # algod_bins = {
    #     'Primary': oldbin,
    #     'Node1': oldbin,
    #     'Node2': newbin,
    # }
    # run_test(netdir, oldbin, newbin, algod_bins)
    # algod_bins = {
    #     'Primary': newbin,
    #     'Node1': oldbin,
    #     'Node2': newbin,
    # }
    # run_test(netdir, oldbin, newbin, algod_bins)
    dt = time.time() - start
    print('DONE OK {:.1f} seconds'.format(dt))
    # wait a moment for terminated algod to clean up their files
    time.sleep(1)
    return 0

def nop(*args, **kwargs):
    pass

def run_defers(defers, reraise=True, keep_going=False):
    if defers is None:
        return
    for di in defers:
        try:
            di()
        except Exception as ie:
            if reraise:
                raise
            logger.error('exception in defer:', exc_info=True)
            if not keep_going:
                break

def defer_wrap(fn):
    def _wrapped(*args, **kwargs):
        out = None
        try:
            defers = None
            if '_defer' not in kwargs:
                defers = []
                kwargs['_defer'] = lambda x: defers.append(x)
            out = fn(*args, **kwargs)
        except:
            run_defers(defers, reraise=False)
            raise
        run_defers(defers, reraise=True)
        return out
    return _wrapped

# Test topology: 1 relay, to leaf nodes.
# one leaf node each for oldbin, newbin
# relay as either oldbin or newbin
@defer_wrap
def run_test(netdir, oldbin, newbin, algod_bins, _defer=nop):
    shutil.rmtree(netdir, ignore_errors=True)
    xrun([os.path.join(oldbin, 'goal'), 'network', 'create', '-r', netdir, '-n', 'tbd', '-t', os.path.join(repodir, 'test/testdata/nettemplates/ThreeNodesEvenDist.json')], timeout=90)

    relay = start_algod(os.path.join(netdir, 'Primary'), algod_bins['Primary'])
    _defer(relay.terminate)
    relay_addr = wait_relay_addr(relay.algodata)

    n1 = start_algod(os.path.join(netdir, 'Node1'), algod_bins['Node1'], relay_addr=relay_addr)
    _defer(n1.terminate)

    n2 = start_algod(os.path.join(netdir, 'Node2'), algod_bins['Node2'], relay_addr=relay_addr)
    _defer(n2.terminate)

    n1algod, n1kmd = n1.connect()
    n2algod, n2kmd = n2.connect()
    time.sleep(5)
    status = n1algod.status()
    # TODO: timeout?
    #print('status {!r}'.format(status))
    n1algod.status_after_block(status['last-round'])

    tryi = 0
    while True:
        try:
            pubw, maxpubaddr = n1.get_pub_wallet()
            break
        except:
            if tryi >= 5:
                raise
            tryi += 1
            print('n1 get pub wallet retry sleep...')
            time.sleep(1)

    a1i = n1algod.account_info(maxpubaddr)
    pubw2, maxpubaddr2 = n2.get_pub_wallet()
    a2i = n2algod.account_info(maxpubaddr2)

    # test txn on n1 account submitted through n1, seen at n2
    tx1amt = 999000
    params = n1algod.suggested_params()
    round = params.first
    max_init_wait_rounds = 5
    txn = algosdk.transaction.PaymentTxn(sender=maxpubaddr, fee=params.min_fee, first=round, last=round+max_init_wait_rounds, gh=params.gh, receiver=maxpubaddr2, amt=tx1amt, flat_fee=True)
    stxn = n1kmd.sign_transaction(pubw, '', txn)
    txid = n1algod.send_transaction(stxn)
    wait_for_transaction(n1algod, txid, round)

    a2i2 = n2algod.account_info(maxpubaddr2)
    logger.debug('a2i %r', a2i)
    logger.debug('a2i2 %r', a2i2)
    # check that recipient got it
    assert(a2i2['amount'] - a2i['amount'] == tx1amt)

    # test txn on n2 account submitted through n2, seen at n1
    a1i = n1algod.account_info(maxpubaddr)
    tx2amt = 3000000
    params = n2algod.suggested_params()
    round = params.first
    txn = algosdk.transaction.PaymentTxn(sender=maxpubaddr2, fee=params.min_fee, first=round, last=round+max_init_wait_rounds, gh=params.gh, receiver=maxpubaddr, amt=tx2amt, flat_fee=True)
    stxn = n2kmd.sign_transaction(pubw2, '', txn)
    txid = n2algod.send_transaction(stxn)
    wait_for_transaction(n2algod, txid, round)

    a1i2 = n1algod.account_info(maxpubaddr)
    # check that recipient got it
    assert(a1i2['amount'] - a1i['amount'] == tx2amt)

    # run for a bunch of rounds and ensure that block proposers are well distributed
    ralgod, _ = relay.connect()
    st = ralgod.status()
    while st['last-round'] < 100:
        st = ralgod.status_after_block(st['last-round'])
        print(st['last-round'])
    get_block_proposers(ralgod, st['last-round'], 3)

    print("OK")
    return 0

class testaddrs:
    def __init__(self):
        self.i = 1
        self.sent = {}
        self.buf = [0] * 32
    def get(self):
        self.buf[31] = self.i
        addr = algosdk.encoding.encode_address(bytes(self.buf))
        amt = 1000000 + self.i
        self.sent[addr] = amt
        self.i += 1
        return addr,amt


def wait_round(algod, waitround, st=None, printround=False):
    if st is None:
        st = algod.status()
    lr = st['last-round']
    if lr >= waitround:
        return st
    nrounds = waitround - lr
    timeout = time.time() + (nrounds * 22)
    while st['last-round'] < waitround:
        if time.time() > timeout:
            raise Exception("too long waiting for round {}, last-round={}".format(waitround, st['last-round']))
        st = algod.status_after_block(st['last-round'])
        if printround:
            print(st['last-round'])
    return st


# test topology: 2 relays, 4 leafs
# (leaf old 1, leaf new 1) <-> (relay old) <-> (relay new) <-> (leaf old 2, leaf new 2)
@defer_wrap
def run_test6(args, netdir, oldbin, newbin, _defer=nop):
    test_addr = testaddrs()

    shutil.rmtree(netdir, ignore_errors=True)
    xrun([os.path.join(oldbin, 'goal'), 'network', 'create', '-r', netdir, '-n', 'tbd', '-t', os.path.join(repodir, 'test/testdata/nettemplates/TransitionSix.json')], timeout=90)

    json_overlay(args.new_config, netdir, ('RelayNew', 'New1', 'New2'))
    json_overlay(args.old_config, netdir, ('RelayOld', 'Old1', 'Old2'))

    relay_old = start_algod(os.path.join(netdir, 'RelayOld'), oldbin)
    _defer(relay_old.terminate)
    relay_old_addr = wait_relay_addr(relay_old.algodata)

    relay_new = start_algod(os.path.join(netdir, 'RelayNew'), newbin, relay_addr=relay_old_addr)
    _defer(relay_new.terminate)
    relay_new_addr = wait_relay_addr(relay_new.algodata)

    new1 = start_algod(os.path.join(netdir, 'New1'), newbin, relay_addr=relay_old_addr)
    _defer(new1.terminate)
    old1 = start_algod(os.path.join(netdir, 'Old1'), oldbin, relay_addr=relay_old_addr)
    _defer(old1.terminate)

    new2 = start_algod(os.path.join(netdir, 'New2'), newbin, relay_addr=relay_new_addr)
    _defer(new2.terminate)
    old2 = start_algod(os.path.join(netdir, 'Old2'), oldbin, relay_addr=relay_new_addr)
    _defer(old2.terminate)

    time.sleep(1)

    leafs = [new1, old1, new2, old2]

    n1algod, n1kmd = new1.connect()

    status = n1algod.status()
    logger.debug('waiting for round after %s', status['last-round'])
    status = n1algod.status_after_block(status['last-round'])
    logger.debug('status %r', status)

    sent_txid = []

    # send a txn from each leaf
    for leaf in leafs:
        algod, kmd = leaf.connect()
        pubw, maxpubaddr = leaf.get_pub_wallet()
        params = algod.suggested_params()
        receiver, amt = test_addr.get()
        txn = algosdk.transaction.PaymentTxn(sender=maxpubaddr, fee=params.min_fee, first=params.first, last=params.first+10, gh=params.gh, receiver=receiver, amt=amt, flat_fee=True)
        stxn = kmd.sign_transaction(pubw, '', txn)
        txid = algod.send_transaction(stxn)
        sent_txid.append(txid)

    ralgod, _ = relay_old.connect()
    st = wait_round(ralgod, status['last-round'] + 12, st=status)

    for leaf in leafs:
        for addr, amt in test_addr.sent.items():
            algod, _ = leaf.connect()
            ast = algod.account_info(addr)
            assert(ast['amount'] == amt)

    st = wait_round(ralgod, 100, printround=True, st=st)
    get_block_proposers(ralgod, st['last-round'], 4)

    print("OK")
    return 0


if __name__ == '__main__':
    sys.exit(main())
