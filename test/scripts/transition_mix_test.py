#!/usr/bin/env python3
#

import argparse
import atexit
import glob
import json
import logging
import os
import re
import shutil
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
    algod = algosdk.algod.AlgodClient(algodtoken, 'http://' + algodnet)
    return algod

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
    #print(json.dumps(ti, indent=2))
    while True:
        if ti and ti.get('round') != 0:
            # txn was committed
            return True
        if timeout and ((time.time() - start) > timeout):
            return False
        time.sleep(1)
        st = algod.status_after_block(round)
        #print(json.dumps(st, indent=2))
        round = st['lastRound']
        ti = algod.pending_transaction_info(txid)
        #print(json.dumps(ti, indent=2))

class NodeContext:
    def __init__(self, bindir, env=None, algodata=None):
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

_logging_format = '%(asctime)s :%(lineno)d %(message)s'
_logging_datefmt = '%Y%m%d_%H%M%S'

def main():
    start = time.time()
    ap = argparse.ArgumentParser()
    ap.add_argument('--new-branch', default=None, help='`git checkout {new-branch}` and build')
    ap.add_argument('--old-branch', default=None, help='`git checkout {new-branch}` and build')
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
    # TODO: default new_branch to `master`

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
            atexit.register(shutil.rmtree, tempdir, onerror=logger.error)
        else:
            atexit.register(print, 'keeping temps. to clean up:\nrm -rf {}'.format(tempdir))

    curbranch = getbranch(repodir)
    goenv = get_go_env()
    gopath = goenv['GOPATH']
    newbin = os.path.join(tempdir, 'newbin')
    newalgod = os.path.join(newbin , 'algod')
    oldbin = os.path.join(tempdir, 'oldbin')
    oldalgod = os.path.join(oldbin, 'algod')
    os.makedirs(newbin, exist_ok=True)
    os.makedirs(oldbin, exist_ok=True)
    changeBack = False
    if not os.path.exists(newalgod):
        if args.no_build:
            raise Exception('{} missing but --no-build set'.format(newalgod))
        xrun(['git', 'checkout', args.new_branch], cwd=repodir)
        if curbranch and not changeBack:
            changeBack = True
            atexit.register(xrun, ['git', 'checkout', curbranch])
        xrun(['make'], cwd=repodir)
        for bn in ('algod', 'goal', 'kmd'):
            shutil.copy(os.path.join(gopath, 'bin', bn), os.path.join(newbin, bn))
    if not os.path.exists(oldalgod):
        if args.no_build:
            raise Exception('{} missing but --no-build set'.format(oldalgod))
        xrun(['git', 'checkout', args.old_branch], cwd=repodir)
        if curbranch and not changeBack:
            changeBack = True
            atexit.register(xrun, ['git', 'checkout', curbranch])
        xrun(['make'], cwd=repodir)
        for bn in ('algod', 'goal', 'kmd'):
            shutil.copy(os.path.join(gopath, 'bin', bn), os.path.join(oldbin, bn))

    netdir = os.path.join(tempdir, 'net')
    env['NETDIR'] = netdir

    shutil.rmtree(netdir, ignore_errors=True)
    xrun([os.path.join(oldbin, 'goal'), 'network', 'create', '-r', netdir, '-n', 'tbd', '-t', os.path.join(repodir, 'test/testdata/nettemplates/ThreeNodesEvenDist.json')], timeout=90)

    relaydir = os.path.join(netdir, 'Primary')
    relay = startdaemon([oldalgod, '-d', relaydir])
    time.sleep(0.5)
    with open(os.path.join(relaydir, 'algod-listen.net')) as fin:
        relay_addr = fin.read().strip()
    atexit.register(relay.terminate)

    n1dir = os.path.join(netdir, 'Node1')
    node1 = startdaemon([oldalgod, '-d', n1dir, '-p', relay_addr])
    atexit.register(node1.terminate)
    n1 = NodeContext(oldbin, algodata=n1dir)
    #~/Algorand/masterbin/algod -d ~/Algorand/tn3/Node1 -p $(cat ~/Algorand/tn3/Primary/algod-listen.net) > ~/Algorand/tn3/Primary/algod.out 2>&1 &

    n2dir = os.path.join(netdir, 'Node2')
    node2 = startdaemon([newalgod, '-d', n2dir, '-p', relay_addr])
    atexit.register(node2.terminate)
    n2 = NodeContext(newbin, algodata=n2dir)
    #~/Algorand/txnsyncbin/algod -d ~/Algorand/tn3/Node2 -p $(cat ~/Algorand/tn3/Primary/algod-listen.net) > ~/Algorand/tn3/Primary/algod.out 2>&1 &

    n1algod, n1kmd = n1.connect()
    n2algod, n2kmd = n2.connect()
    time.sleep(5)
    status = n1algod.status()
    # TODO: timeout?
    #print('status {!r}'.format(status))
    n1algod.status_after_block(status['lastRound'])

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
    params = n1algod.suggested_params()
    round = params['lastRound']
    max_init_wait_rounds = 5
    tx1amt = 999000
    txn = algosdk.transaction.PaymentTxn(sender=maxpubaddr, fee=params['minFee'], first=round, last=round+max_init_wait_rounds, gh=params['genesishashb64'], receiver=maxpubaddr2, amt=tx1amt, flat_fee=True)
    stxn = n1kmd.sign_transaction(pubw, '', txn)
    txid = n1algod.send_transaction(stxn)

    wait_for_transaction(n1algod, txid, round)

    a2i2 = n2algod.account_info(maxpubaddr2)
    print(json.dumps(a2i, indent=2))
    print(json.dumps(a2i2, indent=2))
    assert(a2i2['amount'] - a2i['amount'] == tx1amt)


if __name__ == '__main__':
    sys.exit(main())
