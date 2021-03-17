#!/usr/bin/env python3
#
# Create a local private network and run functional tests on it in parallel.
#
# Each test is run as `ftest.sh wallet_name` for a wallet with a
# million Algos, with the current directory set to the top of the
# repo.  A test should carefully specify that wallet (or wallets
# created for the test) for all actions. Tests are expected to not be
# CPU intensive, merely setting up a handful of transactions and
# executing them against the network, exercising aspects of the
# network and the goal tools.
#
# Usage:
#  ./e2e_client_runner.py e2e_subs/*.sh
#
# Reads each bash script for `# TIMEOUT=N` line to configure timeout to N seconds. (default timeout is 200 seconds)

import argparse
import atexit
import base64
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import threading

# pip install py-algorand-sdk
import algosdk

logger = logging.getLogger(__name__)

scriptdir = os.path.dirname(os.path.realpath(__file__))
repodir =  os.path.join(scriptdir, "..", "..")

# less than 16kB of log we show the whole thing, otherwise the last 16kB
LOG_WHOLE_CUTOFF = 1024 * 16

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

def read_script_for_timeout(fname):
    pat = re.compile(r'^#.*TIMEOUT=(\d+)')
    with open(fname, 'rt') as fin:
        try:
            for line in fin:
                m = pat.match(line)
                if m:
                    return int(m.group(1))
        except:
            logger.debug('read timeout match err', exc_info=True)
    return 200

def _script_thread_inner(runset, scriptname):
    start = time.time()
    algod, kmd = runset.connect()
    pubw, maxpubaddr = runset.get_pub_wallet()

    # create a wallet for the test
    walletname = base64.b16encode(os.urandom(16)).decode()
    winfo = kmd.create_wallet(walletname, '')
    handle = kmd.init_wallet_handle(winfo['id'], '')
    addr = kmd.generate_key(handle)

    # send one million Algos to the test wallet's account
    params = algod.suggested_params()
    round = params['lastRound']
    max_init_wait_rounds = 5
    txn = algosdk.transaction.PaymentTxn(sender=maxpubaddr, fee=params['minFee'], first=round, last=round+max_init_wait_rounds, gh=params['genesishashb64'], receiver=addr, amt=1000000000000, flat_fee=True)
    stxn = kmd.sign_transaction(pubw, '', txn)
    txid = algod.send_transaction(stxn)
    ptxinfo = None
    for i in range(max_init_wait_rounds):
        txinfo = algod.pending_transaction_info(txid)
        if txinfo.get('round'):
            break
        status = algod.status_after_block(round_num=round)
        round = status['lastRound']

    if ptxinfo is not None:
        sys.stderr.write('failed to initialize temporary test wallet account for test ({}) for {} rounds.\n'.format(scriptname, max_init_wait_rounds))
        runset.done(scriptname, False, time.time() - start)

    env = dict(runset.env)
    env['TEMPDIR'] = os.path.join(env['TEMPDIR'], walletname)
    os.makedirs(env['TEMPDIR'])
    cmdlogpath = os.path.join(env['TEMPDIR'],'.cmdlog')
    cmdlog = open(cmdlogpath, 'wb')
    if not runset.is_ok():
        runset.done(scriptname, False, time.time() - start)
        return
    logger.info('starting %s', scriptname)
    p = subprocess.Popen([scriptname, walletname], env=env, cwd=repodir, stdout=cmdlog, stderr=subprocess.STDOUT)
    cmdlog.close()
    runset.running(scriptname, p)
    timeout = read_script_for_timeout(scriptname)
    try:
        retcode = p.wait(timeout)
    except subprocess.TimeoutExpired as te:
        sys.stderr.write('{}\n'.format(te))
        retcode = -1
    dt = time.time() - start


    if runset.terminated:
        logger.info('Program terminated before %s finishes.', scriptname)
        runset.done(scriptname, False, dt)
        return

    if retcode != 0:
        with runset.lock:
            logger.error('%s failed in %f seconds', scriptname, dt)
            st = os.stat(cmdlogpath)
            with open(cmdlogpath, 'r') as fin:
                if st.st_size > LOG_WHOLE_CUTOFF:
                    fin.seek(st.st_size - LOG_WHOLE_CUTOFF)
                    text = fin.read()
                    lines = text.splitlines()
                    if len(lines) > 1:
                        # drop probably-partial first line
                        lines = lines[1:]
                    sys.stderr.write('end of log follows ({}):\n'.format(scriptname))
                    sys.stderr.write('\n'.join(lines))
                    sys.stderr.write('\n\n')
                else:
                    sys.stderr.write('whole log follows ({}):\n'.format(scriptname))
                    sys.stderr.write(fin.read())
    else:
        logger.info('finished %s OK in %f seconds', scriptname, dt)
    runset.done(scriptname, retcode == 0, dt)
    return

def script_thread(runset, scriptname):
    start = time.time()
    try:
        _script_thread_inner(runset, scriptname)
    except Exception as e:
        logger.error('error in e2e_client_runner.py', exc_info=True)
        runset.done(scriptname, False, time.time() - start)

def killthread(runset):
    time.sleep(5)
    runset.kill()
    return

class RunSet:
    def __init__(self, env):
        self.env = env
        self.threads = {}
        self.procs = {}
        self.ok = True
        self.lock = threading.Lock()
        self.terminated = None
        self.killthread = None
        self.kmd = None
        self.algod = None
        self.pubw = None
        self.maxpubaddr = None
        self.errors = []
        self.statuses = []
        return

    def is_ok(self):
        with self.lock:
            return self.ok

    def connect(self):
        with self.lock:
            self._connect()
            return self.algod, self.kmd

    def _connect(self):
        if self.algod and self.kmd:
            return
        # should run from inside self.lock
        algodata = self.env['ALGORAND_DATA']
        xrun(['goal', 'kmd', 'start', '-t', '3600','-d', algodata], env=self.env, timeout=5)
        self.kmd = openkmd(algodata)
        self.algod = openalgod(algodata)

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

    def start(self, scriptname):
        with self.lock:
            if not self.ok:
                return
        t = threading.Thread(target=script_thread, args=(self, scriptname,))
        t.start()
        with self.lock:
            self.threads[scriptname] = t

    def running(self, scriptname, p):
        with self.lock:
            self.procs[scriptname] = p

    def done(self, scriptname, ok, seconds):
        with self.lock:
            self.statuses.append( {'script':scriptname, 'ok':ok, 'seconds':seconds} )
            if not ok:
                self.errors.append('{} failed'.format(scriptname))
            self.threads.pop(scriptname, None)
            self.procs.pop(scriptname, None)
            self.ok = self.ok and ok
            if not self.ok:
                self._terminate()
                if self.killthread is None:
                    self.killthread = threading.Thread(target=killthread, args=(self,), daemon=True)
                    self.killthread.start()

    def _terminate(self):
        # run from inside self.lock
        if self.terminated:
            return
        self.terminated = time.time()
        for p in self.procs.values():
            p.terminate()

    def kill(self):
        with self.lock:
            for p in self.procs.values():
                p.kill()
        return

    def wait(self, timeout):
        now = time.time()
        endt = now + timeout
        while now < endt:
            waitt = None
            with self.lock:
                for t in self.threads.values():
                    waitt = t
                    break
            if waitt is None:
                break
            now = time.time()
            if now >= endt:
                break
            waitt.join(timeout=endt - now)
            now = time.time()
        if now >= endt:
            with self.lock:
                self.ok = False
                self._terminate()


# 'network stop' and 'network delete' are also tested and used as cleanup procedures
# so it re-raises exception in 'test' mode
already_stopped = False
already_deleted = False

def goal_network_stop(netdir, env, normal_cleanup=False):
    global already_stopped, already_deleted
    if already_stopped or already_deleted:
        return

    logger.info('stop network in %s', netdir)
    try:
        xrun(['goal', 'network', 'stop', '-r', netdir], timeout=10)
    except Exception as e:
        logger.error('error stopping network', exc_info=True)
        if normal_cleanup:
            raise e
    try:
        algodata = env['ALGORAND_DATA']
        logger.info('stop kmd in %s', algodata)
        xrun(['goal', 'kmd', 'stop', '-d', algodata], timeout=5)
    except Exception as e:
        logger.error('error stopping kmd', exc_info=True)
        if normal_cleanup:
            raise e
    already_stopped = True

def goal_network_delete(netdir, normal_cleanup=False):
    global already_deleted
    if already_deleted:
        return

    logger.info('delete network in %s', netdir)
    try:
        xrun(['goal', 'network', 'delete', '-r', netdir], timeout=10)
    except Exception as e:
        logger.error('error deleting network', exc_info=True)
        if normal_cleanup:
            raise e
    already_deleted = True

def reportcomms(p, stdout, stderr):
    cmdr = repr(p.args)
    if not stdout and p.stdout:
        stdout = p.stdout.read()
    if not stderr and p.stderr:
        stderr = p.stderr.read()
    if stdout:
        sys.stderr.write('output from {}:\n{}\n\n'.format(cmdr, stdout))
    if stderr:
        sys.stderr.write('stderr from {}:\n{}\n\n'.format(cmdr, stderr))

def xrun(cmd, *args, **kwargs):
    timeout = kwargs.pop('timeout', None)
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.STDOUT
    try:
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

_logging_format = '%(asctime)s :%(lineno)d %(message)s'
_logging_datefmt = '%Y%m%d_%H%M%S'

def main():
    start = time.time()
    ap = argparse.ArgumentParser()
    ap.add_argument('scripts', nargs='*', help='scripts to run')
    ap.add_argument('--keep-temps', default=False, action='store_true', help='if set, keep all the test files')
    ap.add_argument('--timeout', default=500, type=int, help='integer seconds to wait for the scripts to run')
    ap.add_argument('--verbose', default=False, action='store_true')
    ap.add_argument('--version', default="Future")
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(format=_logging_format, datefmt=_logging_datefmt, level=logging.DEBUG)
    else:
        logging.basicConfig(format=_logging_format, datefmt=_logging_datefmt, level=logging.INFO)

    logger.info('starting: %r', args.scripts)
    # start with a copy when making env for child processes
    env = dict(os.environ)
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

    netdir = os.path.join(tempdir, 'net')
    env['NETDIR'] = netdir

    retcode = 0
    capv = args.version.capitalize()
    xrun(['goal', 'network', 'create', '-r', netdir, '-n', 'tbd', '-t', os.path.join(repodir, f'test/testdata/nettemplates/TwoNodes50Each{capv}.json')], timeout=90)
    xrun(['goal', 'network', 'start', '-r', netdir], timeout=90)
    atexit.register(goal_network_stop, netdir, env)

    env['ALGORAND_DATA'] = os.path.join(netdir, 'Node')
    env['ALGORAND_DATA2'] = os.path.join(netdir, 'Primary')

    xrun(['goal', '-v'], env=env, timeout=5)
    xrun(['goal', 'node', 'status'], env=env, timeout=5)

    rs = RunSet(env)
    for scriptname in args.scripts:
        rs.start(scriptname)
    rs.wait(args.timeout)
    if rs.errors:
        retcode = 1
        logger.error('ERRORS after %f seconds: %r', time.time() - start, '\n'.join(rs.errors))
    else:
        logger.info('finished OK %f seconds', time.time() - start)
    logger.info('statuses-json: %s', json.dumps(rs.statuses))

    # ensure 'network stop' and 'network delete' also make they job
    goal_network_stop(netdir, env, normal_cleanup=True)
    if not args.keep_temps:
        goal_network_delete(netdir, normal_cleanup=True)

    return retcode

if __name__ == '__main__':
    sys.exit(main())
