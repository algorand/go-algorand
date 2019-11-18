#!/usr/bin/env python3

import argparse
import atexit
import base64
import glob
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

def script_thread(runset, scriptname):
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
    txn = algosdk.transaction.PaymentTxn(sender=maxpubaddr, fee=params['minFee'], first=round, last=round+100, gh=params['genesishashb64'], receiver=addr, amt=1000000000000, flat_fee=True)
    stxn = kmd.sign_transaction(pubw, '', txn)
    txid = algod.send_transaction(stxn)
    ptxinfo = None
    for i in range(50):
        txinfo = algod.pending_transaction_info(txid)
        if txinfo.get('round'):
            break
        time.sleep(0.1)

    env = dict(runset.env)
    env['TEMPDIR'] = os.path.join(env['TEMPDIR'], walletname)
    os.makedirs(env['TEMPDIR'])
    cmdlogpath = os.path.join(env['TEMPDIR'],'.cmdlog')
    cmdlog = open(cmdlogpath, 'wb')
    logger.info('starting %s', scriptname)
    p = subprocess.Popen([scriptname, walletname], env=env, stdout=cmdlog, stderr=subprocess.STDOUT)
    cmdlog.close()
    runset.running(scriptname, p)
    retcode = p.wait(read_script_for_timeout(scriptname))
    if retcode != 0:
        sys.stderr.write('error: {} FAILED\n'.format(scriptname))
        st = os.stat(cmdlogpath)
        with open(cmdlogpath, 'r') as fin:
            if st.st_size > 4096:
                fin.seek(st.st_size - 4096)
                text = fin.read()
                lines = text.splitlines()
                if len(lines) > 1:
                    # drop probably-partial first line
                    lines = lines[1:]
                sys.stderr.write('end of log follows:\n')
                sys.stderr.write('\n'.join(lines))
                sys.stderr.write('\n\n')
            else:
                sys.stderr.write('whole log follows:\n')
                sys.stderr.write(fin.read())
    runset.done(scriptname, retcode == 0)
    return

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
        return

    def connect(self):
        with self.lock:
            self._connect()
            return self.algod, self.kmd

    def _connect(self):
        if self.algod and self.kmd:
            return
        # should run from inside self.lock
        subprocess.run(['goal', 'kmd', 'start', '-t', '200'], env=self.env, timeout=5).check_returncode()
        algodata = self.env['ALGORAND_DATA']
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

    def done(self, scriptname, ok):
        with self.lock:
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

def goal_network_stop(netdir):
    x = subprocess.run(['goal', 'network', 'stop', '-r', netdir], timeout=30)
    if x.returncode != 0:
        logger.error('stop failed %s', x)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('scripts', nargs='*', help='scripts to run')
    ap.add_argument('--keep-temps', default=False, action='store_true', help='if set, keep all the test files')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

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

    netdir = os.path.join(tempdir, 'net')
    env['NETDIR'] = netdir

    gopath = os.getenv('GOPATH')
    if not gopath:
        logger.error('$GOPATH not set')
        sys.exit(1)

    subprocess.run(['goal', 'network', 'create', '-r', netdir, '-n', 'tbd', '-t', os.path.join(gopath, 'src/github.com/algorand/go-algorand/test/testdata/nettemplates/TwoNodes50EachFuture.json')], timeout=30).check_returncode()
    subprocess.run(['goal', 'network', 'start', '-r', netdir], timeout=30).check_returncode()
    atexit.register(goal_network_stop, netdir)

    env['ALGORAND_DATA'] = os.path.join(netdir, 'Node')
    env['ALGORAND_DATA2'] = os.path.join(netdir, 'Primary')

    subprocess.run(['goal', '-v'], env=env, timeout=5).check_returncode()
    subprocess.run(['goal', 'node', 'status'], env=env, timeout=5).check_returncode()

    rs = RunSet(env)
    for scriptname in args.scripts:
        logger.info('starting %s', scriptname)
        rs.start(scriptname)
    rs.wait(500)
    if rs.errors:
        logger.error('errors: %r', '\n'.join(rs.errors))
    return

if __name__ == '__main__':
    main()
