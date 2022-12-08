#!/usr/bin/env python3
#
# Measure total percieved tx latency.
# Submit transactions to algod, watch blocks for committed transaction.

import argparse
import atexit
import base64
import datetime
import glob
import json
import logging
import os
import queue
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import threading

# pip install py-algorand-sdk
import algosdk
from algosdk.encoding import msgpack
import algosdk.v2client
import algosdk.v2client.algod

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
    algod = algosdk.v2client.algod.AlgodClient(algodtoken, 'http://' + algodnet)
    return algod

def addr_token_from_algod(algorand_data):
    with open(os.path.join(algorand_data, 'algod.net')) as fin:
        addr = fin.read().strip()
    with open(os.path.join(algorand_data, 'algod.token')) as fin:
        token = fin.read().strip()
    if not addr.startswith('http'):
        addr = 'http://' + addr
    return addr, token

def bstr(x):
    if isinstance(x, bytes):
        try:
            return x.decode()
        except:
            pass
    return x

def obnice(ob):
    if isinstance(ob, dict):
        return {bstr(k):obnice(v) for k,v in ob.items()}
    if isinstance(ob, list):
        return [obnice(x) for x in ob]
    return ob

class TxLatencyTest:
    def __init__(self, args, algorand_data=None, prev_round=None, out=None):
        self.algorand_data = algorand_data
        self.token = args.token
        self.addr = args.addr
        self.headers = header_list_to_dict(args.headers)
        self.prev_round = prev_round
        self.out = out or sys.stdout
        self.lock = threading.Lock()
        self.terminated = None
        self._kmd = None
        self._algod = None
        self.privatekey = None
        self.pubw = None
        self.maxpubaddr = None
        self.errors = []
        self.statuses = []
        self.jsonfile = None
        self.sentq = queue.Queue()
        self.txidq = queue.Queue()
        self.period = 1/args.tps
        self.sendcount = args.sendcount
        self.go = True
        self.roundTimes = {}
        self.txTimes = []
        return

    def connect(self):
        with self.lock:
            self._connect()
            return self._algod, self._kmd

    def _connect(self):
        if self._algod and self._kmd:
            return

        # should run from inside self.lock
        algodata = self.algorand_data

        logger.debug('pre kmd')
        subprocess.run(['goal', 'kmd', 'start', '-t', '3600', '-d', algodata], timeout=5, check=True)
        logger.debug('post kmd')
        self._kmd = openkmd(algodata)
        self._algod = self._algod_connect() #openalgod(algodata)

    def algod(self):
        with self.lock:
            if self._algod is None:
                self._algod = self._algod_connect()
            return self._algod

    def _algod_connect(self):
        if self.algorand_data:
            addr, token = addr_token_from_algod(self.algorand_data)
            logger.debug('algod from %r, (%s %s)', self.algorand_data, addr, token)
        else:
            token = self.token
            addr = self.addr
            logger.debug('algod from args (%s %s)', self.addr, self.token)
        self._algod = algosdk.v2client.algod.AlgodClient(token, addr, headers=self.headers)
        return self._algod

    def get_pub_wallet(self):
        with self.lock:
            self._connect()
            if not (self.pubw and self.maxpubaddr):
                # find private test node public wallet and its richest account
                wallets = self._kmd.list_wallets()
                pubwid = None
                for xw in wallets:
                    if xw['name'] == 'unencrypted-default-wallet':
                        pubwid = xw['id']
                pubw = self._kmd.init_wallet_handle(pubwid, '')
                pubaddrs = self._kmd.list_keys(pubw)
                maxamount = 0
                maxpubaddr = None
                for pa in pubaddrs:
                    pai = self._algod.account_info(pa)
                    if pai['amount'] > maxamount:
                        maxamount = pai['amount']
                        maxpubaddr = pai['address']
                self.pubw = pubw
                self.maxpubaddr = maxpubaddr
            return self.pubw, self.maxpubaddr

    def send_thread(self):
        #opriv, opub = algosdk.account.generate_account()
        algod = self.algod()
        nextsend = time.time()
        params = algod.suggested_params()
        paramsMtime = nextsend
        count = 0

        while True:
            txn = algosdk.transaction.PaymentTxn(self.maxpubaddr, 1000, params.first, params.last, params.gh, self.maxpubaddr, 1, gen=params.gen, flat_fee=True, note='{}_'.format(count).encode() + os.getrandom(8))
            ptxid = txn.get_txid()
            if self.privatekey:
                stxn = txn.sign(self.privatekey)
            else:
                stxn = self._kmd.sign_transaction(self.pubw, '', txn)
            txid = algod.send_transaction(stxn)
            if ptxid != txid:
                logger.error('python txid %s, API txid %s', ptxid, txid)
            logger.debug('%r', txn.dictify())
            sendt = time.time()
            logger.debug('sent %s %f', txid, sendt)
            self.sentq.put((txid, sendt))

            if self.sendcount is not None:
                self.sendcount -= 1
                if self.sendcount <= 0:
                    # signal to consumer end of sending
                    self.sentq.put((None, None))
                    return

            if sendt - paramsMtime > 5:
                params = algod.suggested_params()
                paramsMtime = sendt

            while nextsend < sendt:
                nextsend += self.period
            time.sleep(nextsend - sendt)

    def measure_thread(self):
        lastround = self.prev_round
        algod = self.algod()
        while self.go:
            b = self.nextblock(lastround)
            if b is None:
                print("got None nextblock. exiting")
                return
            b = msgpack.loads(b, strict_map_key=False, raw=True)
            b = obnice(b)
            nowround = b['block'].get('rnd', 0)
            logger.debug('r%d', nowround)
            if (lastround is not None) and (nowround != lastround + 1):
                logger.info('round jump %d to %d', lastround, nowround)
            self._block_handler(b)
            lastround = nowround

    def nextblock(self, lastround=None, retries=30):
        trycount = 0
        while (trycount < retries) and self.go:
            trycount += 1
            try:
                return self._nextblock_inner(lastround)
            except Exception as e:
                if trycount >= retries:
                    logger.error('too many errors in nextblock retries')
                    raise
                else:
                    logger.warning('error in nextblock(%r) (retrying): %s', lastround, e)
                    self._algod = None # retry with a new connection
                    time.sleep(1.2)
        return None

    def _nextblock_inner(self, lastround):
        self.block_time = None
        algod = self.algod()
        if lastround is None:
            status = algod.status()
            lastround = status['last-round']
            logger.debug('nextblock status last-round %s', lastround)
        else:
            try:
                blk = algod.block_info(lastround + 1, response_format='msgpack')
                if blk:
                    return blk
                logger.warning('null block %d, lastround=%r', lastround+1, lastround)
            except Exception as e:
                pass
                #logger.debug('could not get block %d: %s', lastround + 1, e, exc_info=True)
        status = algod.status_after_block(lastround)
        block_time = time.time() # the block has happened, don't count block data transit time
        nbr = status['last-round']
        retries = 30
        while (nbr > lastround + 1) and self.go:
            # if more than one block elapsed, we don't have a good time for either block
            block_time = None
            # try lastround+1 one last time
            try:
                blk = algod.block_info(lastround + 1, response_format='msgpack')
                if blk:
                    return blk
                logger.warning('null block %d, lastround=%r, status.last-round=%d', lastround+1, lastround, nbr)
                time.sleep(1.1)
                retries -= 1
                if retries <= 0:
                    raise Exception("too many null block for %d", lastround+1)
            except:
                break
        blk = algod.block_info(nbr, response_format='msgpack')
        if blk:
            self.block_time = block_time
            return blk
        raise Exception('got None for blk {}'.format(nbr))

    def _block_handler(self, b):
        block_time = self.block_time or time.time()
        nowround = b['block'].get('rnd', 0)
        self.roundTimes[nowround] = block_time
        # throw away txns, count is kept in round differential ['block']['tc']
        stxibs = b['block'].get('txns', [])
        txids = []
        for stxib in stxibs:
            txn = stxib['txn']
            #logger.debug('stxib.txn %r', txn)
            hgi = stxib.pop('hgi', False)
            if hgi:
                txn['gh'] = b['block']['gh']
            txn['gen'] = bstr(b['block']['gen'])
            txnd = txn
            txn = algosdk.transaction.Transaction.undictify(txn)
            txid = txn.get_txid()
            logger.debug('rx txn %r, txid %s', txnd, txid)
            txids.append(txid)
        self.txidq.put((txids, block_time))

    def join_thread(self):
        lastSendt = None
        sentq = self.sentq
        sentByTxid = {}
        while self.go:
            if sentq is not None:
                try:
                    txid, sendt = self.sentq.get(block=True, timeout=0.2)
                    if sendt is None:
                        sentq = None
                    else:
                        lastSendt = sendt
                    sentByTxid[txid] = sendt
                except queue.Empty:
                    pass
            elif (lastSendt is None) or (time.time() > (lastSendt + 8)):
                self.go = False
                return
            try:
                txids, rxt = self.txidq.get(block=False)
                for txid in txids:
                    sendt = sentByTxid.get(txid)
                    if sendt is not None:
                        dt = rxt - sendt
                        self.txTimes.append(dt)
                        logger.debug('rx %s %f', txid, dt)
                        self.out.write('{}\n'.format(dt))
                    else:
                        logger.debug('unk blk txid %r', txid)
            except queue.Empty:
                pass

def header_list_to_dict(hlist):
    if not hlist:
        return None
    p = re.compile(r':\s+')
    out = {}
    for x in hlist:
        a, b = p.split(x, 1)
        out[a] = b
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--algod', default=None, help='algod data dir')
    ap.add_argument('-a', '--addr', default=None, help='algod host:port address')
    ap.add_argument('-t', '--token', default=None, help='algod API access token')
    ap.add_argument('--header', dest='headers', nargs='*', help='"Name: value" HTTP header (repeatable)')
    ap.add_argument('--tps', type=float, default=5, help='TPS to send at')
    ap.add_argument('--sendcount', type=int, default=50, help='number of test txns to send at 5 TPS')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    algorand_data = args.algod or os.getenv('ALGORAND_DATA')
    if not algorand_data and not ((args.token or args.headers) and args.addr):
        sys.stderr.write('must specify algod data dir by $ALGORAND_DATA or -d/--algod; OR --a/--addr and -t/--token\n')
        sys.exit(1)

    out = sys.stdout

    bot = TxLatencyTest(
        args,
        algorand_data,
        prev_round=None,
        out=out,
    )

    pubw, maxpubaddr = bot.get_pub_wallet()
    logger.debug('get pub wallet -> %s %s', pubw, maxpubaddr)

    sender = threading.Thread(target=bot.send_thread)
    sender.start()
    measure = threading.Thread(target=bot.measure_thread)
    measure.start()
    merge = threading.Thread(target=bot.join_thread)
    merge.start()
    sender.join()
    measure.join()
    merge.join()

    txTimes = bot.txTimes
    rounds = sorted(bot.roundTimes.keys())
    prevRound = None
    prevRoundTime = None
    roundDts = []
    for rnd in rounds:
        rndTime = bot.roundTimes[rnd]
        if (prevRound is not None) and (prevRound + 1 == rnd):
            dt = rndTime - prevRoundTime
            roundDts.append(dt)
        prevRound = rnd
        prevRoundTime = rndTime
    roundTimeMean = statistics.mean(roundDts)
    roundTimeMin = min(roundDts)
    roundTimeMax = max(roundDts)
    txMean = statistics.mean(txTimes)
    tmin = min(txTimes)
    tmax = max(txTimes)
    out.write('# {} txns measured, {} rounds seen\n'.format(len(txTimes), len(rounds)))
    out.write('# rnd (min={}, mean={}, max={})\n'.format(roundTimeMin, roundTimeMean, roundTimeMax))
    out.write('# tx  (min={}, mean={}, max={})\n'.format(tmin, txMean, tmax))
    out.write('# tx  (min={}, mean={}, max={}) (/(mean rnd))\n'.format(tmin/roundTimeMean, txMean/roundTimeMean, tmax/roundTimeMean))
    return 0

if __name__ == '__main__':
    main()
