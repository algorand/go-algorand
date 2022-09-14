#!/usr/bin/env python3

import argparse
import gzip
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time

# pip install py-algorand-sdk
import algosdk
from algosdk.encoding import msgpack
import algosdk.v2client
import algosdk.v2client.algod
from algosdk.v2client.algod import AlgodClient

logger = logging.getLogger(__name__)

def addr_token_from_algod(algorand_data):
    with open(os.path.join(algorand_data, 'algod.net')) as fin:
        addr = fin.read().strip()
    with open(os.path.join(algorand_data, 'algod.token')) as fin:
        token = fin.read().strip()
    if not addr.startswith('http'):
        addr = 'http://' + addr
    return addr, token

def si(x):
    return str(int(x))

# tps_multiplier=1 is calibrated for 10 pingpongs to deliver slightly more than 1000 TPS
def build_testcases(payment_tps=115, num_accounts=500, num_assets=10, num_apps=10, tps_multiplier=1):
    payment_tps *= tps_multiplier
    rekey_payment_transaction_tps = 50 * tps_multiplier
    asset_transfer_tps = 110 * tps_multiplier
    stateful_teal_tps = 110 * tps_multiplier
    teal_light_tps = 110 * tps_multiplier
    teal_normal_tps = 66 * tps_multiplier
    teal_heavy_tps = 52 * tps_multiplier
    atomic_transfer_small_tps = 20 * tps_multiplier
    atomic_transfer_large = 8 * tps_multiplier

    refresh_arg = ['--refresh', '1800']
    numaccounts_arg = ['--numaccounts', si(num_accounts)]

    payment_transaction = ['--tps', si(payment_tps)] + numaccounts_arg + refresh_arg
    rekey_payment_transaction = ['--tps', si(rekey_payment_transaction_tps), '--rekey', 'true', '--groupsize', '2', '--randomnote', 'true'] + numaccounts_arg + refresh_arg
    asset_transfer_small_transaction = ['--tps', si(asset_transfer_tps), '--numasset', '5', '--numaccounts', '5'] + refresh_arg
    asset_transfer_large_transaction = ['--tps', si(asset_transfer_tps), '--numasset', si(num_assets), '--numaccounts', '5'] + refresh_arg
    stateful_teal_small_transaction = ['--tps', si(stateful_teal_tps), '--numapp', si(num_apps), '--appprogops', '10'] + numaccounts_arg + refresh_arg
    stateful_teal_medium_transaction = ['--tps', si(stateful_teal_tps), '--numapp', si(num_apps), '--appprogops', '200'] + numaccounts_arg + refresh_arg
    stateful_teal_large_transaction = ['--tps', si(stateful_teal_tps), '--numapp', si(num_apps), '--appprogops', '695'] + numaccounts_arg + refresh_arg
    teal_light_transaction = ['--tps', si(teal_light_tps), '--teal=light'] + numaccounts_arg + refresh_arg
    teal_normal_transaction = ['--tps', si(teal_normal_tps), '--teal=normal'] + numaccounts_arg + refresh_arg
    teal_heavy_transaction = ['--tps', si(teal_heavy_tps), '--teal=heavy'] + numaccounts_arg + refresh_arg
    atomic_transfer_small_transaction = ['--tps', si(atomic_transfer_small_tps), '--groupsize', '5', '-a', '1'] + numaccounts_arg + refresh_arg
    atomic_transfer_large_transaction = ['--tps', si(atomic_transfer_large), '--groupsize', '12', '-a', '1'] + numaccounts_arg + refresh_arg

    testcases = [
        #{"name": "no_load", "cmd": [], "clearout": 0, "stabilize": 0},
        {"name": "payment", "cmd": payment_transaction, "clearout": 45, "stabilize": 120},
        {"name": "asset_transfer_small", "cmd": asset_transfer_small_transaction, "clearout": 45, "stabilize": 180},
        {"name": "asset_transfer_large", "cmd": asset_transfer_large_transaction, "clearout": 45, "stabilize": 240},
        {"name": "stateful_teal_small", "cmd": stateful_teal_small_transaction, "clearout": 45, "stabilize": 80},
        {"name": "stateful_teal_medium", "cmd": stateful_teal_medium_transaction, "clearout": 45, "stabilize": 80},
        {"name": "stateful_teal_large", "cmd": stateful_teal_large_transaction, "clearout": 45, "stabilize": 80},
        {"name": "teal_light", "cmd": teal_light_transaction, "clearout": 45, "stabilize": 90},
        {"name": "teal_normal", "cmd": teal_normal_transaction, "clearout": 45, "stabilize": 90},
        {"name": "teal_heavy", "cmd": teal_heavy_transaction, "clearout": 45, "stabilize": 90},
        {"name": "atomic_transfer_small", "cmd": atomic_transfer_small_transaction, "clearout": 45, "stabilize": 120},
        {"name": "atomic_transfer_heavy", "cmd": atomic_transfer_large_transaction, "clearout": 45, "stabilize": 120},
        # TODO: rebuild mixed workloads around new single-pingpong-mixed-workload
        # {"name": "mixed_light",
        #  "cmd": [payment_transaction_quarter, teal_light_transaction_quarter, atomic_transfer_small_transaction_quarter,
        #          asset_transfer_small_transaction_quarter], "clearout": 45, "stabilize": 300},
        # {"name": "mixed_heavy",
        #  "cmd": [payment_transaction_quarter, teal_heavy_transaction_quarter, atomic_transfer_large_transaction_quarter,
        #          asset_transfer_large_transaction_quarter], "clearout": 45, "stabilize": 300},
        {"name": "rekey_payment", "cmd": rekey_payment_transaction, "clearout": 45, "stabilize": 120}
    ]
    return testcases

class pingpong:
    def __init__(self, args, algod_data=None, duration_seconds=300):
        self.args = args
        self.algod_data = algod_data
        self.duration_seconds = duration_seconds
        self.output = None
        self.gzo = None
        self.p = None
        return

    def start(self):
        cmd = ['pingpong', 'run', '--quiet', '--duration', si(self.duration_seconds)]
        if self.algod_data:
            cmd += ['-d', self.algod_data]
        cmd += self.args
        self.output = tempfile.SpooledTemporaryFile(max_size=10_000_000)
        self.gzo = gzip.open(self.output, 'wb')
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.t = threading.Thread(target=self.shuffle)
        self.t.start()

    def shuffle(self):
        # move data from self.p.stdout to self.output
        while True:
            buf = self.p.stdout.read(65536)
            if buf:
                self.gzo.write(buf)
            elif self.p.poll() is not None:
                return
            else:
                time.sleep(0.1)

    def close(self):
        if self.gzo:
            self.gzo.close()
            self.gzo = None
        if self.output:
            self.output.close()
            self.output = None

    def wait(self, timeout=None):
        retcode = self.p.wait(timeout)
        return retcode

    def getOutput(self):
        if self.gzo:
            self.gzo.close()
            self.gzo = None
        self.output.seek(0)
        return gzip.open(self.output, 'rb').read()


class Fetcher:
    def __init__(self, algorand_data=None, token=None, addr=None, headers=None, prev_round=None):
        """
        algorand_data = path to algod data dir
        addr, token = algod URI and access token
        headers = dict of HTTP headers to send to algod
        prev_round = start with (prev_round + 1)
        """
        self.algorand_data = algorand_data
        self.token = token
        self.addr = addr
        self.headers = headers
        self._algod = None
        self.go = True
        self.prev_round = prev_round
        self.block_time = None
        self.data = []
        self.lock = threading.Lock()
        return

    def algod(self):
        "return an open algosdk.v2client.algod.AlgodClient"
        if self._algod is None:
            if self.algorand_data:
                addr, token = addr_token_from_algod(self.algorand_data)
                logger.debug('algod from %r, (%s %s)', self.algorand_data, addr, token)
            else:
                token = self.token
                addr = self.addr
                logger.debug('algod from args (%s %s)', self.addr, self.token)
            self._algod = AlgodClient(token, addr, headers=self.headers)
        return self._algod

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
                blk = self.algod().block_info(lastround + 1, response_format='msgpack')
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
                blk = self.algod().block_info(lastround + 1, response_format='msgpack')
                if blk:
                    return blk
                logger.warning('null block %d, lastround=%r, status.last-round=%d', lastround+1, lastround, nbr)
                time.sleep(1.1)
                retries -= 1
                if retries <= 0:
                    raise Exception("too many null block for %d", lastround+1)
            except:
                break
        blk = self.algod().block_info(nbr, response_format='msgpack')
        if blk:
            self.block_time = block_time
            return blk
        raise Exception('got None for blk {}'.format(nbr))

    def loop(self):
        """Start processing blocks and txns
        runs until error or bot.go=False
        """
        try:
            self._loop_inner()
        finally:
            self.close()

    def _loop_inner(self):
        with self.lock:
            lastround = self.prev_round
        while self.go:
            b = self.nextblock(lastround)
            if b is None:
                print("got None nextblock. exiting")
                return
            b = msgpack.loads(b, strict_map_key=False)
            nowround = b['block'].get('rnd', 0)
            if (lastround is not None) and (nowround != lastround + 1):
                logger.info('round jump %d to %d', lastround, nowround)
            with self.lock:
                lastround = nowround
                self.prev_round = nowround
            self._block_handler(b)

    def get_round(self):
        with self.lock:
            return self.prev_round

    def get_data(self, ra, rb):
        out = []
        with self.lock:
            for rec in self.data:
                if ra <= rec['r'] <= rb:
                    out.append(rec)
        return out

    def _block_handler(self, ba):
        bytxtype = {}
        rec = {}
        rec['ts'] = ba['block'].get('ts',0)
        rec['tc'] = ba['block'].get('tc',0)
        txns = ba['block'].get('txns',[])
        for stxib in txns:
            #logger.debug('txn keys %s', sorted(stxib['txn'].keys()))
            tt = stxib['txn']['type']
            bytxtype[tt] = bytxtype.get(tt, 0) + 1
        rec['t'] = self.block_time or time.time()
        rec['x'] = bytxtype
        rec['r'] = ba['block'].get('rnd', 0)
        self.data.append(rec)

    def close(self):
        self._algod = None

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
    ap.add_argument('--segment-duration', default=90, type=int, help='seconds to run each test case')
    ap.add_argument('--header', dest='headers', nargs='*', help='"Name: value" HTTP header (repeatable)')
    ap.add_argument('--skip', default=[], action='append', help='test cases to skip (repeatable)')
    ap.add_argument('--include', default=[], action='append', help='test cases to include (repeatable)')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    algorand_data = args.algod or os.getenv('ALGORAND_DATA')
    if not algorand_data and not (args.token and args.addr):
        sys.stderr.write('must specify algod data dir by $ALGORAND_DATA or -d/--algod; OR --a/--addr and -t/--token\n')
        sys.exit(1)

    prev_round = None
    bot = Fetcher(
        algorand_data,
        token=args.token,
        addr=args.addr,
        headers=header_list_to_dict(args.headers),
        prev_round=prev_round,
    )

    bott = threading.Thread(target=bot.loop)
    bott.start()

    # TODO: args into build testcases()
    testcases = build_testcases()
    # TODO: arg to filter testcases
    for tc in testcases:
        name = tc['name']
        if (name in args.skip) or (args.include and (name not in args.include)):
            print('{} skipped'.format(name))
            continue
        print('{} starting'.format(name))
        cmd = tc['cmd']
        pp = pingpong(cmd, algorand_data, duration_seconds=args.segment_duration)
        pp.start()
        start_round = bot.get_round()
        while start_round is None:
            time.sleep(1)
            start_round = bot.get_round()
        start_round += 2
        retcode = pp.wait()
        if retcode != 0:
            print('pingpong ret {}'.format(retcode))
            print(pp.getOutput())
            print('pingpong ret {}'.format(retcode))
        end_round = bot.get_round()
        data = bot.get_data(start_round, end_round)
        tpsTarget = float(cmd[cmd.index('--tps')+1])
        txnActual = data[-1]['tc'] - data[0]['tc']
        dt = data[-1]['t'] - data[0]['t']
        tpsActual = txnActual / dt
        rounds = data[-1]['r'] - data[0]['r']
        print('{} --tps {}, actual {} ({:.1f}%) ({} rounds)'.format(name, tpsTarget, tpsActual, (tpsActual * 100.0)/tpsTarget, rounds))

    bot.go = False
    bott.join()

if __name__ == '__main__':
    main()
