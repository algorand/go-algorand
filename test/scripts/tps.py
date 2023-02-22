#!/usr/bin/python3
#
# Ask algod what its recent Transactions Per Second have been
#
# usage:
#  python3 tps.py -r 10 --verbose $ALGORAND_DATA

import argparse
import logging
import os
import sys

# pip install py-algorand-sdk
import algosdk
from algosdk.encoding import msgpack
import algosdk.v2client
import algosdk.v2client.algod

logger = logging.getLogger(__name__)

def read_algod_dir(algorand_data):
    with open(os.path.join(algorand_data, 'algod.net')) as fin:
        net = fin.read().strip()
    with open(os.path.join(algorand_data, 'algod.token')) as fin:
        token = fin.read().strip()
    with open(os.path.join(algorand_data, 'algod.admin.token')) as fin:
        admin_token = fin.read().strip()
    return net, token, admin_token

def algod_client_for_dir(algorand_data, headers=None):
    if headers is None:
        headers = {}
    net, token, admin_token = read_algod_dir(algorand_data)
    if not net.startswith('http'):
        net = 'http://' + net
    return algosdk.v2client.algod.AlgodClient(token, net, headers)

def get_blockinfo_tps(algod, rounds=10):
    status = algod.status()
    ba = msgpack.loads(algod.block_info(status['last-round']-rounds, response_format='msgpack'), strict_map_key=False)
    bb = msgpack.loads(algod.block_info(status['last-round'], response_format='msgpack'), strict_map_key=False)
    ra = ba['block']['rnd']
    rb = bb['block']['rnd']
    assert(rb - ra == rounds)
    tca = ba['block'].get('tc',0)
    tcb = bb['block'].get('tc',0)
    tsa = ba['block']['ts']
    tsb = bb['block']['ts']
    dt = tsb-tsa
    dtxn = tcb-tca
    tps = dtxn/dt
    logger.debug('(b[%d].TimeStamp %d) - (b[%d].TimeStamp %d) = %.1f seconds', ra, tsa, rb, tsb, dt)
    logger.debug('(b[%d].TxnCounter %d) - (b[%d].TxnCounter %d) = %d txns', ra, tca, rb, tcb, dtxn)
    return tps

def mins(a,b):
    if a is None:
        return b
    if b is None:
        return a
    return min(a,b)

def maxs(a,b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a,b)

def get_blockinfo_tps_with_types(algod, rounds=10, adir=''):
    status = algod.status()
    lastround = status['last-round']
    cround = lastround - rounds
    bytxtype = {}
    mintime = None
    maxtime = None
    mintc = None
    maxtc = 0
    while cround <= lastround:
        ba = msgpack.loads(algod.block_info(cround, response_format='msgpack'), strict_map_key=False)
        #logger.debug('block keys %s', sorted(ba['block'].keys()))
        mintime = mins(mintime, ba['block']['ts'])
        maxtime = maxs(maxtime, ba['block']['ts'])
        mintc = mins(mintc, ba['block'].get('tc'))
        maxtc = maxs(maxtc, ba['block'].get('tc',0))
        txns = ba['block'].get('txns',[])
        for stxib in txns:
            #logger.debug('txn keys %s', sorted(stxib['txn'].keys()))
            tt = stxib['txn']['type']
            bytxtype[tt] = bytxtype.get(tt, 0) + 1
        cround += 1
    summary = [(count, tt) for tt,count in bytxtype.items()]
    summary.sort(reverse=True)
    print(summary)
    dt = maxtime-mintime
    dtxn = maxtc-mintc
    logger.debug('%s ts=[%d..%d] (%ds), tc=[%d..%d] (%d txn)', adir, mintime, maxtime, dt, mintc, maxtc, dtxn)
    tps = dtxn/dt
    return tps

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('data_dirs', nargs='*', help='list paths to algorand datadirs to grab heap profile from')
    ap.add_argument('-d', dest='algorand_data')
    ap.add_argument('-T', '--types', default=False, action='store_true', help='show txn types counts within round range')
    ap.add_argument('-r', '--rounds', type=int, default=10, help='number of rounds to calculate over')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    datadirs = args.data_dirs
    if args.algorand_data:
        datadirs = datadirs + [args.algorand_data]
    if not datadirs:
        ad = os.getenv('ALGORAND_DATA')
        if ad:
            datadirs.append(ad)
    if not datadirs:
        sys.stderr.write('no data dirs specified (positional file, -d AD, $ALGORAND_DATA)')
        sys.exit(1)

    for adir in datadirs:
        algod = algod_client_for_dir(adir)
        if args.types:
            tps = get_blockinfo_tps_with_types(algod, rounds=args.rounds)
        else:
            tps = get_blockinfo_tps(algod, rounds=args.rounds)
        print('{:5.1f} TPS\t{}'.format(tps, adir))
    return 0

if __name__ == '__main__':
    sys.exit(main())
