#!/usr/bin/env python3
# Copyright (C) 2019-2022 Algorand, Inc.
# This file is part of go-algorand
#
# go-algorand is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# go-algorand is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.
#
###
#
# Plot the output of test/heapwatch/{block_history.py,block_history_relays.py}
#
# Histograms of round times, TPS, txn/block
# Graph over time of TPS or 10-round-moving-average-TPS

import base64
import statistics

from algosdk.encoding import msgpack
from matplotlib import pyplot as plt

def process(path, args):
    prevtime = None
    prevtc = 0
    prevts = None
    prevrnd = None
    mintxn = 9999999
    maxtxn = 0
    mindt = 999999
    maxdt = 0
    mintps = 999999
    maxtps = 0
    tcv = []
    tsv = []
    tpsv = []
    dtv = []
    txnv = []
    count = 0
    with open(path, 'rb') as fin:
        for line in fin:
            line = line.strip()
            row = msgpack.loads(base64.b64decode(line), strict_map_key=False)
            count += 1
            block = row['block']
            rnd = block.get('rnd',0)
            tc = block.get('tc', 0)
            ts = block.get('ts', 0) # timestamp recorded at algod, 1s resolution int
            _time = row['_time'] # timestamp recorded at client, 0.000001s resolution float
            tcv.append(tc)
            if prevtime is not None:
                dt = _time - prevtime
                if dt < 1:
                    dt = ts - prevts
                    tsv.append(ts)
                else:
                    if _time < tsv[-1]:
                        tsv.append(ts)
                    else:
                        tsv.append(_time)
                dtxn = tc - prevtc
                tps = dtxn / dt
                mintxn = min(dtxn,mintxn)
                maxtxn = max(dtxn,maxtxn)
                mindt = min(dt,mindt)
                maxdt = max(dt,maxdt)
                mintps = min(tps,mintps)
                maxtps = max(tps,maxtps)
                tpsv.append(tps)
                dtv.append(dt)
                txnv.append(dtxn)
            else:
                tsv.append(ts)
            prevrnd = rnd
            prevtc = tc
            prevts = ts
            prevtime = _time
    print('{} blocks, block txns [{}-{}], block seconds [{}-{}], tps [{}-{}]'.format(
        count,
        mintxn,maxtxn,
        mindt,maxdt,
        mintps,maxtps,
    ))

    start = args.start
    end = len(txnv)-1
    if not args.all:
        # find the real start of the test
        start += 1
        for i in range(len(txnv)):
            if len(list(filter(lambda x: x > 100, txnv[i:i+5]))) == 5:
                start = i + 5
                break
        txmean = statistics.mean(txnv[start:])
        txstd = statistics.stdev(txnv[start:])
        end = len(txnv)
        for i in range(start,len(txnv)):
            if len(list(filter(lambda x: x > txmean-(txstd*2), txnv[i:i+5]))) < 4:
                print(i)
                end = i
                break

    print('core test rounds [{}:{}]'.format(start,end))
    print('block txns [{}-{}], block seconds [{}-{}], tps [{}-{}]'.format(
        min(txnv[start:end]), max(txnv[start:end]),
        min(dtv[start:end]), max(dtv[start:end]),
        min(tpsv[start:end]), max(tpsv[start:end]),
    ))
    print('long round times: {}'.format(' '.join(list(map(str,filter(lambda x: x >= 9,dtv[start:end]))))))
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2,2)
    ax1.set_title('round time (seconds)')
    ax1.hist(list(filter(lambda x: x < 9,dtv[start:end])),bins=20)

    if args.rtime:
        ax2.set_title('round time')
        ax2.plot(dtv)
    else:
        ax2.set_title('TPS')
        ax2.hist(tpsv[start:end],bins=20)

    ax3.set_title('txn/block')
    ax3.hist(txnv[start:end],bins=20)

    # 10 round moving average TPS
    tpsv10 = []
    for i in range(10,len(tsv)):
        ts0 = tsv[i-10]
        tsa = tsv[i]
        tc0 = tcv[i-10]
        tca = tcv[i]
        dt = tsa-ts0
        dtxn = tca-tc0
        tpsv10.append(dtxn/dt)
    if args.tps1:
        ax4.set_title('TPS')
        ax4.plot(tpsv[start:end])
        print('fullish block sizes: {}'.format(list(filter(lambda x: x > 100, txnv))))
    else:
        ax4.set_title('TPS(10 round window)')
        ax4.plot(tpsv10)
    fig.tight_layout()
    plt.savefig(path + '_hist.svg', format='svg')
    plt.savefig(path + '_hist.png', format='png')

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+')
    ap.add_argument('--all', default=False, action='store_true')
    ap.add_argument('--tps1', default=False, action='store_true')
    ap.add_argument('--rtime',  default=False, action='store_true')
    ap.add_argument('--start', default=0, type=int, help='start round')
    args = ap.parse_args()

    for fname in args.files:
        process(fname, args)

if __name__ == '__main__':
    main()
