#!/usr/bin/env python3
# Copyright (C) 2019-2024 Algorand, Inc.
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
import json
import os
import statistics
import sys

from algosdk.encoding import msgpack
from matplotlib import pyplot as plt

def process(path, args):
    minrnd = None
    maxrnd = None
    # maybe load first/last round bounds from heapWatch.py emitted rounds.json
    rounds_json = os.path.join(os.path.dirname(path), 'rounds.json')
    if os.path.exists(rounds_json):
        with open(rounds_json) as fin:
            rounds = json.load(fin)
        minrnd = rounds['min']
        maxrnd = rounds['max']
    minrnd = args.start or minrnd or 0
    maxrnd = args.stop or maxrnd
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
            if (rnd < minrnd) or ((maxrnd is not None) and (rnd > maxrnd)):
                sys.stderr.write(f'skip rnd {rnd}\n')
                continue
            if (prevrnd is not None) and (rnd <= prevrnd):
                sys.stderr.write(f'wat rnd {rnd}, prevrnd {prevrnd}, line {count}\n')
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
                if dt > 0.5:
                    dtxn = tc - prevtc
                    if dtxn < 0:
                        sys.stderr.write(f'{path}:{count} tc {tc}, prevtc {prevtc}, rnd {rnd}, prevrnd {prevrnd}\n')
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
                    sys.stderr.write('b[{}] - b[{}], dt={}\n'.format(rnd-1,rnd,dt))
            else:
                tsv.append(ts)
            prevrnd = rnd
            prevtc = tc
            prevts = ts
            prevtime = _time
    print('{} blocks, block txns [{}-{}], block seconds [{}-{}], tps [{}-{}], total txns {}'.format(
        count,
        mintxn,maxtxn,
        mindt,maxdt,
        mintps,maxtps,
        tc,
    ))
    if tc > 0:
        with open(path + '.stats', 'w') as fout:
            fout.write(json.dumps({
                'blocks': count,
                'tc': tc,
                'mintxn': mintxn,
                'maxtxn': maxtxn,
                'mindt': mindt,
                'maxdt': maxdt,
                'mintps': mintps,
                'maxtps': maxtps,
            }))

    start = 0
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
    fig, ((ax1, ax2, ax3), (ax4, ax5, ax6)) = plt.subplots(2,3, figsize=(10, 5))
    ax1.set_title('round time histogram (sec)')
    ax1.hist(list(filter(lambda x: x < 9,dtv[start:end])),bins=20)

    ax4.set_title('round time')
    ax4.plot(dtv[start:end])

    ax2.set_title('txn/block histogram')
    ax2.hist(txnv[start:end],bins=20)

    ax5.set_title('txn/block')
    ax5.plot(txnv[start:end])

    ax3.set_title('TPS')
    ax3.hist(tpsv[start:end],bins=20)

    # 10 round moving average TPS
    tpsv10 = []
    for i in range(10,len(tsv)):
        ts0 = tsv[i-10]
        tsa = tsv[i]
        tc0 = tcv[i-10]
        tca = tcv[i]
        dt = tsa-ts0
        if dt == 0:
            continue
        dtxn = tca-tc0
        tpsv10.append(dtxn/dt)
    if args.tps1:
        ax6.set_title('TPS')
        ax6.plot(tpsv[start:end])
        print('fullish block sizes: {}'.format(list(filter(lambda x: x > 100, txnv))))
    else:
        ax6.set_title('TPS(10 round window)')
        ax6.plot(tpsv10)
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
    ap.add_argument('--start', default=None, type=int, help='start round')
    ap.add_argument('--stop', default=None, type=int, help='stop round')
    args = ap.parse_args()

    for fname in args.files:
        process(fname, args)

if __name__ == '__main__':
    main()
