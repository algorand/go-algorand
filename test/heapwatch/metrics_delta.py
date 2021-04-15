#!/usr/bin/env python3

import argparse
import contextlib
import csv
import gzip
import logging
import json
import os
import sys
import time

logger = logging.getLogger(__name__)

def num(x):
    if '.' in x:
        return float(x)
    return int(x)

def parse_metrics(fin):
    out = dict()
    for line in fin:
        if not line:
            continue
        line = line.strip()
        if not line:
            continue
        if line[0] == '#':
            continue
        ab = line.split()
        out[ab[0]] = num(ab[1])
    return out

# return b-a
def metrics_delta(a,b):
    old_unseen = set(a.keys())
    d = dict()
    for k,bv in b.items():
        if k in a:
            av = a.get(k, 0)
            d[k] = bv-av
            old_unseen.remove(k)
        else:
            d[k] = bv
    for k in old_unseen:
        d[k] = 0-a[k]
    return d

# slightly smarter open, stdout for '-', auto .gz
def sopen(path, mode):
    if path == '-':
        return contextlib.nullcontext(sys.stdout)
    if path.endswith('.gz'):
        return contextlib.closing(gzip.open(path, mode))
    return open(path, mode)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_files', nargs='*')
    ap.add_argument('--deltas', default=None, help='path to write csv deltas')
    ap.add_argument('--report', default=None, help='path to write csv report')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    reportf = None
    writer = None
    if args.report:
        if args.report == '-':
            writer = csv.writer(sys.stdout)
        else:
            reportf = open(args.report, 'wt')
            writer = csv.writer(reportf)
        writer.writerow(('when', 'tx bytes/s', 'rx bytes/s','TPS', 's/block'))
    prev = None
    prevtime = None
    prevPath = None
    prevbi = None

    deltas = []
    for path in sorted(args.metrics_files):
        with open(path, 'rt') as fin:
            cur = parse_metrics(fin)
        bijsonpath = path.replace('.metrics', '.blockinfo.json')
        bi = None
        if os.path.exists(bijsonpath):
            with open(bijsonpath, 'rt') as fin:
                bi = json.load(fin)
        curtime = os.path.getmtime(path)
        logger.debug('%s: %r', path, cur)
        if prev is not None:
            d = metrics_delta(prev, cur)
            dt = curtime - prevtime
            #print("{} ->\n{}".format(prevPath, path))
            #print(json.dumps(d, indent=2, sort_keys=True))
            deltas.append((curtime, d))
            tps = None
            blocktime = None
            if bi and prevbi:
                tps = (bi.get('block',{}).get('tc', 0) - prevbi.get('block',{}).get('tc', 0)) / dt
                rounds = (bi.get('block',{}).get('rnd', 0) - prevbi.get('block',{}).get('rnd', 0))
                if rounds != 0:
                    blocktime = dt/rounds
            if writer:
                txBytesPerSec = d.get('algod_network_sent_bytes_total{}',0) / dt
                rxBytesPerSec = d.get('algod_network_received_bytes_total{}',0) /dt
                writer.writerow((
                    time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(curtime)),
                    txBytesPerSec,
                    rxBytesPerSec,
                    tps,
                    blocktime,
                ))
        prev = cur
        prevPath = path
        prevtime = curtime
        prevbi = bi
    if reportf:
        reportf.close()
    if deltas and args.deltas:
        keys = set()
        for ct, d in deltas:
            keys.update(set(d.keys()))
        keys = sorted(keys)
        with sopen(args.deltas, 'wt') as fout:
            writer = csv.writer(fout)
            writer.writerow(['when'] + keys)
            for ct, d in deltas:
                row = [time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ct))]
                for k in keys:
                    row.append(d.get(k, None))
                writer.writerow(row)
    return 0

if __name__ == '__main__':
    sys.exit(main())
