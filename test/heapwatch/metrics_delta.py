#!/usr/bin/env python3

import argparse
import contextlib
import csv
import gzip
import logging
import json
import os
import re
import statistics
import sys
import time

logger = logging.getLogger(__name__)

def num(x):
    if '.' in x:
        return float(x)
    return int(x)

metric_line_re = re.compile(r'(\S+\{[^}]*\})\s+(.*)')

def test_metric_line_re():
    testlines = (
        ('algod_network_connections_dropped_total{reason="write err"} 1', 1),
        #('algod_network_sent_bytes_MS 274992', 274992), # handled by split
    )
    for line, n in testlines:
        try:
            m = metric_line_re.match(line)
            assert int(m.group(2)) == n
        except:
            logger.error('failed on line %r', line, exc_info=True)
            raise

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
        m = metric_line_re.match(line)
        if m:
            out[m.group(1)] = num(m.group(2))
        else:
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

# d = {k:[v,...]}
def dapp(d, k, v):
    l = d.get(k)
    if l is None:
        d[k] = [v]
    else:
        l.append(v)

class summary:
    def __init__(self):
        self.tpsMeanSum = 0
        self.txBpsMeanSum = 0
        self.rxBpsMeanSum = 0
        self.sumsCount = 0

    def __call__(self, ttr, nick):
        if not ttr:
            return
        tpsList, txBpsList, rxBpsList = ttr
        logger.debug('%d points from %s', len(tpsList), nick)
        self.tpsMeanSum += statistics.mean(tpsList)
        self.txBpsMeanSum += statistics.mean(txBpsList)
        self.rxBpsMeanSum += statistics.mean(rxBpsList)
        self.sumsCount += 1

    def __str__(self):
        return 'summary: {:0.2f} TPS, {:0.0f} tx B/s, {:0.0f} rx B/s'.format(self.tpsMeanSum/self.sumsCount, self.txBpsMeanSum/self.sumsCount, self.rxBpsMeanSum/self.sumsCount)

def main():
    test_metric_line_re()
    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_files', nargs='*')
    ap.add_argument('--mintps', default=None, type=float, help="records below min TPS don't add into summary")
    ap.add_argument('--deltas', default=None, help='path to write csv deltas')
    ap.add_argument('--report', default=None, help='path to write csv report')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    metrics_fname_re = re.compile(r'(.*)\.(.*).metrics')
    filesByNick = {}
    nonick = []
    for path in args.metrics_files:
        fname = os.path.basename(path)
        m = metrics_fname_re.match(fname)
        if not m:
            logger.error('could not parse metrics file name %r', fname)
            nonick.append(path)
            continue
        nick = m.group(1)
        dapp(filesByNick, nick, path)
    rsum = summary()
    if nonick:
        rsum(process_files(args, None, nonick), 'no nick')
    for nick, paths in filesByNick.items():
        rsum(process_files(args, nick, paths), nick)
    print(rsum)
    return 0

def process_files(args, nick=None, metrics_files=None):
    if metrics_files is None:
        return
    reportf = None
    writer = None
    reportpath = None
    if args.report:
        if args.report == '-':
            writer = csv.writer(sys.stdout)
        else:
            if nick is None:
                reportpath = args.report
            elif args.report.endswith('.csv'):
                reportpath = args.report[:-4] + nick + '.csv'
            reportf = open(reportpath, 'wt')
            writer = csv.writer(reportf)
        writer.writerow(('when', 'tx bytes/s', 'rx bytes/s','TPS', 's/block'))
    prev = None
    prevtime = None
    prevPath = None
    prevbi = None

    deltas = []
    txBpsList = []
    rxBpsList = []
    tpsList = []
    for path in sorted(metrics_files):
        with open(path, 'rt') as fin:
            cur = parse_metrics(fin)
        bijsonpath = path.replace('.metrics', '.blockinfo.json')
        bi = None
        if os.path.exists(bijsonpath):
            with open(bijsonpath, 'rt') as fin:
                bi = json.load(fin)
        curtime = os.path.getmtime(path)
        #logger.debug('%s: %r', path, cur)
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
            txBytesPerSec = d.get('algod_network_sent_bytes_total{}',0) / dt
            rxBytesPerSec = d.get('algod_network_received_bytes_total{}',0) /dt
            if (tps is None) or ((args.mintps is not None) and (tps < args.mintps)):
                # do not sum up this row
                pass
            else:
                txBpsList.append(txBytesPerSec)
                rxBpsList.append(rxBytesPerSec)
                tpsList.append(tps)
            if writer:
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
    if writer and txBpsList:
        writer.writerow([])
        writer.writerow(['min', min(txBpsList), min(rxBpsList), min(tpsList)])
        writer.writerow(['avg', statistics.mean(txBpsList), statistics.mean(rxBpsList), statistics.mean(tpsList)])
        writer.writerow(['max', max(txBpsList), max(rxBpsList), max(tpsList)])
        writer.writerow(['std', statistics.pstdev(txBpsList), statistics.pstdev(rxBpsList), statistics.pstdev(tpsList)])
    if reportf:
        reportf.close()
    if deltas and args.deltas:
        keys = set()
        for ct, d in deltas:
            keys.update(set(d.keys()))
        keys = sorted(keys)
        deltapath = args.deltas
        if nick is not None:
            deltapath = deltapath.replace('.csv', '.{}.csv'.format(nick))
        with sopen(deltapath, 'wt') as fout:
            writer = csv.writer(fout)
            writer.writerow(['when'] + keys)
            for ct, d in deltas:
                row = [time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ct))]
                for k in keys:
                    row.append(d.get(k, None))
                writer.writerow(row)
        logger.debug('wrote %r', deltapath)
    if reportpath:
        logger.debug('wrote %r', reportpath)
    return tpsList, txBpsList, rxBpsList

if __name__ == '__main__':
    sys.exit(main())
