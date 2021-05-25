#!/usr/bin/env python3

import argparse
import configparser
import contextlib
import csv
import glob
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

def dictSum(dest, more):
    for k, v in more.items():
        dest[k] = dest.get(k,0) + v
    return dest

def dictMax(dest, more):
    for k, v in more.items():
        if isinstance(v, (list,tuple)):
            v = max(v)
        ov = dest.get(k)
        if ov is None:
            dest[k] = v
        else:
            dest[k] = max(ov,v)
    return dest

def dictMin(dest, more):
    for k, v in more.items():
        if isinstance(v, (list,tuple)):
            v = min(v)
        ov = dest.get(k)
        if ov is None:
            dest[k] = v
        else:
            dest[k] = min(ov,v)
    return dest

class summary:
    def __init__(self):
        self.tpsMeanSum = 0
        self.txBpsMeanSum = 0
        self.rxBpsMeanSum = 0
        self.sumsCount = 0
        self.nodes = {}

    def __call__(self, ttr, nick):
        if not ttr:
            return
        self.nodes[nick] = ttr
        logger.debug('%d points from %s', len(ttr.tpsList), nick)
        self.tpsMeanSum += statistics.mean(ttr.tpsList)
        self.txBpsMeanSum += statistics.mean(ttr.txBpsList)
        self.rxBpsMeanSum += statistics.mean(ttr.rxBpsList)
        self.sumsCount += 1

    def byMsg(self):
        txPSums = {}
        rxPSums = {}
        secondsSum = 0
        txMax = {}
        txMin = {}
        rxMax = {}
        rxMin = {}
        nicks = []
        for nick, ns in self.nodes.items():
            nicks.append(nick)
            secondsSum += ns.secondsSum
            dictSum(txPSums, ns.txPSums)
            dictSum(rxPSums, ns.rxPSums)
            dictMax(txMax, ns.txPLists)
            dictMax(rxMax, ns.rxPLists)
            dictMin(txMin, ns.txPLists)
            dictMin(rxMin, ns.rxPLists)
        lines = ['{} nodes: {}'.format(len(nicks), nicks)]
        for msg, txB in txPSums.items():
            if msg not in rxPSums:
                rxPSums[msg] = 0
        for rxBps, msg in sorted([(rxB/secondsSum, msg) for msg, rxB in rxPSums.items()], reverse=True):
            txBps = txPSums.get(msg,0)/secondsSum
            lines.append('{}\t{:.0f} tx B/s\t{:.0f} rx B/s'.format(msg, txBps, rxBps))
        return '\n'.join(lines)


    def __str__(self):
        return '{}\nsummary: {:0.2f} TPS, {:0.0f} tx B/s, {:0.0f} rx B/s'.format(self.byMsg(), self.tpsMeanSum/self.sumsCount, self.txBpsMeanSum/self.sumsCount, self.rxBpsMeanSum/self.sumsCount)

def anynickre(nick_re, nicks):
    if not nick_re:
        return True
    for nre in nick_re:
        p = re.compile(nre)
        for nick in nicks:
            if p.match(nick):
                return True
    return False

def main():
    test_metric_line_re()
    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_files', nargs='*')
    ap.add_argument('-d', '--dir', default=None, help='dir path to find /*.metrics in')
    ap.add_argument('--mintps', default=None, type=float, help="records below min TPS don't add into summary")
    ap.add_argument('--deltas', default=None, help='path to write csv deltas')
    ap.add_argument('--report', default=None, help='path to write csv report')
    ap.add_argument('--nick-re', action='append', default=[], help='regexp to filter node names, may be repeated')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    metrics_files = args.metrics_files
    metrics_dirs = set()
    if args.dir:
        metrics_dirs.add(args.dir)
        metrics_files += glob.glob(os.path.join(args.dir, '*.metrics'))
    metrics_fname_re = re.compile(r'(.*)\.(.*).metrics')
    filesByNick = {}
    nonick = []
    tf_inventory_path = None
    for path in metrics_files:
        fname = os.path.basename(path)
        if fname == 'terraform-inventory.host':
            tf_inventory_path = path
            continue
        metrics_dirs.add(os.path.dirname(path))
        m = metrics_fname_re.match(fname)
        if not m:
            logger.error('could not parse metrics file name %r', fname)
            nonick.append(path)
            continue
        nick = m.group(1)
        dapp(filesByNick, nick, path)
    if not tf_inventory_path:
        for md in metrics_dirs:
            tp = os.path.join(md, 'terraform-inventory.host')
            if os.path.exists(tp):
                tf_inventory_path = tp
                break
    nick_to_tfname = {}
    if tf_inventory_path:
        tf_inventory = configparser.ConfigParser(allow_no_value=True)
        tf_inventory.read(tf_inventory_path)
        ip_to_name = {}
        for k, sub in tf_inventory.items():
            if k.startswith('name_'):
                for ip in sub:
                    if ip in ip_to_name:
                        logger.warning('ip %r already named %r, also got %r', ip, ip_to_name[ip], k)
                    ip_to_name[ip] = k
        #logger.debug('names: %r', sorted(ip_to_name.values()))
        #logger.debug('ip to name %r', ip_to_name)
        for ip, name in ip_to_name.items():
            found = []
            for nick in filesByNick.keys():
                if ip in nick:
                    found.append(nick)
            if len(found) == 1:
                nick_to_tfname[found[0]] = name
            elif len(found) > 1:
                logger.warning('ip %s (%s) found in nicks: %r', ip, name, found)
            else:
                logger.warning('ip %s no nick')
        #logger.debug('nick_to_tfname %r', nick_to_tfname)

    if args.nick_re:
        # use each --nick-re=foo as a group
        for nre in args.nick_re:
            rsum = summary()
            nretup = (nre,)
            for rnick, paths in filesByNick.items():
                nick = nick_to_tfname.get(rnick, rnick)
                if anynickre(nretup, (rnick,nick)):
                    rsum(process_files(args, nick, paths), nick)
            print(rsum)
            print('\n')
        return 0

    # no filters, glob it all up
    rsum = summary()
    if nonick:
        rsum(process_files(args, None, nonick), 'no nick')
    for rnick, paths in filesByNick.items():
        nick = nick_to_tfname.get(rnick, rnick)
        rsum(process_files(args, nick, paths), nick)
    print(rsum)
    return 0

def perProtocol(prefix, lists, sums, deltas, dt):
    lp = len(prefix)
    for k, v in deltas.items():
        if k.startswith(prefix):
            sub = k[lp:]
            dapp(lists, sub, v/dt)
            sums[sub] = sums.get(sub,0) + v

def process_files(args, nick, paths):
    return nodestats().process_files(args, nick, paths)

class nodestats:
    def __init__(self):
        self.nick = None
        self.args = None
        self.deltas = []
        self.txBpsList = []
        self.rxBpsList = []
        self.tpsList = []
        self.txBSum = 0
        self.rxBSum = 0
        self.txnSum = 0
        self.secondsSum = 0
        # algod_network_received_bytes_*
        self.rxPLists = {}
        self.rxPSums = {}
        # algod_network_sent_bytes_*
        self.txPLists = {}
        self.txPSums = {}

    def process_files(self, args, nick=None, metrics_files=None):
        self.args = args
        self.nick = nick
        if metrics_files is None:
            return self
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
                self.deltas.append((curtime, d))
                tps = None
                blocktime = None
                txnCount = 0
                if bi and prevbi:
                    txnCount = (bi.get('block',{}).get('tc', 0) - prevbi.get('block',{}).get('tc', 0))
                    tps = txnCount / dt
                    rounds = (bi.get('block',{}).get('rnd', 0) - prevbi.get('block',{}).get('rnd', 0))
                    if rounds != 0:
                        blocktime = dt/rounds
                txBytes = d.get('algod_network_sent_bytes_total{}',0)
                rxBytes = d.get('algod_network_received_bytes_total{}',0)
                txBytesPerSec = txBytes / dt
                rxBytesPerSec = rxBytes / dt
                # TODO: gather algod_network_sent_bytes_* and algod_network_received_bytes_*
                if (tps is None) or ((args.mintps is not None) and (tps < args.mintps)):
                    # do not sum up this row
                    pass
                else:
                    self.txBpsList.append(txBytesPerSec)
                    self.rxBpsList.append(rxBytesPerSec)
                    self.tpsList.append(tps)
                    self.txBSum += txBytes
                    self.rxBSum += rxBytes
                    self.txnSum += txnCount
                    self.secondsSum += dt
                    perProtocol('algod_network_sent_bytes_', self.txPLists, self.txPSums, d, dt)
                    perProtocol('algod_network_received_bytes_', self.rxPLists, self.rxPSums, d, dt)
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
        if writer and self.txBpsList:
            writer.writerow([])
            for bsum, msg in sorted([(bsum,msg) for msg,bsum in self.txPSums.items()]):
                pass
            writer.writerow([])
            writer.writerow(['min', min(self.txBpsList), min(self.rxBpsList), min(self.tpsList)])
            writer.writerow(['avg', self.txBSum/self.secondsSum, self.rxBSum/self.secondsSum, self.txnSum/self.secondsSum])
            writer.writerow(['max', max(self.txBpsList), max(self.rxBpsList), max(self.tpsList)])
            writer.writerow(['std', statistics.pstdev(self.txBpsList), statistics.pstdev(self.rxBpsList), statistics.pstdev(self.tpsList)])
        if reportf:
            reportf.close()
        if self.deltas and args.deltas:
            keys = set()
            for ct, d in self.deltas:
                keys.update(set(d.keys()))
            keys = sorted(keys)
            deltapath = args.deltas
            if nick is not None:
                deltapath = deltapath.replace('.csv', '.{}.csv'.format(nick))
            with sopen(deltapath, 'wt') as fout:
                writer = csv.writer(fout)
                writer.writerow(['when'] + keys)
                for ct, d in self.deltas:
                    row = [time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ct))]
                    for k in keys:
                        row.append(d.get(k, None))
                    writer.writerow(row)
            logger.debug('wrote %r', deltapath)
        if reportpath:
            logger.debug('wrote %r', reportpath)
        return self

if __name__ == '__main__':
    sys.exit(main())
