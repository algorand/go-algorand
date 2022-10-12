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
# Process /metrics data captured by heapWatch.py
#
# Generate text report on bandwidth in and out of relays/PN/NPN

import argparse
import configparser
import contextlib
import csv
import glob
import gzip
import logging
import json
import math
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

def hunum(x):
    if x >= 10000000000:
        return '{:.1f}G'.format(x / 1000000000.0)
    if x >= 1000000000:
        return '{:.2f}G'.format(x / 1000000000.0)
    if x >= 10000000:
        return '{:.1f}M'.format(x / 1000000.0)
    if x >= 1000000:
        return '{:.2f}M'.format(x / 1000000.0)
    if x >= 10000:
        return '{:.1f}k'.format(x / 1000.0)
    if x >= 1000:
        return '{:.2f}k'.format(x / 1000.0)
    return '{:.2f}x'.format(x)

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
    try:
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
    except:
        print(f'An exception occurred in parse_metrics: {sys.exc_info()}')
        pass
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

def meanOrZero(seq):
    if not seq:
        return 0
    return statistics.mean(seq)

class summary:
    def __init__(self, label=None):
        self.label = label or ""
        self.tpsMeanSum = 0
        self.txBpsMeanSum = 0
        self.rxBpsMeanSum = 0
        self.tpsSum = 0
        self.blockTimeSum = 0
        self.sumsCount = 0
        self.nodes = {}
        self.biByTime = {}
        self.verifyMillis = []

    def __call__(self, ttr, nick):
        if not ttr:
            logger.debug('no summary for %s', nick)
            return
        self.nodes[nick] = ttr
        logger.debug('%d points from %s', len(ttr.tpsList), nick)
        self.tpsMeanSum += meanOrZero(ttr.tpsList)
        self.txBpsMeanSum += meanOrZero(ttr.txBpsList)
        self.rxBpsMeanSum += meanOrZero(ttr.rxBpsList)
        self.tpsSum += ttr.tps
        self.blockTimeSum += ttr.blockTime
        self.sumsCount += 1
        if ttr.biByTime:
            self.biByTime.update(ttr.biByTime)
        if ttr.verifyMillis:
            self.verifyMillis.append(ttr.verifyMillis)

    def blockinfo(self, curtime):
        return self.biByTime.get(curtime)

    def byMsg(self, html=False):
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
        nodesummary = '{} nodes: {}'.format(len(nicks), nicks)
        lines = []
        if html:
            lines.append('<div>{}</div>'.format(nodesummary))
            lines.append('<table><tr><th></th><th>tx B/s</th><th>rx B/s</th></tr>')
        else:
            lines.append(nodesummary)
            lines.append('\ttx B/s\trx B/s')
        for msg, txB in txPSums.items():
            if msg not in rxPSums:
                rxPSums[msg] = 0
        for rxBps, msg in sorted([(rxB/secondsSum, msg) for msg, rxB in rxPSums.items()], reverse=True):
            txBps = txPSums.get(msg,0)/secondsSum
            if (txBps < 0.5) and (rxBps < 0.5):
                continue
            if html:
                lines.append('<tr><td>{}</td><td>{:.0f}</td><td>{:.0f}</td></tr>'.format(msg, txBps, rxBps))
            else:
                lines.append('{}\t{:.0f}\t{:.0f}'.format(msg, txBps, rxBps))
        if html:
            lines.append('</table>')
        return '\n'.join(lines)

    def txPool(self):
        mins = []
        maxs = []
        means = []
        for nick, ns in self.nodes.items():
            if len(ns.txPool) < 2:
                continue
            # skip the first two while the system could still count as warming up
            txp = ns.txPool[2:]
            mins.append(min(txp))
            maxs.append(max(txp))
            means.append(statistics.mean(txp))
        if not means or not maxs or not mins:
            return 'txnpool(no stats)'
        return 'txnpool({:.0f} {:.0f} {:.0f} {:.0f} {:.0f})'.format(
            min(mins), min(means), statistics.mean(means), max(means), max(maxs)
        )

    def __str__(self):
        return self.str(html=False)

    def html(self):
        return self.str(html=True)

    def str(self, html=False):
        if not self.sumsCount:
            tps, txbps, rxbps = math.nan, math.nan, math.nan
            blockTimes = math.nan
        else:
            #tps = self.tpsMeanSum/self.sumsCount
            tps = self.tpsSum/self.sumsCount
            blockTimes = self.blockTimeSum/self.sumsCount
            txbps = self.txBpsMeanSum/self.sumsCount
            rxbps = self.rxBpsMeanSum/self.sumsCount
        labelspace = ""
        if self.label:
            labelspace = self.label + " "
        if self.verifyMillis:
            verifyMillis = labelspace + 'verify ms ({:.0f}/{:.0f}/{:.0f})\n'.format(min(self.verifyMillis), meanOrZero(self.verifyMillis), max(self.verifyMillis))
            if html:
                verifyMillis = '<div>' + verifyMillis + '</div>'
        else:
            verifyMillis = ''
        if html:
            fmt = '{byMsg}\n{verifyMillis}<div>{labelspace}{txPool}</div>\n<div>{labelspace}summary: {TPS:0.2f} TPS, {bt:1.2f}s/block, tx {txBps}B/s, rx {rxBps}B/s</div>'
            if self.label:
                fmt = '<div class="lh">' + self.label + '</div>' + fmt
        else:
            fmt = '{byMsg}\n{verifyMillis}{labelspace}{txPool}\n{labelspace}summary: {TPS:0.2f} TPS, {bt:1.2f}s/block, tx {txBps}B/s, rx {rxBps}B/s'
        return fmt.format(labelspace=labelspace, byMsg=self.byMsg(html), txPool=self.txPool(), TPS=tps, txBps=hunum(txbps), rxBps=hunum(rxbps), bt=blockTimes, verifyMillis=verifyMillis)

    def plot_pool(self, outpath):
        from matplotlib import pyplot as plt
        any = False
        for nick, ns in self.nodes.items():
            if not ns.txPool:
                continue
            any = True
            plt.plot(ns.times, ns.txPool, label=nick)
            csvoutpath = outpath + nick + '.csv'
            with open(csvoutpath, 'w') as fout:
                writer = csv.writer(fout)
                writer.writerow(['time', 'pool'])
                for t, p in zip(ns.times, ns.txPool):
                    writer.writerow([t,p])
        if not any:
            logger.error('no txPool in {}'.format(list(self.nodes.keys())))
            return
        plt.legend(loc='upper right')
        plt.savefig(outpath + '.svg', format='svg')
        plt.savefig(outpath + '.png', format='png')

def anynickre(nick_re, nicks):
    if not nick_re:
        return True
    for nre in nick_re:
        p = re.compile(nre)
        for nick in nicks:
            if p.match(nick):
                return True
    return False

def gather_metrics_files_by_nick(metrics_files, metrics_dirs=None):
    '''return {"node nickname":[path, path, ...], ...}'''
    metrics_fname_re = re.compile(r'(.*?)\.([0-9_]+\.?\d+)\.metrics')
    filesByNick = {}
    nonick = []
    tf_inventory_path = None
    for path in metrics_files:
        fname = os.path.basename(path)
        if fname == 'terraform-inventory.host':
            tf_inventory_path = path
            continue
        if metrics_dirs is not None:
            metrics_dirs.add(os.path.dirname(path))
        m = metrics_fname_re.match(fname)
        if not m:
            logger.error('could not parse metrics file name %r', fname)
            nonick.append(path)
            continue
        nick = m.group(1)
        dapp(filesByNick, nick, path)
    return tf_inventory_path, filesByNick, nonick

def process_nick_re(nre, filesByNick, nick_to_tfname, rsum, args, grsum):
    nretup = (nre,)
    for rnick, paths in filesByNick.items():
        nick = nick_to_tfname.get(rnick, rnick)
        if anynickre(nretup, (rnick,nick)):
            rsum(process_files(args, nick, paths, grsum), nick)

def main():
    os.environ['TZ'] = 'UTC'
    time.tzset()
    test_metric_line_re()
    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_files', nargs='*')
    ap.add_argument('-d', '--dir', default=None, help='dir path to find /*.metrics in')
    ap.add_argument('--mintps', default=None, type=float, help="records below min TPS don't add into summary")
    ap.add_argument('--deltas', default=None, help='path to write csv deltas')
    ap.add_argument('--report', default=None, help='path to write csv report')
    ap.add_argument('--html-summary', default=None, help='path to write html summary')
    ap.add_argument('--nick-re', action='append', default=[], help='regexp to filter node names, may be repeated')
    ap.add_argument('--nick-lre', action='append', default=[], help='label:regexp to filter node names, may be repeated')
    ap.add_argument('--pool-plot-root', help='write to foo.svg and .png')
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
    tf_inventory_path, filesByNick, nonick = gather_metrics_files_by_nick(metrics_files, metrics_dirs)
    logger.debug('%d files gathered into %d nicks', len(metrics_files), len(filesByNick))
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
        unfound = []
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
                unfound.append((ip,name))
        if not nick_to_tfname:
            for ip,name in unfound:
                logger.warning('ip %s (%s) no nick', ip, name)
        #logger.debug('nick_to_tfname %r', nick_to_tfname)
    logger.debug('nicks: %s', ' '.join(map(lambda x: nick_to_tfname.get(x,x), filesByNick.keys())))

    # global stats across all nodes
    grsum = summary()
    if nonick:
        grsum(process_files(args, None, nonick), 'no nick')
    for rnick, paths in filesByNick.items():
        nick = nick_to_tfname.get(rnick, rnick)
        logger.debug('%s: %d files', nick, len(paths))
        grsum(process_files(args, nick, paths), nick)
    if args.pool_plot_root:
        grsum.plot_pool(args.pool_plot_root)

    htmlout = None
    if args.html_summary:
        htmlout = open(args.html_summary, 'wt')
    # maybe subprocess for stats across named groups
    if args.nick_re:
        # use each --nick-re=foo as a group
        for nre in args.nick_re:
            rsum = summary()
            process_nick_re(nre, filesByNick, nick_to_tfname, rsum, args, grsum)
            print(rsum)
            print('\n')
            if htmlout:
                htmlout.write(rsum.html())
        return 0
    if args.nick_lre:
        for lnre in args.nick_lre:
            label, nre = lnre.split(':', maxsplit=1)
            rsum = summary(label)
            process_nick_re(nre, filesByNick, nick_to_tfname, rsum, args, grsum)
            print(rsum)
            print('\n')
            if htmlout:
                htmlout.write(rsum.html())
        return 0

    # no filters, print global result
    print(grsum)
    if htmlout:
        htmlout.write(grsum.html())
    return 0

def perProtocol(prefix, lists, sums, deltas, dt):
    lp = len(prefix)
    for k, v in deltas.items():
        if k.startswith(prefix):
            sub = k[lp:]
            dapp(lists, sub, v/dt)
            sums[sub] = sums.get(sub,0) + v

def process_files(args, nick, paths, grsum=None):
    "returns a nodestats object"
    return nodestats().process_files(args, nick, paths, grsum and grsum.biByTime)

path_time_re = re.compile(r'(\d\d\d\d)(\d\d)(\d\d)_(\d\d)(\d\d)(\d\d\.+\d+)')

def parse_path_time(path):
    m = path_time_re.search(path)
    if not m:
        return None
    ts = float(m.group(6))
    si = math.floor(ts)
    t = time.mktime((int(m.group(1)), int(m.group(2)), int(m.group(3)),
                     int(m.group(4)), int(m.group(5)), si, 0, 0, 0))
    t += ts - si
    return t

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
        self.times = []
        # algod_tx_pool_count{}
        self.txPool = []
        # total across all measurements
        self.tps = 0
        self.blockTime = 0
        self.biByTime = {}
        # average milliseconds per agreement block verify
        self.verifyMillis = None

    def process_files(self, args, nick=None, metrics_files=None, bisource=None):
        "returns self, a nodestats object"
        if bisource is None:
            bisource = {}
        self.args = args
        self.nick = nick
        if metrics_files is None:
            logger.debug('nodestats(%s) no metrics files', nick)
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
        firstTime = None
        firstBi = None

        for path in sorted(metrics_files):
            curtime = parse_path_time(path) or os.path.getmtime(path)
            self.times.append(curtime)
            with open(path, 'rt', encoding="utf-8") as fin:
                cur = parse_metrics(fin)
            # TODO: use _any_ node's blockinfo json
            bijsonpath = path.replace('.metrics', '.blockinfo.json')
            bi = None
            if os.path.exists(bijsonpath):
                with open(bijsonpath, 'rt', encoding="utf-8") as fin:
                    bi = json.load(fin)
                    self.biByTime[curtime] = bi
            if bi is None:
                bi = bisource.get(curtime)
            if bi is None:
                logger.warning('%s no blockinfo', path)
            self.txPool.append(cur.get('algod_tx_pool_count{}'))
            #logger.debug('%s: %r', path, cur)
            verifyGood = cur.get('algod_agreement_proposal_verify_good{}')
            verifyMs = cur.get('algod_agreement_proposal_verify_ms{}')
            if verifyGood and verifyMs:
                # last writer wins
                self.verifyMillis = verifyMs / verifyGood
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
            else:
                firstTime = curtime
                firstBi = bi
            prev = cur
            prevPath = path
            prevtime = curtime
            prevbi = bi
        if prevbi is None or firstBi is None:
            return self
        txnCount = prevbi.get('block',{}).get('tc',0) - firstBi.get('block',{}).get('tc',0)
        rounds = prevbi.get('block',{}).get('rnd',0) - firstBi.get('block',{}).get('rnd',0)
        totalDt = prevtime - firstTime
        self.tps = txnCount / totalDt
        self.blockTime = totalDt / rounds
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
