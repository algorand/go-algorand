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
# Process /metrics data captured by heapWatch.py
#
# Generate text report on bandwidth in and out of relays/PN/NPN

import argparse
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

from metrics_lib import num, hunum, terraform_inventory_ip_not_names, \
    metric_line_re, test_metric_line_re

logger = logging.getLogger(__name__)

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
                key = m.group(1)
                val = m.group(2)
            else:
                ab = line.split()
                key = ab[0]
                val = ab[1]
            if key.endswith('{}'):
                key = key[:-2]
            out[key] = num(val)
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
        self.txP2PBpsMeanSum = 0
        self.rxP2PBpsMeanSum = 0
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
        self.txP2PBpsMeanSum += meanOrZero(ttr.txP2PBpsList)
        self.rxP2PBpsMeanSum += meanOrZero(ttr.rxP2PBpsList)
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
        txWsPSums = {}
        rxWsPSums = {}
        txP2PPSums = {}
        rxP2PPSums = {}
        secondsSum = 0
        txMax = {}
        txMin = {}
        rxMax = {}
        rxMin = {}
        nicks = []
        for nick, ns in self.nodes.items():
            nicks.append(nick)
            secondsSum += ns.secondsSum
            dictSum(txWsPSums, ns.txPSums)
            dictSum(rxWsPSums, ns.rxPSums)
            dictSum(txP2PPSums, ns.txP2PPSums)
            dictSum(rxP2PPSums, ns.rxP2PPSums)
            dictMax(txMax, ns.txPLists)
            dictMax(rxMax, ns.rxPLists)
            dictMin(txMin, ns.txPLists)
            dictMin(rxMin, ns.rxPLists)
        nodesummary = '{} nodes: {}'.format(len(nicks), nicks)
        lines = []
        if html:
            lines.append('<div>{}</div>'.format(nodesummary))
            lines.append('<table width="50%"><tr>')  # traffic per tag two columns: ws and p2p
        else:
            lines.append(nodesummary)

        for title, txPSums, rxPSums in [
            ('ws', txWsPSums, rxWsPSums),
            ('p2p', txP2PPSums, rxP2PPSums),
        ]:
            if html:
                lines.append('<td valign="top">')
                lines.append(f'<table width="100%"><caption>{title} traffic per tag</caption><tr><th></th><th>tx B/s</th><th>rx B/s</th></tr>')
            else:
                lines.append(f'{title} traffic per tag')
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
                lines.append('</td>')
        if html:
            lines.append('</tr></table>') # traffic per tag two columns: ws and p2p
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
            tps, txbps, rxbps, txP2Pbps, rxP2Pbps = math.nan, math.nan, math.nan, math.nan, math.nan
            blockTimes = math.nan
        else:
            #tps = self.tpsMeanSum/self.sumsCount
            tps = self.tpsSum/self.sumsCount
            blockTimes = self.blockTimeSum/self.sumsCount
            txbps = self.txBpsMeanSum/self.sumsCount
            rxbps = self.rxBpsMeanSum/self.sumsCount
            txP2Pbps = self.txP2PBpsMeanSum/self.sumsCount
            rxP2Pbps = self.rxP2PBpsMeanSum/self.sumsCount
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
            fmt = '{byMsg}\n{verifyMillis}<div>{labelspace}{txPool}</div>\n<div>{labelspace}summary: {TPS:0.2f} TPS, {bt:1.2f}s/block, tx {txBps}B/s, rx {rxBps}B/s, p2p tx {txP2PBps}B/s, p2p rx {rxP2PBps}B/s</div>'
            if self.label:
                fmt = '<div class="lh">' + self.label + '</div>' + fmt
        else:
            fmt = '{byMsg}\n{verifyMillis}{labelspace}{txPool}\n{labelspace}summary: {TPS:0.2f} TPS, {bt:1.2f}s/block, tx {txBps}B/s, rx {rxBps}B/s, p2p tx {txP2PBps}B/s, p2p rx {rxP2PBps}B/s'
        return fmt.format(labelspace=labelspace, byMsg=self.byMsg(html), txPool=self.txPool(), TPS=tps, txBps=hunum(txbps), rxBps=hunum(rxbps), txP2PBps=hunum(txP2Pbps), rxP2PBps=hunum(rxP2Pbps), bt=blockTimes, verifyMillis=verifyMillis)

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

    def heap_xy(self):
        # data from algod_go_memory_classes_heap_objects_bytes
        x = []
        y = []
        for nick, ns in self.nodes.items():
            if not ns.objectBytes:
                continue
            for curtime, nbytes in ns.objectBytes:
                x.append(curtime)
                y.append(nbytes)
        return x, y

    def plot_heaps(self, outpath):
        # data from algod_go_memory_classes_heap_objects_bytes
        from matplotlib import pyplot as plt
        x, y = self.heap_xy()
        if (not x) or (not y):
            return
        plt.scatter(x, y)
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

label_colors = {
    'relay': (1.0,0,0),
    'pn': (0,0,1.0),
    'npn': (.7,.7,0),
}

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
    ap.add_argument('--heap-plot-root', help='write to foo.svg and .png')
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
        ip_to_name = terraform_inventory_ip_not_names(tf_inventory_path)
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
        heaps_xy_color = []
        for lnre in args.nick_lre:
            label, nre = lnre.split(':', maxsplit=1)
            rsum = summary(label)
            process_nick_re(nre, filesByNick, nick_to_tfname, rsum, args, grsum)
            print(rsum)
            print('\n')
            if htmlout:
                htmlout.write(rsum.html())
            x, y = rsum.heap_xy()
            c = label_colors.get(label)
            heaps_xy_color.append((x, y, c))
        if args.heap_plot_root:
            from matplotlib import pyplot as plt
            for x,y,c in heaps_xy_color:
                plt.scatter(x, y, color=c)
                plt.savefig(args.heap_plot_root + '.svg', format='svg')
                plt.savefig(args.heap_plot_root + '.png', format='png')
        return 0
    elif args.heap_plot_root:
        grsum.plot_heaps(args.heap_plot_root)

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
        self.txP2PBpsList = []
        self.rxP2PBpsList = []
        self.tpsList = []
        self.txBSum = 0
        self.rxBSum = 0
        self.txP2PBSum = 0
        self.rxP2PBSum = 0
        self.txnSum = 0
        self.secondsSum = 0
        # algod_network_received_bytes_*
        self.rxPLists = {}
        self.rxPSums = {}
        # algod_network_p2p_received_bytes_*
        self.rxP2PPLists = {}
        self.rxP2PPSums = {}
        # algod_network_sent_bytes_*
        self.txPLists = {}
        self.txPSums = {}
        # algod_network_p2p_sent_bytes_*
        self.txP2PPLists = {}
        self.txP2PPSums = {}
        self.times = []
        # algod_tx_pool_count
        self.txPool = []
        # objectBytes = [(curtime, algod_go_memory_classes_heap_objects_bytes), ...]
        self.objectBytes = []
        # total across all measurements
        self.tps = 0
        self.blockTime = 0
        self.biByTime = {}
        # average milliseconds per agreement block verify
        self.verifyMillis = None

    def process_files(self, args, nick=None, metrics_files=None, bisource=None):
        "returns self, a nodestats object"
        if bisource is not None:
            logger.debug('process_files %r external bisource', nick)
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
            writer.writerow(('when', 'tx bytes/s', 'rx bytes/s', 'tx p2p bytes/s', 'rx p2p bytes/s', 'TPS', 's/block'))
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
                    logger.debug('bi r=%d %s', bi.get('block',{}).get('rnd', 0), bijsonpath)
            if bi is None:
                bi = bisource.get(curtime)
            if bi is None:
                logger.warning('%s no blockinfo', path)
            self.txPool.append(cur.get('algod_tx_pool_count'))
            objectBytes = cur.get('algod_go_memory_classes_heap_objects_bytes')
            if objectBytes:
                self.objectBytes.append((curtime, objectBytes))
            #logger.debug('%s: %r', path, cur)
            verifyGood = cur.get('algod_agreement_proposal_verify_good')
            verifyMs = cur.get('algod_agreement_proposal_verify_ms')
            if verifyGood and verifyMs:
                # last writer wins
                self.verifyMillis = verifyMs / verifyGood
            if prev is not None:
                d = metrics_delta(prev, cur)
                dt = curtime - prevtime
                #print("{} ->\n{}".format(prevPath, path))
                #print(json.dumps(d, indent=2, sort_keys=True))
                self.deltas.append((curtime, dt, d))
                tps = None
                blocktime = None
                txnCount = 0
                if bi and prevbi:
                    txnCount = (bi.get('block',{}).get('tc', 0) - prevbi.get('block',{}).get('tc', 0))
                    tps = txnCount / dt
                    rounds = (bi.get('block',{}).get('rnd', 0) - prevbi.get('block',{}).get('rnd', 0))
                    if rounds != 0:
                        blocktime = dt/rounds
                txBytes = d.get('algod_network_sent_bytes_total',0)
                rxBytes = d.get('algod_network_received_bytes_total',0)
                txBytesPerSec = txBytes / dt
                rxBytesPerSec = rxBytes / dt
                txP2PBytes = d.get('algod_network_p2p_sent_bytes_total',0)
                rxP2PBytes = d.get('algod_network_p2p_received_bytes_total',0)
                txP2PBytesPerSec = txP2PBytes / dt
                rxP2PBytesPerSec = rxP2PBytes / dt

                # TODO: gather algod_network_sent_bytes_* and algod_network_received_bytes_*
                if (tps is None) or ((args.mintps is not None) and (tps < args.mintps)):
                    # do not sum up this row
                    pass
                else:
                    self.txBpsList.append(txBytesPerSec)
                    self.rxBpsList.append(rxBytesPerSec)
                    self.txP2PBpsList.append(txP2PBytesPerSec)
                    self.rxP2PBpsList.append(rxP2PBytesPerSec)
                    self.tpsList.append(tps)
                    self.txBSum += txBytes
                    self.rxBSum += rxBytes
                    self.txP2PBSum += txP2PBytes
                    self.rxP2PBSum += rxP2PBytes
                    self.txnSum += txnCount
                    self.secondsSum += dt
                    perProtocol('algod_network_sent_bytes_', self.txPLists, self.txPSums, d, dt)
                    perProtocol('algod_network_received_bytes_', self.rxPLists, self.rxPSums, d, dt)
                    perProtocol('algod_network_p2p_sent_bytes_', self.txP2PPLists, self.txP2PPSums, d, dt)
                    perProtocol('algod_network_p2p_received_bytes_', self.rxP2PPLists, self.rxP2PPSums, d, dt)
                if writer:
                    writer.writerow((
                        time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(curtime)),
                        txBytesPerSec,
                        rxBytesPerSec,
                        txP2PBytesPerSec,
                        rxP2PBytesPerSec,
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
        if prevbi is firstBi:
            logger.warning('only one blockinfo for %s', nick)
            return self
        txnCount = prevbi.get('block',{}).get('tc',0) - firstBi.get('block',{}).get('tc',0)
        rounds = prevbi.get('block',{}).get('rnd',0) - firstBi.get('block',{}).get('rnd',0)
        if rounds == 0:
            logger.warning('no rounds for %s', nick)
            return self
        totalDt = prevtime - firstTime
        self.tps = txnCount / totalDt
        self.blockTime = totalDt / rounds
        if writer and self.txBpsList:
            writer.writerow([])
            # TODO: summarize
            # for bsum, msg in sorted([(bsum,msg) for msg,bsum in self.txPSums.items()]):
            #     pass
            writer.writerow([])
            writer.writerow(['min', min(self.txBpsList), min(self.rxBpsList), min(self.txP2PBpsList), min(self.rxP2PBpsList), min(self.tpsList)])
            writer.writerow(['avg', self.txBSum/self.secondsSum, self.rxBSum/self.secondsSum, self.txP2PBSum/self.secondsSum, self.rxP2PBSum/self.secondsSum, self.txnSum/self.secondsSum])
            writer.writerow(['max', max(self.txBpsList), max(self.rxBpsList), max(self.txP2PBpsList), max(self.rxP2PBpsList), max(self.tpsList)])
            writer.writerow(['std', statistics.pstdev(self.txBpsList), statistics.pstdev(self.rxBpsList), statistics.pstdev(self.txP2PBpsList), statistics.pstdev(self.rxP2PBpsList), statistics.pstdev(self.tpsList)])
        if reportf:
            reportf.close()
        if self.deltas and args.deltas:
            keys = set()
            for ct, dt, d in self.deltas:
                keys.update(set(d.keys()))
            keys = sorted(keys)
            deltapath = args.deltas
            if nick is not None:
                deltapath = deltapath.replace('.csv', '.{}.csv'.format(nick))
            with sopen(deltapath, 'wt') as fout:
                writer = csv.writer(fout)
                writer.writerow(['when', 'dt'] + keys)
                for ct, d in self.deltas:
                    row = [time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ct)), dt]
                    for k in keys:
                        row.append(d.get(k, None))
                    writer.writerow(row)
            logger.debug('wrote %r', deltapath)
        if reportpath:
            logger.debug('wrote %r', reportpath)
        return self

if __name__ == '__main__':
    sys.exit(main())
