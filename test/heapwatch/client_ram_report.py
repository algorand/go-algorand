#!/usr/bin/env python3

import argparse
import csv
import glob
import json
import logging
import os
import re
import sys
import subprocess
import time

logger = logging.getLogger(__name__)

# go tool pprof -sample_index=inuse_space -text Primary.20210708_131740.heap|grep ^Showing.\*total\$
# Showing nodes accounting for 82.08MB, 100% of 82.08MB total

total_inuse_re = re.compile(r'Showing nodes accounting for [^,]+, .* of ([0-9.]+)([kKmMgGtT]?B) total', re.MULTILINE)

multipliers = {
    'B': 1,
    'KB': 1024,
    'MB': 1024*1024,
    'GB': 1024*1024*1024,
    'TB': 1024*1024*1024*1024,
}

# d = {k:[v,...]}
def dapp(d, k, v):
    l = d.get(k)
    if l is None:
        d[k] = [v]
    else:
        l.append(v)

def get_heap_inuse_totals(dirpath):
    '''return {"node nickname":[(YYYYmmdd_HHMMSS, bytes), ...], ...}'''
    cache_mtime = 0
    cache_path = os.path.join(dirpath, 'heap_inuse_totals.json')
    if os.path.exists(cache_path):
        cache_mtime = os.path.getmtime(cache_path)
        with open(cache_path, 'rb') as fin:
            cached = json.load(fin)
    else:
        cached = {}

    heap_name_re = re.compile(r'(.*)\.(.*).heap')
    bynick = {}
    skipcount = 0
    for path in glob.glob(os.path.join(dirpath, '*.*.heap')):
        if os.path.getmtime(path) < cache_mtime:
            skipcount += 1
            continue
        fname = os.path.basename(path)
        m = heap_name_re.match(fname)
        if not m:
            logger.warning('could not parse heap filename: %r', path)
            continue
        nick = m.group(1)
        timestamp = m.group(2)
        cmd = ['go', 'tool', 'pprof', '-sample_index=inuse_space', '-text', path]
        result = subprocess.run(cmd, capture_output=True)
        text = result.stdout.decode()
        m = total_inuse_re.search(text)
        if not m:
            logger.error('could not find total in output: %s', text)
            raise Exception('could not find total in output of: %s', ' '.join([repr(x) for x in cmd]))
        bytesinuse = float(m.group(1)) * multipliers[m.group(2).upper()]
        dapp(bynick, nick, (timestamp, bytesinuse))
        logger.debug('%s ok, %s %f', path, timestamp, bytesinuse)

    logger.debug('%d skipped older than cache', skipcount)
    for nick, recs in bynick.items():
        old = cached.get(nick)
        if old is None:
            cached[nick] = sorted(recs)
        else:
            cached[nick] = sorted(old + recs)
    if cached and bynick:
        with open(cache_path, 'wt') as fout:
            json.dump(cached, fout)
    return cached


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', required=True, help='dir path to find /*.metrics in')
    ap.add_argument('--csv')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    heap_totals = get_heap_inuse_totals(args.dir)

    if args.csv:
        if args.csv == '-':
            csvf = sys.stdout
        else:
            csvf = open(args.csv, 'wt')
        writer = csv.writer(csvf)
        whens = set()
        for nick, recs in heap_totals.items():
            for ts, n in recs:
                whens.add(ts)
        whens = sorted(whens)
        nodes = sorted(heap_totals.keys())
        writer.writerow(['when','dt','round'] + nodes)
        first = None
        for ts in whens:
            tv = time.mktime(time.strptime(ts, '%Y%m%d_%H%M%S'))
            if first is None:
                first = tv
            nick = nodes[0]
            bipath = os.path.join(args.dir, '{}.{}.blockinfo.json'.format(nick, ts))
            try:
                bi = json.load(open(bipath))
                rnd = str(bi['block']['rnd'])
            except:
                rnd = ''
            row = [ts, tv-first, rnd]
            for nick in nodes:
                for rec in heap_totals[nick]:
                    if rec[0] == ts:
                        row.append(rec[1])
                        break
            writer.writerow(row)

    return 0

if __name__ == '__main__':
    sys.exit(main())
