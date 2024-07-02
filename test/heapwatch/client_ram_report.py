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
# Process heap profiles (*.heap) collected from heapWatch.py
# Create a report on `algod` RAM usage

import argparse
import configparser
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

# d = {k: {t: v},...}
def dapp(d, k, t, v):
    l = d.get(k)
    if l is None:
        d[k] = {t: v}
    else:
        l[t] = v

# d = {k: {t: {m: v},...},...}
def dapp_metric(d, k, t, m, v):
    l = d.get(k)
    if l is None:
        d[k] = {t: {m: v}}
    else:
        l2 = l.get(t)
        if l2 is None:
            l[t] = {m: v}
        else:
            l2[m] = v

def get_heap_inuse_totals(dirpath):
    '''return {"node nickname": {"YYYYmmdd_HHMMSS": bytes}, ...}'''
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
        dapp(bynick, nick, timestamp, bytesinuse)
        logger.debug('%s ok, %s %f', path, timestamp, bytesinuse)

    logger.debug('%d skipped older than cache', skipcount)
    for nick, recs in bynick.items():
        old = cached.get(nick)
        if old is None:
            cached[nick] = recs
        else:
            cached[nick].update(recs)
    if cached and bynick:
        with open(cache_path, 'wt') as fout:
            json.dump(cached, fout)
    return cached

def get_heap_metrics(dirpath):
    '''return {"node nickname": {"YYYYmmdd_HHMMSS": {"metric": value}, ...}, ...}'''
    metrics_name_re = re.compile(r'(.*)\.(.*).metrics')
    bynick = {}
    for path in glob.glob(os.path.join(dirpath, '*.*.metrics')):
        fname = os.path.basename(path)
        m = metrics_name_re.match(fname)
        if not m:
            logger.warning('could not parse heap filename: %r', path)
            continue
        nick = m.group(1)
        timestamp = m.group(2)
        with open(path, 'rt') as fin:
            for line in fin.readlines():
                if line.startswith('#'):
                    continue
                elif line.startswith('algod_go_memory_classes_heap_objects_bytes'):
                    inuse = float(line.split()[1])
                    dapp_metric(bynick, nick, timestamp, 'inuse', inuse)
                elif line.startswith('algod_go_memory_classes_total_bytes'):
                    total = float(line.split()[1])
                    dapp_metric(bynick, nick, timestamp, 'total', total)
                elif line.startswith('algod_go_memory_classes_heap_free_bytes'):
                    free = float(line.split()[1])
                    dapp_metric(bynick, nick, timestamp, 'free', free)
                elif line.startswith('algod_go_memory_classes_heap_released_bytes'):
                    released = float(line.split()[1])
                    dapp_metric(bynick, nick, timestamp, 'released', released)
    return bynick

def maybe_load_tf_nicks(args):
    tf_inventory_path = os.path.join(args.dir, 'terraform-inventory.host')
    if not os.path.exists(tf_inventory_path):
        return None
    tf_inventory = configparser.ConfigParser(allow_no_value=True)
    tf_inventory.read(tf_inventory_path)
    ip_to_name = {}
    for k, sub in tf_inventory.items():
        if k.startswith('name_'):
            nick = k[5:]
            for ip in sub:
                if ip in ip_to_name:
                    logger.warning('ip %r already named %r, also got %r', ip, ip_to_name[ip], k)
                ip_to_name[ip] = nick
    return ip_to_name


def hostports_to_nicks(args, hostports, metrics=None):
    ip_to_nick = maybe_load_tf_nicks(args)
    if not ip_to_nick:
        if metrics:
            return ['{}#{}'.format(hp, m) for hp in hostports for m in metrics]
        return hostports
    out = []
    for hp in hostports:
        hit = None
        for ip, nick in ip_to_nick.items():
            if ip in hp:
                if hit is None:
                    hit = nick
                else:
                    logger.warning('nick collision in ip=%r, hit=%r nick=%r', ip, hit, nick)
                    hit = nick
        if not hit:
            hit = hp
        out.append(hit)
    out.sort()
    if metrics:
        return ['{}#{}'.format(hp, m) for hp in out for m in metrics]
    return out


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
    heap_details = get_heap_metrics(args.dir)

    if not heap_totals and not heap_details:
        print('no data found', file=sys.stderr)
        return 0

    if args.csv:
        if args.csv == '-':
            csvf = sys.stdout
        else:
            csvf = open(args.csv, 'wt')
        writer = csv.writer(csvf)
        whens = set()
        col_names_target = heap_totals if heap_totals else heap_details
        for nick, recs in col_names_target.items():
            # {k: {t: v}}
            for ts in recs.keys():
                whens.add(ts)
        whens = sorted(whens)
        nodes = sorted(col_names_target.keys())
        metrics = list(heap_details[nodes[0]].values())[0]
        writer.writerow(
            ['when','dt','round'] +
            hostports_to_nicks(args, nodes, metrics=['pprof_inuse_space'] + list(metrics.keys()))
        )
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
                rnd = '0'
            row = [ts, tv-first, rnd]
            for nick in nodes:
                # {k: {t: v}}
                val = heap_totals.get(nick, {}).get(ts)
                row.append(val if val else 0)
                vals = heap_details[nick].get(ts)
                # {k: {t: {m: v}}}
                if vals:
                    row.extend(vals.values())
            writer.writerow(row)

    return 0

if __name__ == '__main__':
    sys.exit(main())
