#!/usr/bin/python3
#
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
# repeatedly snapshot metrics & profiles for one or more algod
#
# usage:
# mkdir -p /tmp/heaps
# python3 test/scripts/heapWatch.py -o /tmp/heaps --period 60s private_network_root/*

import argparse
import base64
import configparser
import fnmatch
import json
import logging
import math
import os
import queue
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

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

# data from /debug/pprof/* is already gzipped

# curl -o /tmp/algod.pprof.heap "http://`cat ${ALGORAND_DATA}/algod.net`/urlAuth/`cat ${ALGORAND_DATA}/algod.admin.token`/debug/pprof/heap"
# both reports can be generated from one heap profile snapshot
# go tool pprof -sample_index=inuse_space -svg -output /tmp/algod.heap.svg /tmp/algod.pprof.heap
# go tool pprof -sample_index=alloc_space -svg -output /tmp/algod.alloc.svg /tmp/algod.pprof.heap

## curl -o /tmp/algod.pprof.allocs "http://`cat ${ALGORAND_DATA}/algod.net`/urlAuth/`cat ${ALGORAND_DATA}/algod.admin.token`/debug/pprof/allocs"
# go tool pprof -svg -output /tmp/algod.allocs.svg /tmp/algod.pprof.allocs

# http://localhost:6060/debug/pprof/allocs?debug=1

# -inuse_space           Same as -sample_index=inuse_space
# -inuse_objects         Same as -sample_index=inuse_objects
# -alloc_space           Same as -sample_index=alloc_space
# -alloc_objects         Same as -sample_index=alloc_objects

graceful_stop = False

def do_graceful_stop(signum, frame):
    global graceful_stop
    if graceful_stop:
        sys.stderr.write("second signal, quitting\n")
        sys.exit(1)
    sys.stderr.write("graceful stop...\n")
    graceful_stop = True

signal.signal(signal.SIGTERM, do_graceful_stop)
signal.signal(signal.SIGINT, do_graceful_stop)

def jsonable(ob):
    if isinstance(ob, bytes):
        return base64.b64encode(ob).decode()
    if isinstance(ob, list):
        return [jsonable(x) for x in ob]
    if isinstance(ob, dict):
        return {jsonable(k):jsonable(v) for k,v in ob.items()}
    return ob

def nmax(a,b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a,b)

class algodDir:
    def __init__(self, path, net=None, token=None, admin_token=None):
        self.path = path
        self.isdir = os.path.isdir(path)
        self.nick = os.path.basename(self.path)
        if net is None:
            net, token, admin_token = read_algod_dir(self.path)
        self.net = net
        self.token = token
        self.admin_token = admin_token
        self.headers = {}
        self._pid = None
        self._algod = None
        self.timeout = 15

    def __repr__(self):
        return '<algodDir {}>'.format(self.path)

    def pid(self):
        if self._pid is None:
            if not self.isdir:
                return None
            with open(os.path.join(self.path, 'algod.pid')) as fin:
                self._pid = int(fin.read())
        return self._pid

    def algod(self):
        if self._algod is None:
            net = self.net
            if not net.startswith('http'):
                net = 'http://' + net
            self._algod = algosdk.v2client.algod.AlgodClient(self.token, net, self.headers)
        return self._algod

    def get_pprof_snapshot(self, name, snapshot_name=None, outdir=None, timeout=None):
        if timeout is None:
            timeout = self.timeout
        url = 'http://' + self.net + '/urlAuth/' + self.admin_token + '/debug/pprof/' + name
        try:
            response = urllib.request.urlopen(urllib.request.Request(url, headers=self.headers), timeout=timeout)
        except Exception as e:
            logger.error('could not fetch %s from %s via %r (%s)', name, self.path, url, e)
            return
        if response.code != 200:
            logger.error('could not fetch %s from %s via %r (%r)', name, self.path, url, response.code)
            return
        blob = response.read()
        if snapshot_name is None:
            snapshot_name = time.strftime('%Y%m%d_%H%M%S', time.gmtime())
        outpath = os.path.join(outdir or '.', self.nick + '.' + snapshot_name + '.' + name)
        with open(outpath, 'wb') as fout:
            fout.write(blob)
        logger.debug('%s -> %s', self.nick, outpath)
        return outpath

    def get_debug_settings_pprof(self):
        timeout = self.timeout
        url = 'http://' + self.net + '/debug/settings/pprof'
        headers = self.headers.copy()
        headers['X-Algo-API-Token'] = self.admin_token
        try:
            response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout)
        except Exception as e:
            logger.error('could not fetch %s from %s via %r (%s)', '/debug/settings/pprof', self.path, url, e)
            return
        blob = response.read()
        return json.loads(blob)

    def set_debug_settings_pprof(self, settings):
        timeout = self.timeout
        url = 'http://' + self.net + '/debug/settings/pprof'
        headers = self.headers.copy()
        headers['X-Algo-API-Token'] = self.admin_token
        data = json.dumps(settings).encode()
        try:
            response = urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method='PUT'), timeout=timeout)
        except Exception as e:
            logger.error('could not put %s to %s via %r (%s)', settings, self.path, url, e)
            return
        response.close()

    def get_heap_snapshot(self, snapshot_name=None, outdir=None):
        return self.get_pprof_snapshot('heap', snapshot_name, outdir)

    def get_goroutine_snapshot(self, snapshot_name=None, outdir=None):
        return self.get_pprof_snapshot('goroutine', snapshot_name, outdir)

    def get_mutex_snapshot(self, snapshot_name=None, outdir=None):
        return self.get_pprof_snapshot('mutex', snapshot_name, outdir)

    def get_block_snapshot(self, snapshot_name=None, outdir=None):
        return self.get_pprof_snapshot('block', snapshot_name, outdir)

    def get_cpu_profile(self, snapshot_name=None, outdir=None, seconds=90):
        seconds = int(seconds)
        return self.get_pprof_snapshot('profile?seconds={}'.format(seconds), snapshot_name, outdir, timeout=seconds+20)

    def get_metrics(self, snapshot_name=None, outdir=None, timeout=None):
        url = 'http://' + self.net + '/metrics'
        if timeout is None:
            timeout = self.timeout
        try:
            response = urllib.request.urlopen(urllib.request.Request(url, headers=self.headers), timeout=timeout)
            if response.code != 200:
                logger.error('could not fetch %s from %s via %r', snapshot_name, self.path. url)
                return
            blob = response.read()
        except Exception as e:
            logger.error('could not fetch %s from %s via %r: %s', snapshot_name, self.path, url, e)
            return
        outpath = os.path.join(outdir or '.', self.nick + '.' + snapshot_name + '.metrics')
        with open(outpath, 'wb') as fout:
            fout.write(blob)
        logger.debug('%s -> %s', self.nick, outpath)

    def go_metrics(self, snapshot_name=None, outdir=None):
        t = threading.Thread(target=self.get_metrics, args=(snapshot_name, outdir))
        t.start()
        return t

    def get_blockinfo(self, snapshot_name=None, outdir=None):
        try:
            algod = self.algod()
            status = algod.status()
        except Exception as e:
            logger.error('could not get blockinfo from %s: %s', self.net, e)
            self._algod = None
            return
        bi = msgpack.loads(algod.block_info(status['last-round'], response_format='msgpack'), strict_map_key=False)
        if snapshot_name is None:
            snapshot_name = time.strftime('%Y%m%d_%H%M%S', time.gmtime())
        outpath = os.path.join(outdir or '.', self.nick + '.' + snapshot_name + '.blockinfo.json')
        bi['block'].pop('txns', None)
        bi['block'].pop('cert', None)
        with open(outpath, 'wt') as fout:
            json.dump(jsonable(bi), fout)
        return bi

    def _get_blockinfo_q(self, snapshot_name=None, outdir=None, biqueue=None):
        bi = self.get_blockinfo(snapshot_name, outdir)
        if biqueue and bi:
            biqueue.put(bi)

    def go_blockinfo(self, snapshot_name=None, outdir=None, biqueue=None):
        t = threading.Thread(target=self._get_blockinfo_q, args=(snapshot_name, outdir, biqueue))
        t.start()
        return t

    def psHeap(self):
        if not self.isdir:
            return None, None
        # return rss, vsz (in kilobytes)
        # ps -o rss,vsz $(cat ${ALGORAND_DATA}/algod.pid)
        subp = subprocess.Popen(['ps', '-o', 'rss,vsz', str(self.pid())], stdout=subprocess.PIPE)
        try:
            outs, errs = subp.communicate(timeout=2)
            for line in outs.decode().splitlines():
                try:
                    rss,vsz = [int(x) for x in line.strip().split()]
                    return rss,vsz
                except:
                    pass
        except:
            return None, None

class maxrnd:
    def __init__(self, biqueue):
        self.biqueue = biqueue
        self.maxrnd = None

    def _run(self):
        while True:
            bi = self.biqueue.get()
            if 'block' not in bi:
                return
            rnd = bi['block'].get('rnd',0)
            if (self.maxrnd is None) or (rnd > self.maxrnd):
                self.maxrnd = rnd
    def start(self):
        t = threading.Thread(target=self._run)
        t.start()
        return t

class watcher:
    def __init__(self, args):
        self.args = args
        self.prevsnapshots = {}
        self.they = []
        self.netseen = set()
        self.latest_round = None
        self.rounds_seen = set()
        self.bi_hosts = []
        self.netToAd = {}
        os.makedirs(self.args.out, exist_ok=True)
        if not args.data_dirs and os.path.exists(args.tf_inventory):
            cp = configparser.ConfigParser(allow_no_value=True)
            cp.read(args.tf_inventory)
            shutil.copy2(args.tf_inventory, self.args.out)
            for role in args.tf_roles.split(','):
                role_name = 'role_' + role
                if role_name not in cp:
                    continue
                for net in cp[role_name].keys():
                    logger.debug('addnet role %s %s', role, net)
                    self._addnet(net)
            for nre in args.tf_name_re:
                namere = re.compile(nre)
                for k,v in cp.items():
                    if not namere.match(k):
                        continue
                    for net in v.keys():
                        logger.debug('addnet re %s %s', nre, net)
                        self._addnet(net)
            if args.tf_bi_re:
                namere = re.compile(args.tf_bi_re)
                for k,v in cp.items():
                    if not namere.match(k):
                        continue
                    for net in v.keys():
                        logger.debug('bi net %s %s', nre, net)
                        ad = self.netToAd.get(net)
                        if not ad:
                            self._addnet(net)
                            ad = self.netToAd.get(net)
                        if ad:
                            self.bi_hosts.append(ad)
        for path in args.data_dirs:
            if not os.path.isdir(path):
                continue
            if os.path.exists(os.path.join(path, 'algod.net')):
                try:
                    ad = algodDir(path)
                    self.they.append(ad)
                except:
                    logger.error('bad algod: %r', path, exc_info=True)
            else:
                logger.debug('not a datadir: %r', path)
        logger.debug('data dirs: %r', self.they)

    def _addnet(self, net):
        if net in self.netseen:
            return
        self.netseen.add(net)
        net = net + ':' + self.args.port
        try:
            ad = algodDir(net, net=net, token=self.args.token, admin_token=self.args.admin_token)
            self.they.append(ad)
            self.netToAd[net] = ad
        except:
            logger.error('bad algod: %r', net, exc_info=True)


    def do_snap(self, now, get_cpu=False, fraction=False):
        snapshot_name = time.strftime('%Y%m%d_%H%M%S', time.gmtime(now))
        snapshot_isotime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))
        if fraction:
            sf = now - math.floor(now)
            sfs = '{:.6f}'.format(sf)
            if sfs[0] == '0':
                sfs = sfs[1:]
            snapshot_name += sfs
            snapshot_isotime += sfs
        logger.debug('begin snapshot %s', snapshot_name)
        psheaps = {}
        newsnapshots = {}
        if self.args.heaps:
            for ad in self.they:
                snappath = ad.get_heap_snapshot(snapshot_name, outdir=self.args.out)
                if snappath:
                    newsnapshots[ad.path] = snappath
                rss, vsz = ad.psHeap()
                if rss and vsz:
                    psheaps[ad.nick] = (rss, vsz)
            for nick, rssvsz in psheaps.items():
                rss, vsz = rssvsz
                with open(os.path.join(self.args.out, nick + '.heap.csv'), 'at') as fout:
                    fout.write('{},{},{},{}\n'.format(snapshot_name,snapshot_isotime,rss, vsz))
        if self.args.mutex or self.args.block:
            # get mutex/blocking profiles state and enable as needed
            for ad in self.they:
                settings = ad.get_debug_settings_pprof()
                if not settings:
                    # failed to get settings, probably disabled
                    continue
                updated = False
                if self.args.mutex:
                    mrate = settings.get('mutex-rate', 0)
                    if mrate == 0:
                        settings['mutex-rate'] = 5  # 1/5 of events recorded
                        updated = True
                if self.args.block:
                    brate = settings.get('block-rate', 0)
                    if brate == 0:
                        settings['block-rate'] = 100 # one blocking event per 100 nanoseconds spent blocked.
                        updated = True
                if updated:
                    logger.debug('enabling mutex/blocking profiles on %s', ad.path)
                    ad.set_debug_settings_pprof(settings)
        if self.args.goroutine:
            for ad in self.they:
                ad.get_goroutine_snapshot(snapshot_name, outdir=self.args.out)
        if self.args.mutex:
            for ad in self.they:
                ad.get_mutex_snapshot(snapshot_name, outdir=self.args.out)
        if self.args.block:
            for ad in self.they:
                ad.get_block_snapshot(snapshot_name, outdir=self.args.out)
        if self.args.metrics:
            threads = []
            for ad in self.they:
                threads.append(ad.go_metrics(snapshot_name, outdir=self.args.out))
            for t in threads:
                t.join()
            logger.debug('metrics done')
        if self.args.blockinfo:
            threads = []
            biq = queue.SimpleQueue()
            mr = maxrnd(biq)
            mrt = mr.start()
            bi_hosts = self.bi_hosts or self.they
            for ad in bi_hosts:
                threads.append(ad.go_blockinfo(snapshot_name, outdir=self.args.out, biqueue=biq))
            for t in threads:
                t.join()
            biq.put({})
            mrt.join()
            self.latest_round = mr.maxrnd
            self.rounds_seen.add(self.latest_round)
            logger.debug('blockinfo done')
        if get_cpu:
            cpuSample = durationToSeconds(self.args.cpu_sample) or 90
            threads = []
            for ad in self.they:
                t = threading.Thread(target=ad.get_cpu_profile, kwargs={'snapshot_name':snapshot_name, 'outdir':self.args.out, 'seconds': cpuSample})
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
        if self.args.svg:
            logger.debug('snapped, processing pprof...')
            # make absolute and differential plots
            for path, snappath in newsnapshots.items():
                subprocess.call(['go', 'tool', 'pprof', '-sample_index=inuse_space', '-svg', '-output', snappath + '.inuse.svg', snappath])
                subprocess.call(['go', 'tool', 'pprof', '-sample_index=alloc_space', '-svg', '-output', snappath + '.alloc.svg', snappath])
                prev = self.prevsnapshots.get(path)
                if prev:
                    subprocess.call(['go', 'tool', 'pprof', '-sample_index=inuse_space', '-svg', '-output', snappath + '.inuse_diff.svg', '-base='+prev, snappath])
                    subprocess.call(['go', 'tool', 'pprof', '-sample_index=alloc_space', '-svg', '-output', snappath + '.alloc_diff.svg', '-diff_base='+prev, snappath])
        self.prevsnapshots = newsnapshots
        logger.debug('end snapshot %s', snapshot_name)

    def summaries(self):
        if self.args.out and self.rounds_seen:
            rpath = os.path.join(self.args.out, 'rounds.json')
            with open(rpath, 'wt') as fout:
                json.dump({
                    "min": min(self.rounds_seen),
                    "max": max(self.rounds_seen),
                    "all": sorted(self.rounds_seen),
                }, fout)

def durationToSeconds(rts):
    if rts is None:
        return None
    rts = rts.lower()
    if rts.endswith('h'):
        mult = 3600
        rts = rts[:-1]
    elif rts.endswith('m'):
        mult = 60
        rts = rts[:-1]
    elif rts.endswith('s'):
        mult = 1
        rts = rts[:-1]
    else:
        mult = 1
    return float(rts) * mult

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('data_dirs', nargs='*', help='list paths to algorand datadirs to grab heap profile from')
    ap.add_argument('--no-heap', dest='heaps', default=True, action='store_false', help='disable heap snapshot capture')
    ap.add_argument('--block', default=False, action='store_true', help='also capture goroutines block profile')
    ap.add_argument('--goroutine', default=False, action='store_true', help='also capture goroutine profile')
    ap.add_argument('--mutex', default=False, action='store_true', help='also capture mutex profile')
    ap.add_argument('--metrics', default=False, action='store_true', help='also capture /metrics counts')
    ap.add_argument('--blockinfo', default=False, action='store_true', help='also capture block header info')
    ap.add_argument('--period', default=None, help='seconds between automatically capturing')
    ap.add_argument('--runtime', default=None, help='(\d+)[hm]? time in hour/minute (default second) to gather info then exit')
    ap.add_argument('--rounds', default=None, type=int, help='number of rounds to run')
    ap.add_argument('--tf-inventory', default='terraform-inventory.host', help='terraform inventory file to use if no data_dirs specified')
    ap.add_argument('--token', default='', help='default algod api token to use')
    ap.add_argument('--admin-token', default='', help='default algod admin-api token to use')
    ap.add_argument('--tf-roles', default='relay', help='comma separated list of terraform roles to follow')
    ap.add_argument('--tf-name-re', action='append', default=[], help='regexp to match terraform node names, may be repeated')
    ap.add_argument('--tf-bi-re', help='hosts to get blocks from')
    ap.add_argument('--svg', dest='svg', default=False, action='store_true', help='automatically run `go tool pprof` to generate performance profile svg from collected data')
    ap.add_argument('-p', '--port', default='8580', help='algod port on each host in terraform-inventory')
    ap.add_argument('-o', '--out', default=None, help='directory to write to')
    ap.add_argument('--cpu-after', help='capture cpu profile after some time (e.g. 5m (after start))')
    ap.add_argument('--cpu-sample', help='capture cpu profile for some time (e.g. 90s)')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    for nre in args.tf_name_re:
        try:
            # do re.compile just to check
            re.compile(nre)
        except Exception as e:
            sys.stderr.write('bad --tf-name-re %r: %s', nre, e)
            return 1

    app = watcher(args)

    # get a first snapshot immediately
    start = time.time()
    now = start

    app.do_snap(now)
    endtime = None
    end_round = None
    if (app.latest_round is not None) and (args.rounds is not None):
        end_round = app.latest_round + args.rounds
    if args.runtime:
        endtime = durationToSeconds(args.runtime) + start
        logger.debug('now %.1f; endtime %.1f', start, endtime)

    cpuAfter = durationToSeconds(args.cpu_after)
    if cpuAfter is not None:
        cpuAfter += start


    if args.period:
        periodSecs = durationToSeconds(args.period)
        snap_fraction = periodSecs < 1.0

        periodi = 1
        nextt = start + (periodi * periodSecs)
        while not graceful_stop:
            logger.debug('nextt %f now %f', nextt, now)
            while nextt < now:
                nextt = start + (periodi * periodSecs)
                periodi += 1
            while now < nextt - (periodSecs * 0.05):
                logger.debug('sleep %f', nextt - now)
                time.sleep(nextt - now)
                if graceful_stop:
                    return 0
                now = time.time()
            periodi += 1
            nextt += periodSecs
            get_cpu = False
            if (cpuAfter is not None) and (now > cpuAfter):
                get_cpu = True
                cpuAfter = None
            app.do_snap(now, get_cpu, fraction=snap_fraction)
            now = time.time()
            if (endtime is not None) and (now > endtime):
                logger.debug('after endtime, done')
                return 0
            if (end_round is not None) and (app.latest_round is not None) and (app.latest_round >= end_round):
                logger.debug('after end round %d > %d', app.latest_round, end_round)
                return 0
    app.summaries()
    return 0

if __name__ == '__main__':
    sys.exit(main())
