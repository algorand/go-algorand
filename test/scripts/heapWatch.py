#!/usr/bin/python3
#
# repeatedly snapshot heap profiles for one or more algod
#
# usage:
# mkdir -p /tmp/heaps
# python3 test/scripts/heapWatch.py -o /tmp/heaps --period 60s private_network_root/*

import argparse
import logging
import os
import signal
import subprocess
import sys
import time
import urllib.request

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


class algodDir:
    def __init__(self, path):
        self.path = path
        self.nick = os.path.basename(self.path)
        net, token, admin_token = read_algod_dir(self.path)
        self.net = net
        self.token = token
        self.admin_token = admin_token
        self.headers = {}
        self._pid = None

    def pid(self):
        if self._pid is None:
            with open(os.path.join(self.path, 'algod.pid')) as fin:
                self._pid = int(fin.read())
        return self._pid

    def get_pprof_snapshot(self, name, snapshot_name=None, outdir=None):
        url = 'http://' + self.net + '/urlAuth/' + self.admin_token + '/debug/pprof/' + name
        response = urllib.request.urlopen(urllib.request.Request(url, headers=self.headers))
        if response.code != 200:
            logger.error('could not fetch %s from %s via %r', name, self.path. url)
            return
        blob = response.read()
        if snapshot_name is None:
            snapshot_name = time.strftime('%Y%m%d_%H%M%S', time.gmtime())
        outpath = os.path.join(outdir or '.', self.nick + '.' + snapshot_name + '.' + name)
        with open(outpath, 'wb') as fout:
            fout.write(blob)
        logger.debug('%s -> %s', self.nick, outpath)
        return outpath

    def get_heap_snapshot(self, snapshot_name=None, outdir=None):
        return self.get_pprof_snapshot('heap', snapshot_name, outdir)

    def get_goroutine_snapshot(self, snapshot_name=None, outdir=None):
        return self.get_pprof_snapshot('goroutine', snapshot_name, outdir)

    def psHeap(self):
        # return rss, vsz
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

class watcher:
    def __init__(self, args):
        self.args = args
        self.prevsnapshots = {}
        self.they = []
        for path in args.data_dirs:
            if os.path.exists(os.path.join(path, 'algod.net')):
                try:
                    ad = algodDir(path)
                    logger.debug('found "%s" at %r', ad.nick, ad.path)
                    self.they.append(ad)
                except:
                    logger.error('bad algod: %r', path, exc_info=True)

    def do_snap(self, now):
        snapshot_name = time.strftime('%Y%m%d_%H%M%S', time.gmtime(now))
        snapshot_isotime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))
        logger.debug('begin snapshot %s', snapshot_name)
        psheaps = {}
        newsnapshots = {}
        for ad in self.they:
            snappath = ad.get_heap_snapshot(snapshot_name, outdir=self.args.out)
            newsnapshots[ad.path] = snappath
            rss, vsz = ad.psHeap()
            if rss and vsz:
                psheaps[ad.nick] = (rss, vsz)
        for nick, rssvsz in psheaps.items():
            rss, vsz = rssvsz
            with open(os.path.join(self.args.out, nick + '.heap.csv'), 'at') as fout:
                fout.write('{},{},{},{}\n'.format(snapshot_name,snapshot_isotime,rss, vsz))
        if self.args.goroutine:
            for ad in self.they:
                ad.get_goroutine_snapshot(snapshot_name, outdir=self.args.out)
        logger.debug('snapped, processing...')
        # make absolute and differential plots
        for path, snappath in newsnapshots.items():
            subprocess.call(['go', 'tool', 'pprof', '-sample_index=inuse_space', '-svg', '-output', snappath + '.inuse.svg', snappath])
            subprocess.call(['go', 'tool', 'pprof', '-sample_index=alloc_space', '-svg', '-output', snappath + '.alloc.svg', snappath])
            prev = self.prevsnapshots.get(path)
            if prev:
                subprocess.call(['go', 'tool', 'pprof', '-sample_index=inuse_space', '-svg', '-output', snappath + '.inuse_diff.svg', '-base='+prev, snappath])
                subprocess.call(['go', 'tool', 'pprof', '-sample_index=alloc_space', '-svg', '-output', snappath + '.alloc_diff.svg', '-diff_base='+prev, snappath])
        self.prevsnapshots = newsnapshots

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('data_dirs', nargs='*', help='list paths to algorand datadirs to grab heap profile from')
    ap.add_argument('--goroutine', default=False, action='store_true', help='also capture goroutine profile')
    ap.add_argument('--period', default=None, help='seconds between automatically capturing')
    ap.add_argument('-o', '--out', default=None, help='directory to write to')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    app = watcher(args)

    # get a first snapshot immediately
    start = time.time()
    now = start

    app.do_snap(now)

    if args.period:
        lastc = args.period.lower()[-1:]
        if lastc == 's':
            periodSecs = int(args.period[:-1])
        elif lastc == 'm':
            periodSecs = int(args.period[:-1]) * 60
        elif lastc == 'h':
            periodSecs = int(args.period[:-1]) * 3600
        else:
            periodSecs = int(args.period)

        periodi = 1
        nextt = start + (periodi * periodSecs)
        while not graceful_stop:
            while nextt < now:
                nextt = start + (periodi * periodSecs)
            while now < nextt - (periodSecs * 0.05):
                logger.debug('sleep %f', nextt - now)
                time.sleep(nextt - now)
                if graceful_stop:
                    return
                now = time.time()
            periodi += 1
            nextt += periodSecs
            app.do_snap(now)

if __name__ == '__main__':
    sys.exit(main())
