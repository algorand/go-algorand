#!/usr/bin/env python3
#
# usage:
#  wait_for_progress.py node.log
#
# wathches log file for round advancement.

import json
import queue
import subprocess
import sys
import threading
import time

def tailf(fname):
    pr = subprocess.Popen(['tail', '-F', '-n', '1', fname], stdout=subprocess.PIPE)
    for line in pr.stdout:
        yield line
    return

_timeout_ob = {}

def timeout_linesource(linesource, timeout=60):
    data_queue = queue.Queue(1)
    end = [time.time() + timeout]
    notdone = [True]
    def reader(xlinesource, xend, xnotdone):
        for line in xlinesource:
            #sys.stderr.write('got line\n')
            xend[0] = time.time() + timeout
            data_queue.put(line)
        #sys.stderr.write('tl reader done\n')
        xnotdone[0] = False
    def watchdog(xend, xnotdone):
        while xnotdone[0]:
            if time.time() > xend[0]:
                data_queue.put(_timeout_ob)
                xnotdone[0] = False
                #sys.stderr.write('tl watchdog timeout\n')
                return
            time.sleep(0.3)
    rt = threading.Thread(target=reader, args=(linesource, end, notdone), daemon=True)
    wt = threading.Thread(target=watchdog, args=(end, notdone), daemon=True)
    rt.start()
    wt.start()
    while notdone[0]:
        ob = data_queue.get(timeout=timeout+1)
        if ob is _timeout_ob:
            #sys.stderr.write('tl done\n')
            return
        yield ob

def jloads(x):
    if isinstance(x, bytes):
        x = x.decode()
    return json.loads(x)

# returne True if progress, False if timeout
def wait_for_progress(linesource, timeout=60, verbose=False):
    errcount = 0
    start = time.time()
    end = start + timeout
    startround = None
    linesource = timeout_linesource(linesource, timeout=timeout)
    for line in linesource:
        try:
            ob = jloads(line)
            lround = ob.get('Round')
            if lround is None:
                continue
            if startround is None:
                startround = lround
            elif startround != lround:
                if verbose:
                    sys.stderr.write('{} -> {}\n'.format(startround, lround))
                return True
            if time.time() > end:
                return False
            errcount = 0
        except:
            errcount += 1
            if errcount < 10:
                continue
            raise
        pass
    return False

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('fname', nargs='?', metavar='FILE', default=None, help='log file to watch')
    ap.add_argument('-t', '--timeout', type=float, default=60, help='seconds to wait')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.fname is None or args.fname == '-':
        ok = wait_for_progress(sys.stdin, timeout=args.timeout, verbose=args.verbose)
    else:
        ok = wait_for_progress(tailf(args.fname), timeout=args.timeout, verbose=args.verbose)
    if ok:
        if args.verbose:
            sys.stderr.write('ok\n')
        sys.exit(0)
    else:
        if args.verbose:
            sys.stderr.write('no progress\n')
        sys.exit(1)
    return


if __name__ == '__main__':
    main()
