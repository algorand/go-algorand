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
# Capture block headers every round from a running `algod`
# Talk to a set of relays found in a terraform-inventory.host file.
#
# pip install py-algorand-sdk


import argparse
import atexit
import configparser
import logging
import os
import re
import signal
import sys
import threading

import block_history

logger = logging.getLogger(__name__)

graceful_stop = False
fetchers = []

def do_graceful_stop(signum, frame):
    global fetchers
    global graceful_stop
    if graceful_stop:
        sys.stderr.write("second signal, quitting\n")
        sys.exit(1)
    sys.stderr.write("graceful stop...\n")
    graceful_stop = True
    for fet in fetchers:
        fet.go = False

relay_pat = re.compile(r'name_r\d+')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tf-inventory', default='terraform-inventory.host', help='terraform inventory file to use if no data_dirs specified')
    ap.add_argument('--all', default=False, action='store_true')
    ap.add_argument('-p', '--port', default='8580', help='algod port on each host in terraform-inventory')
    ap.add_argument('--pid')
    ap.add_argument('--token', default='', help='default algod api token to use')
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--all-rounds', default=False, action='store_true', help='fetch all blocks from 0')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.pid:
        with open(args.pid, 'w') as fout:
            fout.write('{}'.format(os.getpid()))
        atexit.register(os.remove, args.pid)
    prev_round = None
    if args.all_rounds:
        prev_round = -1
    signal.signal(signal.SIGTERM, do_graceful_stop)
    signal.signal(signal.SIGINT, do_graceful_stop)

    threads = []
    cp = configparser.ConfigParser(allow_no_value=True)
    cp.read(args.tf_inventory)
    for k,v in cp.items():
        if not relay_pat.match(k):
            continue
        if args.all:
            pass
        elif k.endswith('1'):
            pass
        else:
            continue
        for net in v.keys():
            addr = 'http://' + net + ':' + args.port
            outpath = os.path.join(args.outdir, k + '_' + net + '.blockhistory')
            fet = block_history.Fetcher(addr=addr, token=args.token, outpath=outpath, prev_round=prev_round)
            t = threading.Thread(target=fet.loop)
            logger.debug('starting %s -> %s', addr, outpath)
            t.start()
            threads.append(t)
            fetchers.append(fet)
    for t in threads:
        t.join()
    logger.debug('block_history_relays.py done')

if __name__ == '__main__':
    main()
