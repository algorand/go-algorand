#!/usr/bin/env python3
#

import argparse
import configparser
import logging
import os
import re
import threading

import block_history

logger = logging.getLogger(__name__)

relay_pat = re.compile(r'name_r\d+')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tf-inventory', default='terraform-inventory.host', help='terraform inventory file to use if no data_dirs specified')
    ap.add_argument('--all', default=False, action='store_true')
    ap.add_argument('-p', '--port', default='8580', help='algod port on each host in terraform-inventory')
    ap.add_argument('--token', default='', help='default algod api token to use')
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    #addrName = {}
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
            #addrName[addr] = k
            outpath = os.path.join(args.outdir, k + '_' + net + '.blockhistory')
            fet = block_history.Fetcher(addr=addr, token=args.token, outpath=outpath)
            t = threading.Thread(target=fet.loop)
            logger.debug('starting %s -> %s', addr, outpath)
            t.start()
            threads.append(t)
    for t in threads:
        t.join()
    logger.debug('block_history_relays.py done')

if __name__ == '__main__':
    main()
