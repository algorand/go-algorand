#!/usr/bin/env python3
#
# process pingpong TotalLatencyOut output file into a graph
#
# requires:
# pip install matplotlib

import argparse
import gzip
import math
import statistics

from matplotlib import pyplot as plt

def mmstdm(data):
    dmin = min(data)
    dmax = max(data)
    dmean = statistics.mean(data)
    dstd = statistics.pstdev(data)
    return f'[{dmin}/{dmean} ({dstd})/{dmax}]'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('latency_log')
    args = ap.parse_args()

    data = []
    if args.latency_log.endswith('.gz'):
        fin = gzip.open(args.latency_log, 'rt')
        outname = args.latency_log.replace('.gz', '')
    else:
        fin = open(args.latency_log, 'rt')
        outname = args.latency_log
    for line in fin:
        rec = int(line.strip())/1000000000.0
        data.append(rec)
    fin.close()

    #subd = data[50:-50]
    subd = data
    print('min {:.2f}s'.format(min(subd)))
    print('max {:.2f}s'.format(max(subd)))
    plt.plot(subd)
    plt.savefig(outname + '.png', format='png')
    plt.savefig(outname + '.svg', format='svg')
    subd.sort()
    some = int(math.log(len(data))*4)
    lowest = subd[:some]
    highest = subd[-some:]
    print(f'lowest-{some}: {mmstdm(lowest)}')
    print(f'highest-{some}: {mmstdm(highest)}')

if __name__ == '__main__':
    main()
