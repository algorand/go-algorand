#!/usr/bin/env python3
#
# process pingpong TotalLatencyOut output file into a graph
#
# requires:
# pip install matplotlib

import argparse
import statistics

from matplotlib import pyplot as plt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('latency_log')
    args = ap.parse_args()

    data = []
    with open(args.latency_log) as fin:
        for line in fin:
            rec = int(line.strip())/1000000000.0
            data.append(rec)

    #subd = data[50:-50]
    subd = data
    print('min {:.2f}s'.format(min(subd)))
    print('max {:.2f}s'.format(max(subd)))
    plt.plot(subd)
    plt.savefig(args.latency_log + '.png', format='png')
    plt.savefig(args.latency_log + '.svg', format='svg')

if __name__ == '__main__':
    main()
