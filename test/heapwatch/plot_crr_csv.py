#!/usr/bin/env python3
#
# Plot the output of test/heapwatch/client_ram_report.py --csv

import csv
import random

from matplotlib import pyplot as plt

_meta_cols = {'when', 'dt', 'round'}

def smin(a,b):
    if a is None:
        return b
    if b is None:
        return a
    return min(a,b)
def smax(a,b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a,b)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+')
    args = ap.parse_args()

    for fname in args.files:
        fvals = {}
        minv = None
        maxv = None
        with open(fname) as fin:
            reader = csv.DictReader(fin)
            for rec in reader:
                xround = int(rec['round'])
                for k,v in rec.items():
                    if k in _meta_cols:
                        continue
                    klist = fvals.get(k)
                    if klist is None:
                        klist = []
                        fvals[k] = klist
                    v = float(v)
                    klist.append((xround, v))
                    minv = smin(minv, v)
                    maxv = smax(maxv, v)
        print("{} found series {}".format(fname, sorted(fvals.keys())))
        fig, ax = plt.subplots()
        ax.set_ylabel('bytes')
        ax.set_xlabel('round')
        ax.set_ylim(minv,maxv)
        for k in sorted(fvals.keys()):
            xy = fvals[k]
            #for k, xy in fvals.items():
            lc = None
            if k.startswith('r'):
                # blueish
                lc = (0.3*random.random(), 0.3*random.random(), 0.7+(0.3*random.random()))
            elif k.startswith('npn'):
                # greenish
                lc = (0.3*random.random(), 0.7+(0.3*random.random()), 0.3*random.random())
            elif k.startswith('n'):
                # reddish
                lc = (0.7+(0.3*random.random()), 0.3*random.random(), 0.3*random.random())
            ax.plot([p[0] for p in xy], [p[1] for p in xy], label=k, color=lc)
        ax.legend(loc='upper left', ncol=2)
        plt.savefig(fname + '.svg', format='svg')
        plt.savefig(fname + '.png', format='png')
        #plt.show()

if __name__ == '__main__':
    main()
