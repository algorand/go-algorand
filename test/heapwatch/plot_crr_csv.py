#!/usr/bin/env python3
#
# Plot the output of test/heapwatch/client_ram_report.py --csv

import csv
import random

from matplotlib import pyplot as plt
from matplotlib.ticker import MaxNLocator, FuncFormatter

_meta_cols = {'when', 'dt', 'round'}
_metrics_cols = {'free', 'inuse', 'released', 'total'}

# see https://matplotlib.org/stable/gallery/lines_bars_and_markers/linestyles.html
plt_line_styles = [
    'solid', 'dotted', 'dashed', 'dashdot',
    (5, (10, 3)), # long dash with offset
    (0, (3, 5, 1, 5)), # dashdotted
    (0, (3, 10, 1, 10, 1, 10)), # loosely dashdotted
]

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

def add_metric(d, k, m, x, y):
    """d: {k: {m: [(x,y)]}}"""
    mt = d.get(k)
    if mt is None:
        d[k] = {m: [(x,y)]}
    else:
        klist = mt.get(m)
        if klist is None:
            mt[m] = [(x,y)]
        else:
            klist.append((x, y))


def format_mem(x, _):
    if x<0:
        return ""
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        if x < 1024:
            return "%3.1f %s" % (x, unit)
        x /= 1024

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+')
    args = ap.parse_args()

    for fname in args.files:
        fvals = {}
        minv = None
        maxv = None
        minr = None
        maxr = None
        with open(fname) as fin:
            reader = csv.DictReader(fin)
            for rec in reader:
                xround = int(rec['round'])
                row_nick = None
                for k,v in rec.items():
                    if k in _meta_cols:
                        continue
                    v = float(v)
                    parts = k.split('#')
                    if len(parts) == 2:
                        row_nick = parts[0]
                        metric = parts[1]
                    else :
                        print(f"unknown column {k}")
                        row_nick = k
                        metric = k
                    add_metric(fvals, row_nick, metric, xround, v)

                    minv = smin(minv, v)
                    maxv = smax(maxv, v)
                minr = smin(minr, xround)
                maxr = smax(maxr, xround)
        if not fvals:
            print(f"{fname} empty")
            continue
        nodes = sorted(fvals.keys())
        print("{} found series {} ({} - {})".format(fname, nodes, minr, maxr))
        fig, ax = plt.subplots()
        ax.xaxis.set_major_locator(MaxNLocator(integer=True))
        ax.set_xlim([minr, maxr])
        ax.yaxis.set_major_formatter(FuncFormatter(format_mem))
        ax.set_ylabel('bytes')
        ax.set_xlabel('round')
        ax.set_ylim(minv,maxv)

        max_val_color = max(map(len, nodes)) * ord('z')
        for k in nodes:
            lc = None  # let matplotlib to pick a color if there is no standard nodes name pattern => probably because of a single local run
            if len(nodes) > 1:
            # if there are multiple nodes choose some color based on the node name
                s = sum(map(ord, k))
                lc = (s/max_val_color, s/max_val_color, s/max_val_color)
            if k.startswith('r'):
                # blueish
                lc = (0.3*random.random(), 0.3*random.random(), 0.7+(0.3*random.random()))
            elif k.startswith('npn'):
                # greenish
                lc = (0.3*random.random(), 0.7+(0.3*random.random()), 0.3*random.random())
            elif k.startswith('n'):
                # reddish
                lc = (0.7+(0.3*random.random()), 0.3*random.random(), 0.3*random.random())

            metrics = fvals[k]
            for i, metric in enumerate(metrics.keys()):
                xy = metrics[metric]

                ax.plot([p[0] for p in xy], [p[1] for p in xy], label=f'{k}/{metric}', color=lc, linestyle=plt_line_styles[i%len(plt_line_styles)])
        fig.legend(loc='outside upper left', ncol=4)
        plt.savefig(fname + '.svg', format='svg')
        plt.savefig(fname + '.png', format='png')
        #plt.show()

if __name__ == '__main__':
    main()
