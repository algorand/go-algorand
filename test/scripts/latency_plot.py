#!/usr/bin/env python3
#
# process pingpong TotalLatencyOut output file into a graph
#
# requires:
# pip install matplotlib

import argparse
import gzip
import math
import os
import statistics
import sys
import tarfile

def mmstdm(data):
    dmin = min(data)
    dmax = max(data)
    dmean = statistics.mean(data)
    dstd = statistics.pstdev(data)
    return f'[{dmin:.3f}/{dmean:.3f} ({dstd:.3f})/{dmax:.3f}]'

class LatencyAnalyzer:
    def __init__(self):
        self.data = []
    def read(self, path):
        if path.endswith('.gz'):
            with gzip.open(path, 'rt') as fin:
                self.rlines(fin)
        else:
            with open(path, 'rt') as fin:
                self.rlines(fin)
    def rlines(self, linesource):
        for line in linesource:
            rec = int(line.strip())/1000000000.0
            self.data.append(rec)
    def plot(self, outname):
        from matplotlib import pyplot as plt
        plt.plot(self.data)
        plt.savefig(outname + '.png', format='png')
        plt.savefig(outname + '.svg', format='svg')
    def report_data(self):
        self.data.sort()
        some = int(math.log(len(self.data))*4)
        lowest = self.data[:some]
        highest = self.data[-some:]
        return some, lowest, highest
    def report(self):
        lines = []
        some, lowest, highest = self.report_data()
        lines.append(f'{len(self.data)} points: {mmstdm(self.data)}')
        lines.append('min {:.3f}s'.format(min(self.data)))
        lines.append('max {:.3f}s'.format(max(self.data)))
        lines.append(f'lowest-{some}: {mmstdm(lowest)}')
        lines.append(f'highest-{some}: {mmstdm(highest)}')
        return '\n'.join(lines)
    def report_html(self):
        lines = []
        some, lowest, highest = self.report_data()
        lines.append('<h2>Latency</h2>')
        lines.append('<div class="legend">[min/mean (std)/max]</div>')
        lines.append(f'<div>{len(self.data)} points: {mmstdm(self.data)}</div>')
        lines.append(f'<div>min {min(self.data):.3f}s</div>')
        lines.append(f'<div>max {max(self.data):.3f}s</div>')
        lines.append(f'<div>lowest-{some}: {mmstdm(lowest)}</div>')
        lines.append(f'<div>highest-{some}: {mmstdm(highest)}</div>')
        return ''.join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('latency_log', nargs='*')
    ap.add_argument('-p', '--plot', help='plot base name for .png .svg')
    ap.add_argument('-a', '--aout', help='report text output path (append)')
    ap.add_argument('-H', '--ahtml', help='report html output path (append)')
    ap.add_argument('--tardir')
    args = ap.parse_args()

    la = LatencyAnalyzer()
    for path in args.latency_log:
        la.read(path)
    if args.tardir:
        for dirpath, dirnames, filenames in os.walk(args.tardir):
            for fname in filenames:
                if fname.endswith('.tar.bz2'):
                    tarname = os.path.join(dirpath, fname)
                    tf = tarfile.open(tarname, 'r:bz2')
                    for tinfo in tf:
                        if not tinfo.isfile():
                            continue
                        if 'latency' in tinfo.name:
                            rawf = tf.extractfile(tinfo)
                            if tinfo.name.endswith('.gz'):
                                fin = gzip.open(rawf, 'rt')
                            else:
                                fin = rawf
                                rawf = None
                            try:
                                la.rlines(fin)
                            except Exception as e:
                                sys.stderr.write(f'{tarname}/{tinfo.name}: {e}\n')
                            fin.close()
                            if rawf is not None:
                                rawf.close()

    if args.plot:
        la.plot(args.plot)
    if args.ahtml:
        with open(args.ahtml, 'at') as fout:
            fout.write(la.report_html())
    if args.aout:
        with open(args.aout, 'at') as fout:
            fout.write(la.report())
    if (not args.aout) and (not args.ahtml):
        print(la.report())

if __name__ == '__main__':
    main()
