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
# Convert metrics collected by heapWatch.py from prometheus format to prometheus + timestamp format.
# See https://prometheus.io/docs/prometheus/latest/storage/#backfilling-from-openmetrics-format
#
# Usage:
# python3 /data/go-algorand/test/heapwatch/metrics_gra.py -d metrics/500x15/ -o prom-metrics.txt
#
# Local Grafana setup:
# 1. Download standalone and unpack from https://grafana.com/grafana/download
# 2. Run ./grafana-v11.2.2/bin/grafana server -config ./grafana-v11.2.2/conf/defaults.ini -homepath ./grafana-v11.2.2
# 3. Open http://localhost:3000/ in web browser
#
# Prometheus setup:
# 1. Download and unpack from https://prometheus.io/download/
#
# Apply prom-metrics.txt to prometheus:
# (cd ./prometheus-2.54.1.linux-amd64 && ./promtool tsdb create-blocks-from openmetrics prom-metrics.txt)
# Start Prometheus
# ./prometheus-2.54.1.linux-amd64/prometheus --config.file=./prometheus-2.54.1.linux-amd64/prometheus.yml --storage.tsdb.path=./prometheus-2.54.1.linux-amd64/data --storage.tsdb.retention.time=60d --storage.tsdb.retention.size=500MB
# This should import the data into ./prometheus-2.54.1.linux-amd64/data and have them available for plotting. Use https://127.0.0.1:9090/ as Prometheus data source location in Grafana.
# Then create new or import dashboards from internal Grafana.
###

import argparse
import glob
import logging
import os
import sys

from metrics_lib import gather_metrics_files_by_nick, parse_metrics

logger = logging.getLogger(__name__)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', type=str, default=None, help='dir path to find /*.metrics in')
    ap.add_argument('--nick-re', action='append', default=[], help='regexp to filter node names, may be repeated')
    ap.add_argument('--nick-lre', action='append', default=[], help='label:regexp to filter node names, may be repeated')
    ap.add_argument('-o', '--output', type=str, default=None, help='output file to write to')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if not args.dir:
        logging.error('need at least one dir set with -d/--dir')
        return 1

    metrics_files = sorted(glob.glob(os.path.join(args.dir, '*.metrics')))
    metrics_files.extend(glob.glob(os.path.join(args.dir, 'terraform-inventory.host')))
    filesByNick = gather_metrics_files_by_nick(metrics_files, args.nick_re, args.nick_lre)

    outf = sys.stdout
    if args.output:
        outf = open(args.output, 'wt')

    for nick, files_by_ts in filesByNick.items():
        for ts, metrics_file in files_by_ts.items():
            with open(metrics_file, 'rt') as fin:
                metrics = parse_metrics(fin, nick)
                for metric_seq in metrics.values():
                    for metric in metric_seq:
                        print('# TYPE', metric.short_name(), metric.type, file=outf)
                        print('# HELP', metric.short_name(), metric.desc, file=outf)
                        print(metric.string(with_role=True, quote=True), metric.value, int(ts.timestamp()), file=outf)

    print('# EOF', file=outf)

    return 0


if __name__ == '__main__':
    sys.exit(main())
