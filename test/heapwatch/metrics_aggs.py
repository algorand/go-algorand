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
# Process and aggregate /metrics data captured by heapWatch.py
# Useful for metrics with labels and bandwidth analysis.
#
import argparse
import glob
import logging
import os
import time
import sys

import dash
from dash import dcc, html
import plotly.graph_objs as go
from plotly.subplots import make_subplots


from metrics_lib import Metric, MetricType, parse_metrics, gather_metrics_files_by_nick, parse_tags

logger = logging.getLogger(__name__)


def main():
    os.environ['TZ'] = 'UTC'
    time.tzset()
    default_img_filename = 'metrics_aggs.png'
    default_html_filename = 'metrics_aggs.html'

    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_names', nargs='+', default=None, help='metric name(s) to track')
    ap.add_argument('-d', '--dir', type=str, default=None, help='dir path to find /*.metrics in')
    ap.add_argument('-l', '--list-nodes', default=False, action='store_true', help='list available node names with metrics')
    ap.add_argument('-t', '--tags', action='append', default=[], help='tag/label pairs in a=b format to aggregate by, may be repeated. Empty means aggregation by metric name')
    ap.add_argument('--nick-re', action='append', default=[], help='regexp to filter node names, may be repeated')
    ap.add_argument('--nick-lre', action='append', default=[], help='label:regexp to filter node names, may be repeated')
    ap.add_argument('-s', '--save', type=str, choices=['png', 'html'], help=f'save plot to \'{default_img_filename}\' or \'{default_html_filename}\' file instead of showing it')
    ap.add_argument('--verbose', default=False, action='store_true')
    ap.add_argument('--avg-max', default=False, action='store_true', help='print avg of max values across nodes for each metric')
    ap.add_argument('--avg-max-min', default=False, action='store_true', help='print avg of max-min values across nodes for each metric')

    args = ap.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    tags, tag_keys = parse_tags(args.tags)

    metrics_files = sorted(glob.glob(os.path.join(args.dir, '*.metrics')))
    metrics_files.extend(glob.glob(os.path.join(args.dir, 'terraform-inventory.host')))
    filesByNick = gather_metrics_files_by_nick(metrics_files, args.nick_re, args.nick_lre)

    if args.list_nodes:
        print('Available nodes:', ', '.join(sorted(filesByNick.keys())))
        return 0

    app = dash.Dash(__name__)
    app.layout = html.Div(
        html.Div([
            html.H4('Algod Metrics'),
            html.Div(id='text'),
            dcc.Graph(id='graph'),
        ])
    )
    metrics_names = set(args.metrics_names)
    nrows = len(metrics_names)

    fig = make_subplots(
        rows=nrows, cols=1,
        vertical_spacing=0.03, shared_xaxes=True,
        subplot_titles=[f'{name}' for name in sorted(metrics_names)],
    )

    fig['layout']['margin'] = {
        'l': 30, 'r': 10, 'b': 10, 't': 20
    }
    fig['layout']['height'] = 500 * nrows

    nick_series = {}

    for nick, files_by_date in filesByNick.items():
        active_metrics = {}
        data = {'time': []}
        raw_series = {}
        raw_times = {}
        idx = 0
        for dt, metrics_file in files_by_date.items():
            data['time'].append(dt)
            with open(metrics_file, 'rt') as f:
                metrics = parse_metrics(f, nick, metrics_names)
                for metric_name, metrics_seq in metrics.items():
                    active_metric_names = []
                    raw_value = 0
                    for metric in metrics_seq:
                        if metric.type != MetricType.COUNTER:
                            raise RuntimeError('Only COUNT metrics are supported')
                        if tags is None or tags is not None and metric.has_tags(tags, tag_keys):
                            raw_value += metric.value
                            full_name = metric.string(set(tag_keys).union({'n'}))

                    if full_name is None:
                        continue

                    if full_name not in data:
                        # handle gaps in data, sometimes metric file might miss a value
                        # but the chart requires matching x and y series (time and metric value)
                        # data is what does into the chart, and raw_series is used to calculate
                        data[full_name] = [0] * len(files_by_date)
                        raw_series[full_name] = []
                        raw_times[full_name] = []

                    metric_value = raw_value
                    if len(raw_series[full_name]) > 0 and len(raw_times[full_name]) > 0:
                        metric_value = (metric_value - raw_series[full_name][-1]) / (dt - raw_times[full_name][-1]).total_seconds()
                    else:
                        metric_value = 0

                    data[full_name][idx] = metric_value
                    raw_series[full_name].append(raw_value)
                    raw_times[full_name].append(dt)

                    active_metric_names.append(full_name)

                    active_metric_names.sort()
                    active_metrics[full_name] = active_metric_names
            idx += 1

        if args.avg_max or args.avg_max_min:
            nick_series[nick] = raw_series

        for i, metric_pair in enumerate(sorted(active_metrics.items())):
            metric_name, metric_fullnames = metric_pair
            for metric_fullname in metric_fullnames:
                fig.append_trace(go.Scatter(
                    x=data['time'],
                    y=data[metric_fullname],
                    name=metric_fullname,
                    mode='lines+markers',
                    line=dict(width=1),
                ), i+1, 1)

    if args.avg_max or args.avg_max_min:
        metric_names_nick_max_avg = {}
        for nick, raw_series in nick_series.items():
            for metric_name, rw in raw_series.items():
                mmax = max(rw)
                mmin = min(rw)
                print(f'{nick}: {metric_name}: count {len(rw)}, max {mmax}, min {mmin}, min-max {mmax - mmin}')
                metric = Metric(metric_name, 0, '', MetricType.COUNTER)
                if metric.short_name() not in metric_names_nick_max_avg:
                    metric_names_nick_max_avg[metric.short_name()] = []
                if args.avg_max_min:
                    metric_names_nick_max_avg[metric.short_name()].append(mmax - mmin)
                if args.avg_max:
                    metric_names_nick_max_avg[metric.short_name()].append(mmax)
        for metric_name, val in metric_names_nick_max_avg.items():
            print(f'{metric_name}: avg {sum(val)/len(val)}')

    if args.save:
        if args.save == 'html':
            target_path = os.path.join(args.dir, default_html_filename)
            fig.write_html(target_path)
        else:
            target_path = os.path.join(args.dir, default_img_filename)
            fig.write_image(target_path)
        print(f'Saved plot to {target_path}')
    else:
        fig.show()

    return 0

if __name__ == '__main__':
    sys.exit(main())