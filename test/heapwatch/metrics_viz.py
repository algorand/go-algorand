"""
Tool for metrics files visualization.
Expects metrics files in format <node nickname>.<date>_<time>.metrics like Primary.20230804_182932.metrics
Works with metrics collected by heapWatch.py.

Example usage for local net:
python3 ./test/heapwatch/heapWatch.py --period 10 --metrics --blockinfo --runtime 20m -o nodedata ~/networks/mylocalnet/Primary
python3 ./test/heapwatch/metrics_viz.py -d nodedata algod_transaction_messages_handled algod_tx_pool_count algod_transaction_messages_backlog_size algod_go_memory_classes_total_bytes

Also works with bdevscripts for cluster tests since it uses heapWatch.py for metrics collection.
"""

import argparse
import glob
import logging
import os
import re
import time
import sys

import dash
from dash import dcc, html
import plotly.graph_objs as go
from plotly.subplots import make_subplots

from metrics_lib import MetricType, parse_metrics, gather_metrics_files_by_nick

logger = logging.getLogger(__name__)


def main():
    os.environ['TZ'] = 'UTC'
    time.tzset()
    default_img_filename = 'metrics_viz.png'
    default_html_filename = 'metrics_viz.html'

    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_names', nargs='+', default=None, help='metric name(s) to track')
    ap.add_argument('-d', '--dir', type=str, default=None, help='dir path to find /*.metrics in')
    ap.add_argument('-l', '--list-nodes', default=False, action='store_true', help='list available node names with metrics')
    ap.add_argument('--nick-re', action='append', default=[], help='regexp to filter node names, may be repeated')
    ap.add_argument('--nick-lre', action='append', default=[], help='label:regexp to filter node names, may be repeated')
    ap.add_argument('-s', '--save', type=str, choices=['png', 'html'], help=f'save plot to \'{default_img_filename}\' or \'{default_html_filename}\' file instead of showing it')
    ap.add_argument('--diff', action='store_true', default=None, help='diff two gauge metrics instead of plotting their values. Requires two metrics names to be set')
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
    nrows = 1 if args.diff and len(args.metrics_names) == 2 else len(metrics_names)

    fig = make_subplots(
        rows=nrows, cols=1,
        vertical_spacing=0.03, shared_xaxes=True,
        subplot_titles=[f'{name}' for name in sorted(metrics_names)],
    )

    fig['layout']['margin'] = {
        'l': 30, 'r': 10, 'b': 10, 't': 20
    }
    fig['layout']['height'] = 500 * nrows
    # fig.update_layout(template="plotly_dark")

    for nick, files_by_date in filesByNick.items():
        active_metrics = {}
        data = {'time': []}
        raw_series = {}
        raw_times = {}
        idx = 0
        for dt, metrics_file in files_by_date.items():
            data['time'].append(dt)
            with open(metrics_file, 'rt') as f:
                metrics = parse_metrics(f, nick, metrics_names, args.diff)
                for metric_name, metrics_seq in metrics.items():
                    active_metric_names = []
                    for metric in metrics_seq:
                        raw_value = metric.value

                        full_name = metric.string()
                        if full_name not in data:
                            # handle gaps in data, sometimes metric file might miss a value
                            # but the chart requires matching x and y series (time and metric value)
                            # data is what does into the chart, and raw_series is used to calculate
                            data[full_name] = [0] * len(files_by_date)
                            raw_series[full_name] = []
                            raw_times[full_name] = []

                        metric_value = metric.value
                        if metric.type == MetricType.COUNTER:
                            if len(raw_series[full_name]) > 0 and len(raw_times[full_name]) > 0:
                                metric_value = (metric_value - raw_series[full_name][-1]) / (dt - raw_times[full_name][-1]).total_seconds()
                            else:
                                metric_value = 0

                        data[full_name][idx] = metric_value
                        raw_series[full_name].append(raw_value)
                        raw_times[full_name].append(dt)

                        active_metric_names.append(full_name)

                    active_metric_names.sort()
                    active_metrics[metric_name] = active_metric_names
            idx += 1

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

    # app.run_server(debug=True)
    return 0

if __name__ == '__main__':
    sys.exit(main())