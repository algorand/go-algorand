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
from datetime import datetime
import glob
import logging
import os
import re
import time
from typing import Dict, Iterable, Tuple
import sys

import dash
from dash import dcc, html
import plotly.graph_objs as go
from plotly.subplots import make_subplots

from metrics_delta import metric_line_re, num, terraform_inventory_ip_not_names
from client_ram_report import dapp

logger = logging.getLogger(__name__)

metrics_fname_re = re.compile(r'(.*?)\.(\d+_\d+)\.metrics')

def gather_metrics_files_by_nick(metrics_files: Iterable[str]) -> Dict[str, Dict[datetime, str]]:
    """return {"node nickname": {datetime: path, ...}, ...}}"""
    filesByNick = {}
    tf_inventory_path = None
    for path in metrics_files:
        fname = os.path.basename(path)
        if fname == 'terraform-inventory.host':
            tf_inventory_path = path
            continue
        m = metrics_fname_re.match(fname)
        if not m:
            continue
        nick = m.group(1)
        timestamp = m.group(2)
        timestamp = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
        dapp(filesByNick, nick, timestamp, path)
    return tf_inventory_path, filesByNick


TYPE_GAUGE = 0
TYPE_COUNTER = 1

def parse_metrics(fin: Iterable[str], nick: str, metrics_names: set=None, diff: bool=None) -> Tuple[Dict[str, float], Dict[str, int]]:
    """Parse metrics file and return dicts of values and types"""
    out = {}
    types = {}
    try:
        last_type = None
        for line in fin:
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            if line[0] == '#':
                if line.startswith('# TYPE'):
                    tpe = line.split()[-1]
                    if tpe == 'gauge':
                        last_type = TYPE_GAUGE
                    elif tpe == 'counter':
                        last_type = TYPE_COUNTER
                continue
            m = metric_line_re.match(line)
            if m:
                name = m.group(1)
                value = num(m.group(2))
            else:
                ab = line.split()
                name = ab[0]
                value = num(ab[1])

            det_idx = name.find('{')
            if det_idx != -1:
                name = name[:det_idx]
            fullname = f'{name}{{n={nick}}}'
            if not metrics_names or name in metrics_names:
                out[fullname] = value
                types[fullname] = last_type
    except:
        print(f'An exception occurred in parse_metrics: {sys.exc_info()}')
        pass
    if diff and metrics_names and len(metrics_names) == 2 and len(out) == 2:
        m = list(out.keys())
        name = f'{m[0]}_-_{m[1]}'
        new_out = {name: out[m[0]] - out[m[1]]}
        new_types = {name: TYPE_GAUGE}
        out = new_out
        types = new_types

    return out, types


def main():
    os.environ['TZ'] = 'UTC'
    time.tzset()
    default_output_file = 'metrics_viz.png'

    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_names', nargs='+', default=None, help='metric name(s) to track')
    ap.add_argument('-d', '--dir', type=str, default=None, help='dir path to find /*.metrics in')
    ap.add_argument('-l', '--list-nodes', default=False, action='store_true', help='list available node names with metrics')
    ap.add_argument('-s', '--save', action='store_true', default=None, help=f'save plot to \'{default_output_file}\' file instead of showing it')
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
    tf_inventory_path, filesByNick = gather_metrics_files_by_nick(metrics_files)
    if tf_inventory_path:
        # remap ip addresses to node names
        ip_to_name = terraform_inventory_ip_not_names(tf_inventory_path)
        for nick in filesByNick.keys():
            name = ip_to_name.get(nick)
            if name:
                val = filesByNick[nick]
                filesByNick[name] = val
                del filesByNick[nick]

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
        vertical_spacing=0.03, shared_xaxes=True)

    fig['layout']['margin'] = {
        'l': 30, 'r': 10, 'b': 10, 't': 10
    }
    fig['layout']['height'] = 500 * nrows
    # fig.update_layout(template="plotly_dark")

    data = {
        'time': [],
    }
    raw_series = {}
    for nick, items in filesByNick.items():
        active_metrics = set()
        for dt, metrics_file in items.items():
            data['time'].append(dt)
            with open(metrics_file, 'rt') as f:
                metrics, types = parse_metrics(f, nick, metrics_names, args.diff)
                for metric_name, metric_value in metrics.items():
                    raw_value = metric_value
                    if metric_name not in data:
                        data[metric_name] = []
                        raw_series[metric_name] = []
                    if types[metric_name] == TYPE_COUNTER:
                        if len(raw_series[metric_name]) > 0:
                            metric_value = (metric_value - raw_series[metric_name][-1]) / (dt - data['time'][-2]).total_seconds()
                        else:
                            metric_value = 0
                    data[metric_name].append(metric_value)
                    raw_series[metric_name].append(raw_value)

                    active_metrics.add(metric_name)

        for i, metric in enumerate(sorted(active_metrics)):
            fig.append_trace(go.Scatter(
                x=data['time'],
                y=data[metric],
                name=metric,
                mode='lines+markers',
                line=dict(width=1),
            ), i+1, 1)

    if args.save:
        fig.write_image(os.path.join(args.dir, default_output_file))
    else:
        fig.show()

    # app.run_server(debug=True)
    return 0

if __name__ == '__main__':
    sys.exit(main())