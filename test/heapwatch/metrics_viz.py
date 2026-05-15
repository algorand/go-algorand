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

from dash import Dash, dcc, html, Input, Output
import plotly.graph_objs as go
from plotly.subplots import make_subplots

from metrics_lib import MetricType, parse_metrics, gather_metrics_files_by_nick, parse_tags

logger = logging.getLogger(__name__)


def parse_all_metrics(filesByNick, metrics_names, raw_metrics, all_raw, tags, tag_keys, diff):
    """Parse every metrics file and transform values (rate vs raw) up front.

    Returns a dict keyed by nick:
        {nick: {
            'time':   [datetime, ...],                     # one entry per metrics file
            'series': {full_name: [float, ...]},           # transformed value series, aligned to 'time'
            'active': {metric_name: [full_name, ...]},     # full_names actually seen for each requested metric
        }}

    Doing this once (instead of per-Dash-callback) keeps the selector callback cheap.
    """
    parsed = {}
    for nick, files_by_date in filesByNick.items():
        active_metrics = {}
        data = {'time': []}
        raw_series = {}
        raw_times = {}
        # raw_indices[full_name][j] is the file-index (column in data[full_name]) at which
        # raw_series[full_name][j] was recorded. Needed to rewrite earlier samples in place
        # when a metric is discovered to be non-monotonic mid-stream.
        raw_indices = {}
        # Metrics exported as `# TYPE ... counter` but observed to decrease at least once.
        # Treated as gauges from the moment the decrease is seen.
        non_monotonic = set()
        idx = 0
        for dt, metrics_file in files_by_date.items():
            data['time'].append(dt)
            with open(metrics_file, 'rt') as f:
                metrics = parse_metrics(f, nick, metrics_names, diff)
                for metric_name, metrics_seq in metrics.items():
                    active_metric_names = []
                    for metric in metrics_seq:
                        raw_value = metric.value

                        if tags and not metric.has_tags(tags, tag_keys):
                            continue

                        full_name = metric.string()
                        if full_name not in data:
                            # handle gaps in data, sometimes metric file might miss a value
                            # but the chart requires matching x and y series (time and metric value)
                            # data is what does into the chart, and raw_series is used to calculate
                            data[full_name] = [0] * len(files_by_date)
                            raw_series[full_name] = []
                            raw_times[full_name] = []
                            raw_indices[full_name] = []

                        # If a "counter" metric decreases, it isn't actually monotonic —
                        # algod exports some gauge-like values (queue sizes, pool counts) as
                        # `# TYPE ... counter`. Rate-of-change for those is meaningless and
                        # plots near zero. On first decrease, flip the metric to gauge mode
                        # and rewrite previously-stored rate samples back to raw values so
                        # the whole series is consistent.
                        if (metric.type == MetricType.COUNTER
                                and full_name not in non_monotonic
                                and raw_series[full_name]
                                and raw_value < raw_series[full_name][-1]):
                            non_monotonic.add(full_name)
                            for j, prev_idx in enumerate(raw_indices[full_name]):
                                data[full_name][prev_idx] = raw_series[full_name][j]

                        metric_value = metric.value
                        if (metric.type == MetricType.COUNTER
                                and not all_raw
                                and full_name not in non_monotonic
                                and metric.name not in raw_metrics):
                            if len(raw_series[full_name]) > 0 and len(raw_times[full_name]) > 0:
                                metric_value = (metric_value - raw_series[full_name][-1]) / (dt - raw_times[full_name][-1]).total_seconds()
                            else:
                                metric_value = 0
                        # else: gauge, or counter that turned out to be non-monotonic — plot raw.

                        data[full_name][idx] = metric_value
                        raw_series[full_name].append(raw_value)
                        raw_times[full_name].append(dt)
                        raw_indices[full_name].append(idx)

                        active_metric_names.append(full_name)

                    if active_metric_names:
                        active_metric_names.sort()
                        active_metrics[metric_name] = active_metric_names
            idx += 1

        time_series = data.pop('time')
        parsed[nick] = {
            'time': time_series,
            'series': data,
            'active': active_metrics,
        }
    return parsed


def build_figure(selected_metric_names, parsed):
    """Build a Figure with one subplot row per metric name in selected_metric_names.

    Each Scatter trace is tagged with a legendgroup so that the legend acts as a
    per-metric selector in any output mode (static HTML, fig.show, or Dash) —
    `legend.groupclick = 'togglegroup'` makes clicking a legend entry toggle the
    whole group on/off.
    """
    selected = list(selected_metric_names)
    nrows = max(1, len(selected))

    # Plotly requires vertical_spacing < 1/(rows-1). 0.03 is a nice value for a handful of
    # rows but blows up past ~33 rows. Scale it down for tall figures.
    vertical_spacing = min(0.03, 0.5 / nrows) if nrows > 1 else 0.0

    fig = make_subplots(
        rows=nrows, cols=1,
        vertical_spacing=vertical_spacing, shared_xaxes=True,
        subplot_titles=selected if selected else [''],
    )
    fig['layout']['margin'] = {'l': 30, 'r': 10, 'b': 10, 't': 20}
    fig['layout']['height'] = 500 * nrows

    for nick_data in parsed.values():
        for i, metric_name in enumerate(selected):
            fullnames = nick_data['active'].get(metric_name)
            if not fullnames:
                continue
            for full_name in fullnames:
                fig.append_trace(go.Scatter(
                    x=nick_data['time'],
                    y=nick_data['series'][full_name],
                    name=full_name,
                    mode='lines+markers',
                    line=dict(width=1),
                    legendgroup=metric_name,
                    legendgrouptitle_text=metric_name,
                ), i+1, 1)

    # Per-trace toggling (default): clicking a legend entry toggles only that line, so users
    # can hide a single node's series within a metric. The dropdown selector handles the
    # whole-metric add/remove case, so we don't need legend groups to also act as toggles.
    fig.update_layout(legend=dict(groupclick='toggleitem'))
    return fig


def main():
    os.environ['TZ'] = 'UTC'
    time.tzset()
    default_img_filename = 'metrics_viz.png'
    default_html_filename = 'metrics_viz.html'

    ap = argparse.ArgumentParser()
    ap.add_argument('metrics_names', nargs='*', default=[], help='metric name(s) to track. If omitted, every metric found in the files is plotted')
    ap.add_argument('-d', '--dir', type=str, default=None, help='dir path to find /*.metrics in')
    ap.add_argument('-l', '--list-nodes', default=False, action='store_true', help='list available node names with metrics')
    ap.add_argument('--nick-re', action='append', default=[], help='regexp to filter node names, may be repeated')
    ap.add_argument('--nick-lre', action='append', default=[], help='label:regexp to filter node names, may be repeated')
    ap.add_argument('-s', '--save', type=str, choices=['png', 'html'], help=f'save plot to \'{default_img_filename}\' or \'{default_html_filename}\' file instead of showing it')
    ap.add_argument('--diff', action='store_true', default=None, help='diff two gauge metrics instead of plotting their values. Requires two metrics names to be set')
    ap.add_argument('--raw', action='append', default=[], help='metric name to plot as raw value (skip rate calculation). Useful for counters that should be shown as totals. May be repeated')
    ap.add_argument('--all-raw', action='store_true', default=False, help='plot all metrics as raw values (skip rate calculation for every counter)')
    ap.add_argument('-t', '--tags', action='append', default=[], help='tag/label pairs in a=b format to aggregate by, may be repeated. Empty means aggregation by metric name')
    ap.add_argument('--verbose', default=False, action='store_true')
    ap.add_argument('-p', '--port', type=int, default=False, help='port to run the Dash app on')
    ap.add_argument('--auth-user', type=str, default='admin', help='HTTP Basic Auth username (default: admin). Only meaningful with --port and when a password is set')
    ap.add_argument('--auth-password', type=str, default=None, help='HTTP Basic Auth password. If unset, the METRICS_VIZ_PASSWORD env var is used. If neither is set, no auth is required. NOTE: Basic Auth is plaintext over HTTP — use TLS or an SSH tunnel for untrusted networks')

    args = ap.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if not args.dir:
        logging.error('need at least one dir set with -d/--dir')
        return 1

    tags, tag_keys = parse_tags(args.tags)

    metrics_files = sorted(glob.glob(os.path.join(args.dir, '*.metrics')))
    metrics_files.extend(glob.glob(os.path.join(args.dir, 'terraform-inventory.host')))
    filesByNick = gather_metrics_files_by_nick(metrics_files, args.nick_re, args.nick_lre)

    if args.list_nodes:
        print('Available nodes:', ', '.join(sorted(filesByNick.keys())))
        return 0

    metrics_names = set(args.metrics_names)
    # Metrics the user wants plotted raw regardless of their `# TYPE` declaration.
    raw_metrics = set(args.raw)

    parsed = parse_all_metrics(
        filesByNick, metrics_names, raw_metrics, args.all_raw, tags, tag_keys, args.diff,
    )

    # Displayable metric names = whatever survived parsing and showed up in at least one nick.
    # With --diff this is the single synthetic name produced by parse_metrics; otherwise it's
    # the requested set (minus any that weren't present in the data), or — when the user
    # didn't pass any names on the CLI — every metric name discovered across all files.
    display_metric_names = sorted({m for n in parsed.values() for m in n['active']})
    if not display_metric_names:
        display_metric_names = sorted(metrics_names)

    # When the user explicitly listed metrics, render them all by default. When they didn't,
    # there can easily be hundreds of metrics — too many to render at once. Fall back to
    # "render on demand" via the Dash checklist (initial selection is empty), or refuse to
    # render in static modes since there's no selector there.
    if args.metrics_names:
        initial_selection = list(display_metric_names)
    elif args.port:
        initial_selection = []
        logging.info(
            'no metrics specified; %d metrics available in the checklist, none selected initially',
            len(display_metric_names),
        )
    else:
        logging.error(
            'no metrics specified and %d metrics found; either list metric names on the '
            'command line, or use --port for an interactive checklist',
            len(display_metric_names),
        )
        return 1

    initial_fig = build_figure(initial_selection, parsed)

    if args.save:
        if args.save == 'html':
            target_path = os.path.join(args.dir, default_html_filename)
            initial_fig.write_html(target_path)
        else:
            target_path = os.path.join(args.dir, default_img_filename)
            initial_fig.write_image(target_path)
        print(f'Saved plot to {target_path}')
    elif args.port:
        app = Dash(__name__)

        # Optional HTTP Basic Auth. CLI flag takes precedence over env var. Prefer the env
        # var so the password doesn't leak through `ps` / shell history.
        auth_password = args.auth_password or os.environ.get('METRICS_VIZ_PASSWORD')
        if auth_password:
            from flask import request, Response

            @app.server.before_request
            def _require_basic_auth():
                auth = request.authorization
                if auth and auth.username == args.auth_user and auth.password == auth_password:
                    return None
                return Response(
                    'Authentication required.', 401,
                    {'WWW-Authenticate': 'Basic realm="metrics_viz"'},
                )

            logging.info('HTTP Basic Auth enabled for user %r', args.auth_user)

        app.layout = html.Div([
            html.H4('Algod Metrics'),
            # Multi-select: subplot rows for unchecked metrics are removed entirely
            # by the callback (vs. the legend, which can only hide traces in place).
            # Multi-select dropdown with built-in text filter — much more usable than a
            # checklist when there are hundreds of metric names. Type to narrow, click to
            # add; selected chips show inline and can be removed individually.
            dcc.Dropdown(
                id='metric-selector',
                options=[{'label': m, 'value': m} for m in display_metric_names],
                value=initial_selection,
                multi=True,
                placeholder='Type to filter and select metrics...',
            ),
            dcc.Graph(id='graph', figure=initial_fig),
        ])

        @app.callback(Output('graph', 'figure'), Input('metric-selector', 'value'))
        def update_graph(selected):
            # Render exactly what's checked. Empty -> empty placeholder figure; do NOT
            # fall back to "everything" because that can be hundreds of metrics.
            return build_figure(sorted(selected or []), parsed)

        app.run_server(debug=args.verbose, host='0.0.0.0', port=args.port)
    else:
        initial_fig.show()

    return 0

if __name__ == '__main__':
    sys.exit(main())