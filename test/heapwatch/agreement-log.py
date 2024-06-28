"""
Agreement logs parser, takes either separate node.log files from a directory and guessing names from the file names,
or parses the e2e test failure log file watching for node names as "    libgoalFixture.go:376: Relay0/node.log:" strings.

This tool similar a bit to carpenter but takes multiple log files at once.
To force colors when outputting to a file, set FORCE_COLOR=1 in the environment.
"""

import argparse
from datetime import datetime, timedelta
import glob
import json
import logging
import os
import time

from termcolor import COLORS, colored

logger = logging.getLogger(__name__)

filtered_events = frozenset(['Persisted'])

def process_json_line(line: str, node_name: str, by_node: dict, events: list):
    """Handles a single line of json log file, returns parsed event or None if it's not an agreement event.

    line is a single line of json log file.
    node_name is a name of the node that produced this line.
    by_node is dict with unique nodes meta information.
    events is a list of all parsed events. It is appended in this function to keep the caller code clean.
    """
    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        logger.error('failed to parse json: %s', line)
        return None
    if evt.get('Context') == 'Agreement' and evt.get('Type'):
        if evt['Type'] in filtered_events:
            return None
        dt = datetime.strptime(evt['time'], '%Y-%m-%dT%H:%M:%S.%f%z')
        sender = evt.get('Sender')
        sender = sender[:12] if sender else ''
        h = evt.get('Hash')
        h = h[:8] if h else ''
        w = evt.get('Weight', '-') if not evt['Type'].startswith('Proposal') else ' '
        wt = evt.get('WeightTotal', '-') if not evt['Type'].startswith('Proposal') else ' '
        if evt['Type'] in ('StepTimeout', 'VoteAttest', 'BlockAssembled', 'BlockPipelined'):
            w, wt = ' ', ' '
        result = {
            'time': dt,
            'type': evt.get('Type'),
            'round': evt.get('Round', '-'),
            'period': evt.get('Period', '-'),
            'step': evt.get('Step', '-'),
            'object_round': evt.get('ObjectRound', '-'),
            'object_period': evt.get('ObjectPeriod', '-'),
            'object_step': evt.get('ObjectStep', '-'),
            'hash': h,
            'sender': sender,
            'weight': w,
            'weight_total': wt,
            'node': node_name,
        }
        events.append(result)
        metadata = by_node.get(node_name)
        if not metadata:
            metadata = {
                'type': evt.get('Type'),
                'time': dt
            }
            by_node[node_name] = metadata
        else:
            if evt.get('Type') == 'RoundConcluded':
                rt = dt - metadata['time']
                result['round_time_ms'] = rt / timedelta(milliseconds=1)
            elif evt.get('Type') == 'RoundStart':
                metadata['time'] = dt
                metadata['type'] = 'RoundStart'
                by_node[node_name] = metadata

        return result
    return None

def main():
    os.environ['TZ'] = 'UTC'
    time.tzset()

    ap = argparse.ArgumentParser()
    ap.add_argument('test_log_or_dir', help='Dir with log files or a single log file from e2e tests')
    ap.add_argument('-e', '--end-round', type=int, help=f'Round to end at')
    args = ap.parse_args()

    by_node = {}
    events = []
    if os.path.isdir(args.test_log_or_dir):
        logger.info('processing directory %s', args.test_log_or_dir)
        log_files = sorted(glob.glob(os.path.join(args.test_log_or_dir, '*-node.log')))
        if not log_files:
            logger.error('no log files found in %s', args.test_log_or_dir)
            return 1
        for filename in os.listdir(args.test_log_or_dir):
            if filename.endswith("-node.log"):
                with open(os.path.join(args.test_log_or_dir, filename), 'r') as file:
                    node_name = filename[:len(filename) - len('-node.log')]
                    node_name = node_name.replace('relay', 'R')
                    node_name = node_name.replace('nonParticipatingNode', 'NPN')
                    node_name = node_name.replace('node', 'N')
                    for line in file:
                        event = process_json_line(line, node_name, by_node, events)
                        if event and args.end_round and \
                            isinstance(event['round'], int) and event['round'] >= args.end_round:
                            break

    else:
        logger.info('processing file %s', args.test_log_or_dir)
        with open(args.test_log_or_dir, 'r') as file:
            line0 = None
            while not line0:
                line0 = file.readline()
                line0 = line0.strip()

            if line0[0] == '{':
                # regular json line
                node_name = 'node'
                process_json_line(line, node_name, by_node, events)
                for line in file:
                    line = line.strip()
                    event = process_json_line(line, node_name, by_node, events)
                    if event and args.end_round and \
                        isinstance(event['round'], int) and event['round'] >= args.end_round:
                        break
            else:
                # looks like e2e test output with lines line this:
                """
                    libgoalFixture.go:374: ===================...
                    libgoalFixture.go:376: Relay0/node.log:
                    libgoalFixture.go:379: {"file":"server.go"...
                """
                node_name = None
                if line0.endswith('node.log:'):
                    node_name = line0.split(' ')[1].split('/')[0]
                    logger.info('found node name: %s', node_name)
                for line in file:
                    line = line.strip()
                    if line.endswith('node.log:'):
                        node_name = line.split(' ')[1].split('/')[0]
                        logger.info('found node name: %s', node_name)
                    if node_name:
                        for line in file:
                            json_start = line.find('{')
                            if json_start == -1:
                                # end of continuous json block
                                node_name = None
                                break
                            line = line[json_start:]
                            event = process_json_line(line, node_name, by_node, events)
                            if event and args.end_round and \
                                isinstance(event['round'], int) and event['round'] >= args.end_round:
                                break

    log = sorted(events, key=lambda x: x['time'])

    # num_nodes = len(by_node)
    colors = list(COLORS)
    colors = colors[colors.index('light_grey'):]
    if len(colors) < len(by_node):
        colors = colors * (len(by_node) // len(colors) + 1)
    node_color = {k: v for k, v in zip(by_node.keys(), colors)}

    fmt = '%15s (%s,%s,%s) (%s,%s,%s) %4s|%-4s %-8s %-18s %8s %12s %5s'
    print(fmt % ('TS', 'R', 'P', 'S', 'r', 'p', 's', 'W', 'WT', 'NODE', 'EVENT TYPE', 'HASH', 'SENDER', 'RT ms'))
    for e in log:
        color = node_color[e['node']]
        text = colored(fmt % (
                e['time'].strftime('%H:%M:%S.%f'),
                e['round'], e['period'], e['step'],
                e['object_round'], e['object_period'], e['object_step'],
                e['weight'], e['weight_total'],
                e['node'][:8],
                e['type'], e['hash'], e['sender'],
                int(e['round_time_ms']) if 'round_time_ms' in e else ''),
            color,
        )
        print(text)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
