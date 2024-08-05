"""
WSNet network topology extraction script from e2e test output single log file.

1. Save the e2e test output to a file
It starts with a line like this:
libgoalFixture.go:374: ===================...
libgoalFixture.go:376: Relay0/node.log:
libgoalFixture.go:379: {"file":"server.go"...

OR like this:
=================================
Relay0/node.log:
{"file":"server.go","function":"gi...

2. Run this script `python3 topology-extract-ws-e2e.py -o top.json e2e-test.log
3. Run the visualizer `topology-viz.py top.json`
"""
import argparse
from datetime import datetime
import json
import logging
import re
import sys
from typing import Dict, List

logger = logging.getLogger(__name__)


def node_name_from_line(line: str):
    """Extracts node name from the line like "libgoalFixture.go:376: Relay0/node.log:"""
    pattern = r'([^:]+?)/node\.log'
    match = re.search(pattern, line)
    if match:
        return match.group(1).strip()
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log_file', help='log file path')
    ap.add_argument('-o', '--output', type=argparse.FileType('wt', encoding='utf-8'), help=f'save topology to the file specified instead of showing it')
    ap.add_argument('-t', '--timestamp', action='store_true', help=f'store connection timestamp for each edge')
    args = ap.parse_args()

    log_file = args.log_file

    nodes: List[str] = []
    edges: List[List[str]] = []
    mapping: Dict[str, str] = {}

    addr_to_name = {}
    with open(log_file, 'rt', encoding='utf-8') as file:
        line0 = None
        while not line0:
            line0 = file.readline()
            line0 = line0.strip()

        node_name = None
        if line0.endswith('node.log:'):
            node_name = node_name_from_line(line0)
            logger.info('found node name: \'%s\'', node_name)
        for line in file:
            line = line.strip()
            if line.endswith('node.log:'):
                node_name = node_name_from_line(line)
                logger.info('found node name: \'%s\'', node_name)
            if node_name:
                nodes.append(node_name)
                for line in file:
                    json_start = line.find('{')
                    if json_start == -1:
                        # end of continuous json block
                        node_name = None
                        break
                    line = line[json_start:]

                    if "serving genesisID" in line:
                        data = json.loads(line.strip())
                        match = re.search(r'(?:http://)?(\d+\.\d+\.\d+\.\d+:\d+)', data['msg'])
                        if match:
                            addr = match.group(1)
                            addr_to_name[addr] = node_name

                    # Check if line contains relevant substrings before parsing as JSON
                    if "Accepted incoming connection from peer" in line or "Made outgoing connection to peer" in line:
                        data = json.loads(line.strip())

                        # Check for incoming connections
                        if "Accepted incoming connection from peer" in data.get("msg", ""):
                            remote = data['remote']
                            match = re.search(r'(?:http://)?(\d+\.\d+\.\d+\.\d+:\d+)', remote)
                            remote_addr = match.group(1)
                            remote_name = remote_addr
                            if resolved := addr_to_name.get(remote_addr):
                                remote_name = resolved
                            source = remote_name
                            target = node_name
                            if args.timestamp:
                                # datetime is not serializable, so we store it as string for now
                                edge = (source, target, {'dt': data["time"]})
                            else:
                                edge = (source, target)

                        # Check for outgoing connections
                        elif "Made outgoing connection to peer" in data.get('msg', ""):
                            remote_addr = data['remote']
                            remote_name = remote_addr
                            if resolved := addr_to_name.get(remote_addr):
                                remote_name = resolved
                            target = remote_name
                            source = node_name

                            if args.timestamp:
                                # datetime is not serializable, so we store it as string for now
                                edge = (source, target, {'dt': data["time"]})
                            else:
                                edge = (source, target)

                            edges.append(edge)

    # apply names that were learned from the logs
    for i, edge in enumerate(edges):
        e0 = edge[0]
        e0 = addr_to_name.get(e0, e0)
        e1 = edge[1]
        e1 = addr_to_name.get(e1, e1)
        if len(edge) == 3:
            edge = (e0, e1, edge[2])
        else:
            edge = (e0, e1)
        edges[i] = edge

    orig_nodes = set(nodes)
    # remap non-canonical names (like poorNode) and non-resolved ip addresses to some nodes
    for i, node in enumerate(nodes):
        if not node.startswith(('N', 'R', 'NPN')):
            nodes[i] = 'N-' + node

    # remove non-resolved ip addresses from edges - most likely these N, NPN already counted
    # because both nodes and relays logs are processed
    trimmed_edges = []
    for i, edge in enumerate(edges):
        e0 = edge[0]
        e1 = edge[1]
        if e0 not in orig_nodes or e1 not in orig_nodes:
            # some non-resolved ip address, skip
            continue

        if not e0.startswith(('N', 'R', 'NPN')):
            e0 = 'N-' + e0
        if not e1.startswith(('N', 'R', 'NPN')):
            e1 = 'N-' + e1

        if len(edge) == 3:
            edge = (e0, e1, edge[2])
        else:
            edge = (e0, e1)
        trimmed_edges.append(edge)

    result = {
        "mapping": mapping,
        "nodes": nodes,
        "edges": trimmed_edges
    }

    if args.timestamp and not args.output:
        edges = sorted(edges, key=lambda x: x[2]['dt'])
        for edge in edges:
            ts = datetime.strptime(edge[2]['dt'], "%Y-%m-%dT%H:%M:%S.%f%z")
            print('%15s %5s -> %-5s' % (ts.strftime('%H:%M:%S.%f'), edge[0], edge[1]))
        return

    if args.output:
        json.dump(result, args.output, indent=2)
    else:
        json.dump(result, sys.stdout, indent=2)
        print(file=sys.stdout)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
