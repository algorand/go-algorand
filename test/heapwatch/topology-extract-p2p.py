"""
P2P network topology extraction script from node.log files.

1. Run P2P scenario like scenario1s-p2p
2. Fetch logs with `algonet play fetch_node_logs`
3. Extract logs
```
cd nodelog
find . -name 'nodelog.tar.gz' -print | xargs -I{} tar -zxf {}
```
4. Run this script `python3 topology-extract-p2p.py -o top.json nodelog`
5. Run the visualizer `topology-viz.py top.json`
"""
import argparse
import json
import re
import os
import sys

# Regex patterns to find node IDs and connections
node_pattern = r"P2P host created: peer ID (\w{52})"
edge_pattern = r"Made outgoing connection to peer (\w{52})"

ap = argparse.ArgumentParser()
ap.add_argument('log_dir_path', help='logs directory path')
ap.add_argument('-o', '--output', type=argparse.FileType('wt', encoding='utf-8'), help=f'save topology to the file specified instead of showing it')

args = ap.parse_args()

# Directory containing log files
log_dir_path = args.log_dir_path

nodes = []
edges = []
mapping = {}

# Iterate through all files in the specified directory
for filename in os.listdir(log_dir_path):
    if filename.endswith("-node.log"):
        with open(os.path.join(log_dir_path, filename), 'r') as file:
            mapped = filename[:len(filename) - len('-node.log')]
            mapped = mapped.replace('relay', 'R')
            mapped = mapped.replace('nonParticipatingNode', 'NPN')
            mapped = mapped.replace('node', 'N')
            node_id = None
            for line in file:
                # Check if line contains relevant substrings before parsing as JSON
                if "P2P host created" in line or "Made outgoing connection to peer" in line:
                    data = json.loads(line.strip())
                    
                    # Check for node creation
                    if "P2P host created" in data.get("msg", ""):
                        match = re.search(node_pattern, data["msg"])
                        if match:
                            node_id = match.group(1)
                            nodes.append(node_id)
                            mapping[node_id] = mapped
                    
                    # Check for connections
                    elif "Made outgoing connection to peer" in data.get("msg", ""):
                        match = re.search(edge_pattern, data["msg"])
                        if match:
                            target_node_id = match.group(1)
                            match = re.findall(r"/p2p/(\w{52})", data["local"])
                            if match:
                                source_node_id = match[0]
                            else:
                                print('WARN: no local addr set', data, file=sys.stderr)
                                source_node_id = node_id
                            edges.append((source_node_id, target_node_id))

result = {
    "mapping": mapping,
    "nodes": nodes,
    "edges": edges
}

if args.output:
    json.dump(result, args.output, indent=2)
else:
    json.dump(result, sys.stdout, indent=2)
    print(file=sys.stdout)
