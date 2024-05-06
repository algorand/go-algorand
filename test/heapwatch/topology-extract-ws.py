"""
WSNet network topology extraction script from node.log files.

1. Run cluster scenario like scenario1s
2. Fetch logs with `algonet play fetch_node_logs`
3. Extract logs
```
cd nodelog
find . -name 'nodelog.tar.gz' -print | xargs -I{} tar -zxf {}
```
4. Run this script `python3 topology-extract-ws.py ../terraform-inventory.json nodelog`
5. Save the result json and copy run topology-viz.py with it.
"""

import json
import re
import os
import sys

# Directory containing log files
inventory_file = sys.argv[1]
log_dir_path = sys.argv[2]

nodes = []
edges = []
mapping = {}

with open(inventory_file, 'rt') as f:
    inventory = json.load(f)

ip_to_name = {}
for k, v in inventory.items():
    if k.startswith('name_'):
        name = k.split('_')[1].upper()
        if not isinstance(v, list) or len(v) != 1:
            raise RuntimeError(f"Invalid inventory entry, expected a single item list: {k}={v}")
        ip = v[0]
        ip_to_name[ip] = name
        # no need for mapping but keep the data compatible with the topology-viz script
        mapping[name] = name

# Iterate through all files in the specified directory
for filename in os.listdir(log_dir_path):
    if filename.endswith('-node.log'):
        with open(os.path.join(log_dir_path, filename), 'r') as file:
            mapped = filename[:len(filename) - len('-node.log')]
            mapped = mapped.replace('relay', 'R')
            mapped = mapped.replace('nonParticipatingNode', 'NPN')
            mapped = mapped.replace('node', 'N')
            nodes.append(mapped)
            for line in file:
                # Check if line contains relevant substrings before parsing as JSON
                if "Accepted incoming connection from peer" in line or "Made outgoing connection to peer" in line:
                    data = json.loads(line.strip())
                    
                    # Check for incoming connections
                    if "Accepted incoming connection from peer" in data.get("msg", ""):
                        remote = data['remote']
                        remote_ip = remote.split(':')[0]
                        remote_name = ip_to_name[remote_ip]
                        source = remote_name
                        target = mapped
                        edges.append((source, target))

                    # Check for outgoing connections
                    elif "Made outgoing connection to peer" in data.get('msg', ""):
                        remote = data['remote']
                        name: str = remote.split('.')[0]
                        # check ip or name
                        if name.isdigit():
                            remote_ip = remote.split(':')[0]
                            remote_name = ip_to_name[remote_ip]
                            target = remote_name
                            source = mapped
                            edges.append((source, target))
                        else:
                            target = name.upper()
                            source = mapped
                            edges.append((source, target))

result = {
    "mapping": mapping,
    "nodes": nodes,
    "edges": edges
}
json.dump(result, sys.stdout, indent=2)
print(file=sys.stdout)
