"""
P2P network topology extraction script from node.log files.

1. Run P2P scenario like scenario1s-p2p
2. Fetch logs with `algonet play fetch_node_logs`
3. Extract logs
```
cd nodelog
find . -name 'nodelog.tar.gz' -print | xargs -I{} tar -zxf {}
rm *-host.log
```
4. Run this script `python3 p2p-topology-extract.py nodelog`
5. Save the result json and copy run p2p-topology-vis.py with it.
"""

import json
import re
import os
import sys

# Regex patterns to find node IDs and connections
node_pattern = r"P2P host created: peer ID (\w{52})"
edge_pattern = r"Made outgoing connection to peer (\w{52})"

# Directory containing log files
log_dir_path = sys.argv[1]

nodes = []
edges = []
mapping = {}

# Iterate through all files in the specified directory
for filename in os.listdir(log_dir_path):
    if filename.endswith(".log"):
        with open(os.path.join(log_dir_path, filename), 'r') as file:
            mapped = filename[:len(filename) - len('-node.log')]
            mapped = mapped.replace('relay', 'R')
            mapped = mapped.replace('nonParticipatingNode', 'NPN')
            mapped = mapped.replace('node', 'N')
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
                    if "Made outgoing connection to peer" in data.get("msg", ""):
                        match = re.search(edge_pattern, data["msg"])
                        if match:
                            target_node_id = match.group(1)
                            source_node_id = re.findall(r"/p2p/(\w{52})", data["local"])[0]
                            edges.append((source_node_id, target_node_id))

result = {
    "mapping": mapping,
    "nodes": nodes,
    "edges": edges
}
json.dump(result, sys.stdout, indent=2)
print(file=sys.stdout)
