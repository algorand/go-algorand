"""
P2P network topology visualization script.
See p2p-topology-extract.py for details.
"""

import json
import sys

import gravis as gv
import networkx as nx

topology_filename = sys.argv[1]

with open(topology_filename, 'rt') as f:
    topology = json.load(f)

# Create a new directed graph
G = nx.DiGraph()

G.add_edges_from(topology['edges'])
nx.relabel_nodes(G, topology['mapping'], copy=False)

# Set node colors
for node in G:
    if node.startswith('R'):
        G.nodes[node]['color'] = 'red'
    elif node.startswith('NPN'):
        G.nodes[node]['color'] = 'blue'
    elif node.startswith('N'):
        G.nodes[node]['color'] = 'green'
    else:
        raise RuntimeError(f"Unknown node type: {node}")

# Calculate in-degrees
in_degrees = dict(G.in_degree())
out_degrees = dict(G.out_degree())

for node in G:
    size = max(2, in_degrees[node])
    G.nodes[node]['size'] = size
    G.nodes[node]['in_degree'] = in_degrees[node]
    G.nodes[node]['out_degree'] = out_degrees[node]
    G.nodes[node]['hover'] = f'In: {in_degrees[node]}, Out: {out_degrees[node]}'

res = gv.d3(
    G,
    node_hover_tooltip=True,
    node_size_data_source='size',
    node_label_size_factor=0.5,
    use_node_size_normalization=True,
    node_size_normalization_max=20,
    use_edge_size_normalization=True,
    edge_curvature=0.1
    )

res.display()
