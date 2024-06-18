import copy
import json
import os

node_types = {"R": 5, "N": 20, "NPN": 20, "NPX": 50}
nodes_per_npx = 10
node_size = {"R": "-c5d.4xl", "N": "-c5d.2xl", "NPN": "-Small", "NPX": "-Small"}
regions = {
    "R": [
        "AWS-US-EAST-1",
        "AWS-US-WEST-1",
        "AWS-SA-EAST-1",
        "AWS-EU-NORTH-1",
        "AWS-AP-SOUTHEAST-1"
    ],
    "N": [
        "AWS-US-EAST-2",
        "AWS-US-WEST-2",
        "AWS-CA-CENTRAL-1",
        "AWS-EU-WEST-2",
        "AWS-AP-SOUTHEAST-2"
    ],
    "NPN": [
        "AWS-US-EAST-2",
        "AWS-US-WEST-2",
        "AWS-CA-CENTRAL-1",
        "AWS-EU-WEST-2",
        "AWS-AP-SOUTHEAST-2"
    ],
    "NPX": [
        "AWS-US-EAST-2",
        "AWS-US-WEST-2",
        "AWS-CA-CENTRAL-1",
        "AWS-EU-WEST-2",
        "AWS-AP-SOUTHEAST-2"
    ]
}

network = "betanet-model-2"

host_elements = []
region_count = len(regions)
for node_type in node_types.keys():
    node_count = node_types[node_type]
    region_size = node_size[node_type]
    for i in range(node_count):
        host = {}
        node_name = node_type + str(i + 1) + "-" + network
        region = regions[node_type][i % region_count]
        host["Name"] = node_name
        host["Template"] = region + region_size
        host_elements.append(host)

ec2_hosts = {"Hosts": host_elements}
with open("topology.json", "w") as f:
    f.write(json.dumps(ec2_hosts, indent=2) + os.linesep)

npx_node = {'Wallets': [],
            'APIToken': "{{APIToken}}",
            'EnableTelemetry': False,
            'EnableMetrics': False,
            'EnableService': False,
            'EnableBlockStats': False,
            'ConfigJSONOverride':
"{ \"TxPoolExponentialIncreaseFactor\": 1, \
\"DNSBootstrapID\": \"<network>.algodev.network\", \
\"DeadlockDetection\": -1, \"BaseLoggerDebugLevel\": 4, \
\"CadaverSizeTarget\": 0  }"}

npx_count = node_types['NPX']
host_list = []
for x in range(1, npx_count + 1):
    host = {}
    host_name = 'NPX' + str(x) + '-' + network

    host['Name'] = host_name
    host['Group'] = ""
    host['Nodes'] = []
    for n in range(1, nodes_per_npx + 1):
        node_name = 'NPX' + str(x) + '-' + str(n) + '-' + network
        npx_node_1 = copy.deepcopy(npx_node)
        npx_node_1['Name'] = node_name
        host['Nodes'].append(npx_node_1)
    host_list.append(host)

with open("net-extension.json", "w") as f:
    f.write(json.dumps(host_list, indent=2) + os.linesep)
