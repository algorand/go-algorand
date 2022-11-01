import json
import os

node_types = {"R":5, "N":20, "NPN":10}
node_size = {"R":"-c5d.4xl", "N":"-c5d.2xl", "NPN":"-c5d.2xl"}
regions = [
    "AWS-US-EAST-1",
    "AWS-US-WEST-1",
    "AWS-SA-EAST-1",
    "AWS-EU-NORTH-1",
    "AWS-AP-SOUTHEAST-1"
]

network = "alphanet"

host_elements = []
region_count = len(regions)
for node_type in node_types.keys():
    node_count = node_types[node_type]
    region_size = node_size[node_type]
    for i in range(node_count):
        host = {}
        node_name = node_type + str(i + 1) + "-" + network
        region = regions[i % region_count]
        host["Name"] = node_name
        host["Template"] = region + region_size
        host_elements.append(host)

ec2_hosts = {"Hosts": host_elements}
with open("topology.json", "w") as f:
    f.write(json.dumps(ec2_hosts, indent = 2) + os.linesep)
