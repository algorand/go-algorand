import json

node_types = {"RN": 5}
node_size = {"RN": "-m5d.4xl"}
regions = [
    "AWS-US-EAST-1",
    "AWS-US-WEST-2",
    "AWS-SA-EAST-1",
    "AWS-EU-NORTH-1",
    "AWS_AP_SOUTHEAST-2"
]
network = "DevNet"

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
    f.write(json.dumps(ec2_hosts, indent = 2))
