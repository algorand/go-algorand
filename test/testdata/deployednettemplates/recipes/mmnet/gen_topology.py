import json
import os

# the name of the topology file to write to
if "TOPOLOGY_FILE" in os.environ:
    TOPOLOGY_FILE = os.environ["TOPOLOGY_FILE"]
else:
    TOPOLOGY_FILE = "topology.json"

# the instance size of relays, nodes, and non-participating nodes
NODE_SIZES = {
    "R": "m5d.4xl",
    "N": "m5d.4xl",
    "NPN": "m5d.4xl"
}

# the default number of relays, nodes, or non-participating nodes if a region doesn't specify
REGION_DEFAULTS = {
    "R": 1,
    "N": 4,
    "NPN": 2
}

# mapping of regions and associated number of relays, nodes, and non-participating nodes
REGIONS = {
    "AWS-US-EAST-1": {      # Virginia, USA
        "R": 20,
        "NPN": 2,
        "N": 20
    },
    "AWS-US-EAST-2": {      # Ohio, USA
        "R": 20,
        "NPN": 2,
        "N": 20
    },
    "AWS-US-WEST-2": {      # Oregon, USA
        "R": 10,
        "NPN": 2,
        "N": 20
    },
    "AWS-CA-CENTRAL-1": {   # Canada
        "R": 6,
        "NPN": 1,
        "N": 5
    },
    "AWS-EU-CENTRAL-1": {   # Frankfurt, Germany
        "R": 10,
        "NPN": 2,
        "N": 10
    },
    "AWS-EU-WEST-1": {      # Ireland
        "R": 14,
        "NPN": 1,
        "N": 8
    },
    "AWS-EU-NORTH-1": {     # Stockholm, Sweden
        "R": 2,
        "NPN": 1,
        "N": 6
    },
    "AWS-EU-SOUTH-1": {     # Milan, Italy
        "R": 4,
        "NPN": 1,
        "N": 4
    },
    "AWS-AP-EAST-1": {      # Hong Kong, China
        "R": 5,
        "NPN": 2,
        "N": 10
    },
    "AWS-AP-SOUTH-1": {     # Mumbai, India
        "R": 3,
        "NPN": 1,
        "N": 2
    },
    "AWS-AP-SOUTHEAST-1": { # Singapore
        "R": 12,
        "NPN": 1,
        "N": 2
    },
    "AWS-AP-SOUTHEAST-2": { # Sydney, Australia
        "R": 4,
        "NPN": 1,
        "N": 4
    },
    "AWS-AP-NORTHEAST-2": { # Seoul, South Korea
        "R": 1,
        "NPN": 1,
        "N": 2
    },
    "AWS-AP-NORTHEAST-3": { # Osaka, Japan
        "R": 15,
        "NPN": 1,
        "N": 12
    },
    "AWS-ME-SOUTH-1": {     # Middle East
        "R": 2,
        "NPN": 1,
        "N": 2
    },
    "AWS-AF-SOUTH-1": {     # Cape Town, South Africa
        "R": 4,
        "NPN": 1,
        "N": 1
    },
    "AWS-SA-EAST-1": {      # Sao Paulo, Brazil
        "R": 4,
        "NPN": 1,
        "N": 4
    }
}


host_elements = []
region_count = len(REGIONS.keys())

# dict that keeps track of number of nodes
node_count = {
    "R": 0,
    "N": 0,
    "NPN": 0
}

for region in REGIONS.keys():

    # merge region-specific config with region defaults so that all values are set
    region_config = {**REGION_DEFAULTS, **REGIONS[region]}

    for node_type in region_config.keys():
        for i in range(region_config[node_type]):
            host = {}
            host["Name"] = f"{node_type}{node_count[node_type] + 1}"
            host["Template"] = f"{region}-{NODE_SIZES[node_type]}"
            host_elements.append(host)

            # increment counter for specific node_type
            node_count[node_type] += 1


ec2_hosts = {"Hosts": host_elements}
with open(TOPOLOGY_FILE, "w") as f:
    f.write(json.dumps(ec2_hosts, indent = 2) + os.linesep)
