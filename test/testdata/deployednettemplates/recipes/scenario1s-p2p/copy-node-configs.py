"""
Copies node.json, relay.json and nonPartNode.json from scenario1s:
1. Append \"EnableP2P\": true to all configs
2. Set P2PBootstrap: true to relay.json
"""

import json
import os

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
SCENARIO1S_DIR = os.path.join(CURRENT_DIR, "..", "scenario1s")

def main():
    """main"""
    with open(os.path.join(SCENARIO1S_DIR, "node.json"), "r") as f:
        node = json.load(f)
    with open(os.path.join(SCENARIO1S_DIR, "relay.json"), "r") as f:
        relay = json.load(f)
    with open(os.path.join(SCENARIO1S_DIR, "nonPartNode.json"), "r") as f:
        non_part_node = json.load(f)

    # make all relays P2PBootstrap'able
    relay["P2PBootstrap"] = True

    # enable P2P for all configs
    for config in (node, relay, non_part_node):
        override = config.get("ConfigJSONOverride")
        if override:
            override_json = json.loads(override)
            override_json["EnableP2P"] = True
            config["ConfigJSONOverride"] = json.dumps(override_json)
        altconfigs = config.get("AltConfigs", [])
        if altconfigs:
            for i, altconfig in enumerate(altconfigs):
                override = altconfig.get("ConfigJSONOverride")
                if override:
                    override_json = json.loads(override)
                    override_json["EnableP2P"] = True
                    altconfigs[i]["ConfigJSONOverride"] = json.dumps(override_json)
            config["AltConfigs"] = altconfigs

    with open("node.json", "w") as f:
        json.dump(node, f, indent=4)
    with open("relay.json", "w") as f:
        json.dump(relay, f, indent=4)
    with open("nonPartNode.json", "w") as f:
        json.dump(non_part_node, f, indent=4)

    print("Done!")

if __name__ == '__main__':
    main()