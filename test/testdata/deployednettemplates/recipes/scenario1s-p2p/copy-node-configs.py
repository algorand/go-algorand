"""
Copies node.json, relay.json and nonPartNode.json from scenario1s:
1. Append \"EnableP2P\": true to all configs
2. Set P2PBootstrap: true to relay.json
3. Set DNSSecurityFlags: 0 to all configs
"""

import argparse
import copy
import json
import os

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
SCENARIO1S_DIR = os.path.join(CURRENT_DIR, "..", "scenario1s")

def make_p2p_net(*args):
    """convert config to a pure p2p network"""
    for config in args:
        override_json = json.loads(config.get("ConfigJSONOverride", "{}"))
        override_json["EnableP2P"] = True
        override_json["DNSSecurityFlags"] = 0x8000  # set to some unused value otherwise 0 would be migrated to default that enables DNSSEC
        config["ConfigJSONOverride"] = json.dumps(override_json)

        net_address = config.get("NetAddress")
        if net_address:
            config["P2PBootstrap"] = True
        altconfigs = config.get("AltConfigs", [])
        if altconfigs:
            for i, altconfig in enumerate(altconfigs):
                override_json = json.loads(altconfig.get("ConfigJSONOverride", "{}"))
                override_json["EnableP2P"] = True
                override_json["DNSSecurityFlags"] = 0x8000  # set to some unused value otherwise 0 would be migrated to default that enables DNSSEC
                altconfigs[i]["ConfigJSONOverride"] = json.dumps(override_json)
            config["AltConfigs"] = altconfigs


def make_hybrid_p2p_net(*args):
    """convert config to a hybrid p2p network:
      - half of relays become hybrid and receive public address
      - half of non-relay nodes become hybrid
      - AltConfigs are used for hybrid nodes with FractionApply=0.5
      - Only one AltConfigs is supported and its FractionApply is forced to 0.5
    """
    for config in args:
        override_json = json.loads(config.get("ConfigJSONOverride", "{}"))
        override_json["EnableP2P"] = True
        override_json["DNSSecurityFlags"] = 0x8000  # set to some unused value otherwise 0 would be migrated to default that enables DNSSEC
        config["ConfigJSONOverride"] = json.dumps(override_json)

        net_address = config.get("NetAddress")
        if net_address:
            config["P2PBootstrap"] = True

        altconfigs = config.get("AltConfigs")
        altconfig = None
        if altconfigs:
            altconfig = altconfigs[0]
        else:
            altconfig = copy.deepcopy(config)

        override_json = json.loads(altconfig.get("ConfigJSONOverride", "{}"))
        override_json["EnableP2PHybridMode"] = True
        override_json["DNSSecurityFlags"] = 0x8000  # set to some unused value otherwise 0 would be migrated to default that enables DNSSEC
        altconfig["ConfigJSONOverride"] = json.dumps(override_json)
        if net_address:  # relay, set public address
            altconfig["P2PBootstrap"] = True
            altconfig["P2PNetAddress"] = "{{NetworkPort2}}"
            altconfig["PublicAddress"] = True
        altconfig['FractionApply'] = 0.5

        altconfigs = [altconfig]
        config["AltConfigs"] = altconfigs


def make_hybrid_ws_net(*args):
    """convert config to a hybrid ws network:
      - half of relays become hybrid and receive public address
      - half of non-relay nodes become hybrid
      - AltConfigs are used for hybrid nodes with FractionApply=0.5
      - Only one AltConfigs is supported and its FractionApply is forced to 0.5
    """
    for config in args:
        override_json = json.loads(config.get("ConfigJSONOverride", "{}"))
        override_json["DNSSecurityFlags"] = 0x8000  # set to some unused value otherwise 0 would be migrated to default that enables DNSSEC
        config["ConfigJSONOverride"] = json.dumps(override_json)

        net_address = config.get("NetAddress")
        altconfigs = config.get("AltConfigs")
        altconfig = None
        if altconfigs:
            altconfig = altconfigs[0]
        else:
            altconfig = copy.deepcopy(config)

        override_json = json.loads(altconfig.get("ConfigJSONOverride", "{}"))
        override_json["EnableP2PHybridMode"] = True
        override_json["DNSSecurityFlags"] = 0x8000  # set to some unused value otherwise 0 would be migrated to default that enables DNSSEC
        altconfig["ConfigJSONOverride"] = json.dumps(override_json)
        if net_address:  # relay, set public address
            altconfig["P2PBootstrap"] = True
            altconfig["P2PNetAddress"] = "{{NetworkPort2}}"
            altconfig["PublicAddress"] = True
        altconfig['FractionApply'] = 0.5

        altconfigs = [altconfig]
        config["AltConfigs"] = altconfigs


def main():
    """main"""
    ap = argparse.ArgumentParser()
    ap.add_argument('--hybrid', type=str, help='Hybrid mode: p2p, ws')
    args = ap.parse_args()

    hybrid_mode = args.hybrid
    if hybrid_mode not in ("p2p", "ws"):
        hybrid_mode = None

    print('Hybrid mode:', hybrid_mode)

    with open(os.path.join(SCENARIO1S_DIR, "node.json"), "r") as f:
        node = json.load(f)
    with open(os.path.join(SCENARIO1S_DIR, "relay.json"), "r") as f:
        relay = json.load(f)
    with open(os.path.join(SCENARIO1S_DIR, "nonPartNode.json"), "r") as f:
        non_part_node = json.load(f)

    # in p2p-only mode all relays are P2PBootstrap-able
    if not  hybrid_mode:
        make_p2p_net(node, relay, non_part_node)
    elif  hybrid_mode == 'p2p':
        make_hybrid_p2p_net(node, relay, non_part_node)
    elif  hybrid_mode == 'ws':
        make_hybrid_ws_net(node, relay, non_part_node)
    else:
        raise ValueError(f"Invalid hybrid mode: { hybrid_mode }")

    with open("node.json", "w") as f:
        json.dump(node, f, indent=4)
    with open("relay.json", "w") as f:
        json.dump(relay, f, indent=4)
    with open("nonPartNode.json", "w") as f:
        json.dump(non_part_node, f, indent=4)

    print("Done!")

if __name__ == '__main__':
    main()