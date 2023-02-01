#!/usr/bin/env python3
"""
generate_network_tpl.py

reads a network_performance_rules file and returns a network-tpl.json that can be used by generate_recipe.py.

v2 format:

    ```
    group1 group2 minrtt
    ```

    > group1 and group2 are referring to individual hosts (e.g. R1 and R2), so there should be one group per host.

"""
import argparse
import json
import math


DEFAULT_NETWORK_TPL = 'network-tpl.default.json'
DEFAULT_NUM_N = 5
DEFAULT_NUM_NPN = 5


def main():
    args = parse_args()

    # initialize network_tpl with defaults
    network_tpl = get_default_network_tpl()

    groups = []

    if args.network_rules_file is not None:
        network_tpl_from_rules = gen_network_tpl_from_rules_v2(args.network_rules_file)
        # merging overrides groups, so save the defaults before merging
        default_groups = network_tpl['groups']
        merge(network_tpl_from_rules, network_tpl)
        for v in default_groups:
            network_tpl['groups'].append(v)

    # write network_tpl to file
    with open(args.out, 'w') as out:
        out.write(json.dumps(network_tpl, indent=2))
        out.write('\n')


def parse_args():
    parser = argparse.ArgumentParser(
        description='Generate a network-tpl.json file for generate_network.py'
    )
    parser.add_argument('-n', '--network-rules-file', help='Path of network_performance_rules file', required=True)
    parser.add_argument('-o', '--out', help='Path to write output', default='network-tpl.json')
    return parser.parse_args()


def get_default_network_tpl():
    return {
        'network': {
            'wallets': 5
        },
        'instances': {
            'relays': {
                'config': './configs/relay.json',
                'type': 'c5.xlarge',
                'count': 5
            },
            'participatingNodes': {
                'config': './configs/node.json',
                'type': 'c5.xlarge',
                'count': 5
            },
            'nonParticipatingNodes': {
                'config': './configs/nonPartNode.json',
                'type': 'c5.xlarge',
                'count': 5
            }
        },
        'groups': [
            {
                'name': 'n',
                'percent': {
                    'relays': 0,
                    'nonParticipatingNodes': 100,
                    'participatingNodes': 100
                },
                'region': 'us-west-1'
            }
        ]
    }

    with open(DEFAULT_NETWORK_TPL) as default_tpl:
        return json.load(default_tpl)


def merge(source, destination):
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merge(value, node)
        else:
            destination[key] = value

    return destination


def gen_network_tpl_from_rules_v2(path):
    """
        Loads network_performance_rules v2 file, and generates a network-tpl.json file
        @param path: the filesystem path to the network_performance_rules file
        @return list of network-tpl.json groups
    """
    groups = []

    with open(path) as network_performance_rules:
        npr = network_performance_rules.readlines()

    found = []
    num_relays = 0
    num_npn = 0
    num_n = 0

    # loop over rules and get counts of types of instances
    for rule in npr:
        # algonet retrieves groups from terraform-inventory and they are lowercase
        name = rule.split(' ')[0].lower()
        relays = 0
        nonParticipatingNodes = 0
        participatingNodes = 0

        if name in found:
            continue

        found.append(name)

        if name.startswith('r'):
            num_relays += 1
        elif name.startswith('npn'):
            num_npn += 1
        else:
            num_n += 1

    if num_n == 0:
        num_n = DEFAULT_NUM_N

    if num_npn == 0:
        num_npn = DEFAULT_NUM_NPN

    for item in found:
        group = {'name': item}
        percent = {}
        if item.startswith('r'):
            percent = {
                'relays': math.ceil(1 / num_relays * 100),
                'nonParticipatingNodes': 0,
                'participatingNodes': 0
            }
        elif item.startswith('npn'):
            percent = {
                'relays': 0,
                'nonParticipatingNodes': math.ceil(1 / num_npn * 100),
                'participatingNodes': 0
            }
        else:
            percent = {
                'relays': 0,
                'nonParticipatingNodes': 0,
                'participatingNodes': math.ceil(1 / num_n * 100)
            }

        group['percent'] = percent
        group['region'] = 'us-west-1'

        groups.append(group)

    network = {
        'relays': num_relays,
        'nodes': num_n,
        'npn': num_npn
    }

    instances = {
        'relays': {
            'count': num_relays
        },
        'participatingNodes': {
            'count': num_n
        },
        'nonParticipatingNodes': {
            'count': num_npn
        }
    }

    return {
        'network': network,
        'instances': instances,
        'groups': groups
    }


if __name__ == '__main__':
    main()
