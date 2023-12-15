#!/usr/bin/env python3
import json
import argparse
import math
import subprocess
import shutil
import os

def build_network(template):
    with open(template) as f:
        template_dict = json.load(f)

    template_path = os.path.abspath(os.path.dirname(args.template))
    script_path = os.path.dirname(__file__)
    topology = build_topology(template_dict)

    gen_dir = f"{template_path}/generated"
    if not os.path.isdir(gen_dir):
        os.mkdir(gen_dir)

    shutil.copy(f"{script_path}/recipe.json", f"{template_path}/recipe.json")

    with open(f"{template_path}/generated/topology.json", 'w') as topology_file:
        json.dump(topology, topology_file, indent=4)

    netgoal_params = build_netgoal_params(template_dict)
    build_net(template_path, netgoal_params)
    build_genesis(template_path, netgoal_params, template_dict)

def build_netgoal_params(template_dict):
    instances = template_dict['instances']

    relay_count = 0
    participating_instance_count = 0
    non_participating_instance_count = 0

    for group in template_dict['groups']:
        relay_count += getInstanceCount(instances['relays'], group['percent']['relays'])
        participating_instance_count += getInstanceCount(instances['participatingNodes'], group['percent']['participatingNodes'])
        non_participating_instance_count += getInstanceCount(instances['nonParticipatingNodes'], group['percent']['nonParticipatingNodes'])

    relay_config = instances['relays']['config']
    participating_node_config = instances['participatingNodes']['config']
    non_participating_node_config = instances['nonParticipatingNodes']['config']

    wallets_count = template_dict['network']['wallets']
    nodes_count = template_dict['network']['nodes']
    npn_count     =  template_dict['network']['npn']

    return [
        '-w', str(wallets_count),
        '-R', str(relay_count),
        '-N', str(participating_instance_count),
        '-X', str(non_participating_instance_count),
        '-n', str(nodes_count),
        '-x', str(npn_count),
        '--relay-template', relay_config,
        '--node-template', participating_node_config,
        '--non-participating-node-template', non_participating_node_config
    ]

def build_net(template_path, netgoal_params):
    args = [
        '-t', 'net',
        '-o', f"{template_path}/generated/net.json"
    ]
    args.extend(netgoal_params)
    netgoal(args, template_path)

def build_genesis(template_path, netgoal_params, template_dict):
    args = [
        '-t', 'genesis',
        '--last-part-key-round', str(100_000),
        '-o', f"{template_path}/generated/genesis.json"
    ]
    args.extend(netgoal_params)
    netgoal(args, template_path)
    if 'ConsensusProtocol' in template_dict['network']:
        updateProtocol(f"{template_path}/generated/genesis.json", template_dict['network']['ConsensusProtocol'])

def updateProtocol(genesis_path, consensus_protocol):
    with open(genesis_path, 'r') as genfile:
        genjson = json.load(genfile)
        genjson["ConsensusProtocol"] = consensus_protocol
    with open(genesis_path, 'w') as genfile:
        json.dump(genjson, genfile, indent="\t")

def netgoal(args, template_path='.'):
    cmd = [
        'netgoal', 'generate',
        '-r', '/dev/null'
    ]
    cmd.extend(args)
    subprocess.run(cmd, cwd=template_path)

def build_topology(template_dict):

    instances = template_dict['instances']
    groups = template_dict['groups']

    hosts = build_hosts(instances, groups)
    return {
        'Hosts': hosts
    }

def build_hosts(instances, groups):
    relays = []
    participating_nodes = []
    non_participating_nodes = []

    relay_cfg = instances['relays']
    participating_node_cfg = instances['participatingNodes']
    non_participating_node_cfg = instances['nonParticipatingNodes']

    for group in groups:
        for i in range(getInstanceCount(relay_cfg, group['percent']['relays'])):
            relays.append({
                "Name": f"R{len(relays) + 1}",
                "Group": group['name'],
                "Template": f"AWS-{group['region'].upper()}-{relay_cfg['type']}"
            })
        for i in range(getInstanceCount(participating_node_cfg, group['percent']['participatingNodes'])):
            participating_nodes.append({
                "Name": f"N{len(participating_nodes) + 1}",
                "Group": group['name'],
                "Template": f"AWS-{group['region'].upper()}-{participating_node_cfg['type']}"
            })
        for i in range(getInstanceCount(non_participating_node_cfg, group['percent']['nonParticipatingNodes'])):
            non_participating_nodes.append({
                "Name": f"NPN{len(non_participating_nodes) + 1}",
                "Group": group['name'],
                "Template": f"AWS-{group['region'].upper()}-{non_participating_node_cfg['type']}"
            })

    hosts = []
    hosts.extend(relays)
    hosts.extend(participating_nodes)
    hosts.extend(non_participating_nodes)
    return hosts

def getInstanceCount(instance, percent):
    if (percent == 0):
        return 0
    total_instance_count = instance['count']
    instance_count = math.floor(total_instance_count * percent / 100)
    return max(instance_count, 1)


def validate_template(template_dict):
    groups = template_dict['groups']
    total_percent = 0
    for group in groups:
        total_percent += groups['percent']
    if total_percent != 100:
        raise Exception(f"Total percentages of groups expected 100, got {total_percent}")

parser = argparse.ArgumentParser(
    description="",
)

parser.add_argument(
    '-f',
    '--template',
    help = 'Path to network template',
    required=True
)

args = parser.parse_args()

if os.path.isfile(args.template):
    build_network(args.template)
else:
    print(f"Expected --template option to be set with a path to a network template, was {args.template}")
    exit(2)
