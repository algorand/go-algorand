import simplejson
import math
import subprocess

def build_network(template):
    with open(template) as f:
        template_dict = simplejson.load(f)

    topology = build_topology(template_dict)

    with open('generated/topology.json', 'w') as topology_file:
        simplejson.dump(topology, topology_file, indent=4)

    netgoal_params = build_netgoal_params(template_dict)
    build_net(netgoal_params)
    build_genesis(netgoal_params)

def build_netgoal_params(template_dict):
    instances = template_dict['instances']

    relay_count = 0
    participating_node_count = 0
    non_participating_node_count = 0

    for group in template_dict['groups']:
        relay_count += getInstanceCount(instances['relays'], group['percent']['relays'])
        participating_node_count += getInstanceCount(instances['participatingNodes'], group['percent']['participatingNodes'])
        non_participating_node_count += getInstanceCount(instances['nonParticipatingNodes'], group['percent']['nonParticipatingNodes'])
    

    relay_config = instances['relays']['config']
    participating_node_config = instances['participatingNodes']['config']
    non_participating_node_config = instances['nonParticipatingNodes']['config']

    wallets_count = template_dict['network']['wallets']
    nodes_count = template_dict['network']['nodes']

    return [
        '-w', str(wallets_count),
        '-R', str(relay_count),
        '-N', str(participating_node_count),
        '-H', str(non_participating_node_count),
        '-n', str(nodes_count),
        '--relay-template', relay_config,
        '--node-template', participating_node_config,
        '--non-participating-node-template', non_participating_node_config
    ]

def build_net(netgoal_params):
    args = [
        '-t', 'net',
        '-o', 'generated/net.json'
    ]
    args.extend(netgoal_params)
    netgoal(args)

def build_genesis(netgoal_params):
    args = [
        '-t', 'genesis',
        '-o', 'generated/genesis.json'
    ]
    args.extend(netgoal_params)
    netgoal(args)

def netgoal(args):
    cmd = [
        'netgoal', 'generate',
        '-r', '/dev/null'
    ]
    cmd.extend(args)
    subprocess.run(cmd)

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


build_network('./network-tpl.json')
