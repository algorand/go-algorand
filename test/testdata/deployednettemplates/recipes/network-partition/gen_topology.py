import random

node_types = {"R":8, "N":20, "NPN":2}
node_size = {"R":"-m5d.4xl", "N":"-m5d.4xl", "NPN":"-m5d.4xl"}
partitions = {"A":50, "B":20, "C":10, "D":10, "E":5, "F":5}
regions = [
    "AWS-US-EAST-2",
    "AWS-US-WEST-1"
]

def gen_topology(ranges):
    f = open("topology.json", "w")
    f.write("{ \"Hosts\":\n  [")
    node_groups = {}

    region_count = len(regions)
    first = True
    for  x in node_types:
        node_type = x
        node_count = node_types[x]
        region_size = node_size[x]
        for i in range(node_count):
            node_name = node_type + str(i+1)
            region = regions[i%region_count]
            # randomly assign the node to a partition
            partition = get_partition(ranges)
            node_groups.setdefault(partition,[]).append(node_name);
            if (first ):
                first = False
            else:
                f.write(",")
            f.write ("\n    {\n      \"Name\": \"" + node_name + "\",\n      \"Group\": \"" + partition + "\",\n      \"Template\": \"" + region + region_size + "\"\n    }"  )

    f.write("\n  ]\n}\n")
    f.close()

    for node_group in node_groups:
        f = open("group_" + node_group + ".txt", "w")
        for node in node_groups[node_group]:
            f.write(node +"\n")
        f.close()


def get_partition(ranges):
    random_value = random.randint(1,100)
    for partition_name  in ranges:
        partition_value = ranges[partition_name]
        if random_value >= partition_value['start']  and random_value <= partition_value['end'] :
            return partition_name
    print("error, partition not found for random_value ", random_value)
    exit(1)

def get_ranges():
    ranges = {}
    start_pos = 1;
    for name, size in partitions.items():
        if (start_pos > 100) :
            print("error, range exceeded 100")
            exit(1)
        end_pos = start_pos + size - 1
        ranges[name] = {"start": start_pos, "end": end_pos}
        start_pos = end_pos + 1
    print(ranges)
    return ranges


# create the group ranges based on group percent size
ranges = get_ranges()

# gen the topology.json file based and assign groups
gen_topology(ranges)
