# scenario1s is scenario1 but smaller, (100 nodes, 100 wallets) -> (20 nodes, 20 wallets), each algod gets single tenancy on a smaller ec2 instance
node_types = {"R":8, "N":20, "NPN":10}
node_size = {"R":"-m5d.4xl", "N":"-m5d.2xl", "NPN":"-m5d.2xl"}
regions = [
    "AWS-US-EAST-2"
]

f = open("topology.json", "w")
f.write("{ \"Hosts\":\n  [")

region_count = len(regions)
first = True
for x in sorted(node_types.keys()):
    node_type = x
    node_count = node_types[x]
    region_size = node_size[x]
    for i in range(node_count):
        node_name = node_type + str(i+1)
        region = regions[i%region_count]
        if (first ):
            first = False
        else:
            f.write(",")
        f.write ("\n    {\n      \"Name\": \"" + node_name + "\",\n      \"Template\": \"" + region + region_size + "\"\n    }"  )

f.write("\n  ]\n}\n")
f.close()
