node_types = {"R":30, "N":6, "NPN":5}
node_size = {"R":"-m5d.4xl", "N":"-m5d.4xl", "NPN":"-m5d.4xl"}
regions = [
    "AWS-AP-SOUTHEAST-1", 
    "AWS-EU-CENTRAL-1", 
    "AWS-AP-SOUTHEAST-2"
]

f = open("topology.json", "w")
f.write("{ \"Hosts\":\n  [")

region_count = len(regions)
first = True
for  x in node_types:
    node_type = x
    node_count = node_types[x]
    region_size = node_size[x]
    for i in range(node_count):
        node_name = node_type + str(i+1)
        if node_type == "N":
            region = "AWS-US-EAST-2"
        else:
            region = regions[i%region_count]
        if (first ):
            first = False
        else:
            f.write(",")
        f.write ("\n    {\n      \"Name\": \"" + node_name + "\",\n      \"Template\": \"" + region + region_size + "\"\n    }"  )

f.write("\n  ]\n}\n")
f.close()

