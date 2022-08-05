# scenario3s is scenario3 but smaller. (10000 wallets -> 500) (1000 algod participating nodes -> 100) It still keeps a global datacenter distribution.
node_types = {"R":20, "N":100, "NPN":15}
node_size = {"R":"-m5d.4xl", "N":"-m5d.2xl",  "NPN":"-m5d.4xl"}
regions = [
   "AWS-US-EAST-1",
   "AWS-US-WEST-2",
   "AWS-CA-CENTRAL-1",
   "AWS-AP-SOUTHEAST-1",
   "AWS-AP-SOUTHEAST-2",
   "AWS-EU-CENTRAL-1",
   "AWS-EU-WEST-2",
   "AWS-EU-WEST-3"
]

f = open("topology.json", "w")
f.write("{ \"Hosts\":\n  [")

region_count = len(regions)
first = True
for node_type in sorted(node_types.keys()):
  node_count = node_types[node_type]
  region_size = node_size[node_type]
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
