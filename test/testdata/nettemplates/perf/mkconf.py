#!/usr/bin/python

import json

d = {
  "Genesis": {
    "NetworkName": "tbd",
    "ConsensusProtocol": "test-big-blocks",
    "Wallets": [],
  },
  "Nodes": [],
}

nodes = 5
walletsPerNode = 10
for n in range(0, nodes):
  node = {
    "Name": "Node%d" % n,
    "Wallets": [],
    "DeadlockDetection": -1,
  }

  for w in range(0, walletsPerNode):
    node["Wallets"].append({
      "Name": "Wallet-%d-%d" % (n, w),
      "ParticipationOnly": False,
    })
    d["Genesis"]["Wallets"].append({
      "Name": "Wallet-%d-%d" % (n, w),
      "Online": True,
      "Stake": 2,
    })

  d["Nodes"].append(node)

d["Nodes"].append({
  "Name": "Relay",
  "IsRelay": True,
  "Wallets": [],
})

print json.dumps(d, indent=True)
