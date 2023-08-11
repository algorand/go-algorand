#!/usr/bin/python

import json

d = {
  "Genesis": {
    "NetworkName": "tbd",
    "ConsensusProtocol": "test-big-blocks",
    "LastPartKeyRound": 3000,
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

npn_nodes = 0
for n in range(0, npn_nodes):
  node = {
    "Name": "NPNode%d" % n,
    "Wallets": [],
    "DeadlockDetection": -1,
    "ConfigJSONOverride": '{"ForceFetchTransactions":true}'
  }
  d["Nodes"].append(node)

d["Nodes"].append({
  "Name": "Relay",
  "IsRelay": True,
  "Wallets": [],
})

print(json.dumps(d, indent=True))
