# Recipes

Most of the recipes' net.json and genesis.json use one of the following methods to call `netgoal generate`:
1. `Makefile`
2. `python3 {GO_ALGORAND_PATH}/test/testdata/deployednettemplates/generate-recipe/generate_network.py -f {PATH_TO}/network-tpl.json`

Details for netgoal generate could be found in the binary with:
```
netgoal generate -h
```

Source code for netgoal can be found in `{GO_ALGORAND_PATH}/cmd/netgoal/generate.go`

Quick reference when reading some of the Makefiles in this directory:
```
PARAMS=-w 100 -R 8 -N 20 -n 100 -H 10 -X 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json
```
- If you specify `-n` (number of participating algod nodes), the default if you don't pass in `-N` (number of machines to host the algod nodes) is set to match `-n`, i.e. one algod node per machine. To increase the number of nodes per machine, specify both `-n` and `-N`. `-n 10 -N 5` means 10 participating algod nodes across 5 machines, so 2 algod nodes per machine.
- If you specify `-X` (number of non-participating nodes, npn), the default if you don't pass in `-H` (number of machines to host the npn) is set to the match `-X`, i.e. one npn per machine. To increase the number of nodes per machine, specify both `-X` and `-H`. `-X 10 -H 5` means 10 npns across 5 machines, so 2 npns per machine.

```
Usage:
  netgoal generate [flags]

Flags:
      --bal stringArray                          Application Count
  -h, --help                                     help for generate
      --naccounts uint                           Account count (default 31)
      --napps uint                               Application Count (default 7)
      --nassets uint                             Asset count (default 5)
  -N, --node-hosts int                           Node-hosts to generate, default=nodes (default -1)
      --node-template string                     json for one node
  -n, --nodes int                                Nodes to generate (default -1)
      --non-participating-node-template string   json for non participating node
  -X, --non-participating-nodes int              Non participating nodes to generate
  -H, --non-participating-nodes-hosts int        Non participating nodes hosts to generate
      --ntxns uint                               Transaction count (default 17)
  -o, --outputfile string                        Output filename
      --relay-template string                    json for a relay node
  -R, --relays int                               Relays to generate (default -1)
      --rounds uint                              Number of rounds (default 13)
  -t, --template string                          Template to generate
      --wallet-name string                       Source wallet name
  -w, --wallets int                              Wallets to generate (default -1)
```
