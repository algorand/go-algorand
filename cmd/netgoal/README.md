# Netgoal

## netgoal generate
`--participation-host-machines (-N)` and `--npn-host-machines (-X)` are optional parameters and they default to `--participation-algod-nodes (-n)` and `--npn-algod-nodes (-x)` respectively, i.e. defaults to a machine per algod node.

### Long-Form Flags Example
- Wallets: The command below will generate 100 wallets for the 100 participation algod nodes. By default each npn gets one wallet each. If there are more wallets than nodes, it will get split across the participation algod nodes.
- Relays: 8 Relays and 8 machines to host the relays will be generated
- Participation Nodes: 100 particiipation algod nodes will be distributed across 20 host machines.
- Non-Participation Nodes (NPNs): 10 non-participation algod nodes will be distributed across 5 host machines.

```
netgoal generate -t net -r /tmp/wat -o net.json --wallets 100 --relays 8 --participation-host-machines 20 --participation-algod-nodes 100 --npn-host-machines 5 --npn-algod-nodes 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json
```

### Short-Form Flags Example
The following will result in the same outcome as the command above.
```
netgoal generate -t net -r /tmp/wat -o net.json -w 100 -R 8 -N 20 -n 100 -X 5 -x 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json
```
## Flags
```
netgoal generate -h

Usage:
  netgoal generate [flags]

Flags:
      --bal stringArray                          Application Count
  -h, --help                                     help for generate
      --naccounts uint                           Account count (default 31)
      --napps uint                               Application Count (default 7)
      --nassets uint                             Asset count (default 5)
      --node-template string                     json for one node
      --non-participating-node-template string   json for non participating node
  -x, --npn-algod-nodes int                      Total non-participation algod nodes to generate
  -X, --npn-host-machines int                    Host machines to generate for non-participation algod nodes, default=npn-algod-nodes
      --ntxns uint                               Transaction count (default 17)
  -o, --outputfile string                        Output filename
  -n, --participation-algod-nodes int            Total participation algod nodes to generate (default -1)
  -N, --participation-host-machines int          Host machines to generate for participation algod nodes, default=participation-algod-nodes (default -1)
      --relay-template string                    json for a relay node
  -R, --relays int                               Relays to generate (default -1)
      --rounds uint                              Number of rounds (default 13)
  -t, --template string                          Template to generate
      --wallet-name string                       Source wallet name
  -w, --wallets int                              Wallets to generate (default -1)

Global Flags:
  -m, --modifier string   Override Genesis Version Modifier (eg 'v1')
  -r, --rootdir string    Root directory for the private network directories
```
