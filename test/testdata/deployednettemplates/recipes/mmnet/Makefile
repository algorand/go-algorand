PARAMS=-w 130 -R 136 -n 130 --npn-algod-nodes 16 --node-template configs/node.json --relay-template configs/relay.json --non-participating-node-template configs/nonPartNode.json

all: topology.json net.json genesis.json

topology.json:
	TOPOLOGY_FILE=$@ python gen_topology.py

net.json: configs/node.json configs/relay.json configs/nonPartNode.json $(GOPATH)/bin/netgoal Makefile
	netgoal generate -t net -r /tmp/wat -o net.json $(PARAMS)

genesis.json: configs/node.json configs/relay.json configs/nonPartNode.json $(GOPATH)/bin/netgoal Makefile
	netgoal generate -t genesis -r /tmp/wat -o genesis.json $(PARAMS)

clean:
	rm -f net.json genesis.json
