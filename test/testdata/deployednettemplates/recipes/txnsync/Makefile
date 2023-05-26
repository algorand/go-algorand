PARAMS=-w 10 -R 4 -N 10 -n 10 --npn-algod-nodes 1 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json

all:	net.json genesis.json

net.json:	node.json nonPartNode.json
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}

clean:
	rm -f net.json genesis.json
