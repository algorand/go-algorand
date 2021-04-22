PARAMS=-w 6 -R 30 -N 6 -n 6 -H 5 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json

all:	net.json genesis.json

net.json:	node.json nonPartNode.json ${GOPATH}/bin/netgoal
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${GOPATH}/bin/netgoal
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}

clean:
	rm -f net.json genesis.json
