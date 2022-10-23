PARAMS=-w 10000 -R 20 -N 100 -n 1000 --npn-algod-nodes 15 --node-template node.json --relay-template relay.json

all:	net.json genesis.json

net.json:	node.json ${GOPATH}/bin/netgoal Makefile
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${GOPATH}/bin/netgoal Makefile
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}

clean:
	rm -f net.json genesis.json
