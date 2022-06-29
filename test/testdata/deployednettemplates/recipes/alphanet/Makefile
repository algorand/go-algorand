PARAMS=-w 20 -R 5 -N 1 -n 20 -H 4 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json

all:	topology.json net.json genesis.json

topology.json: gen_topology.py
	python gen_topology.py

net.json:	node.json relay.json nonPartNode.json ${GOPATH}/bin/netgoal Makefile
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	node.json relay.json nonPartNode.json ${GOPATH}/bin/netgoal Makefile
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}

clean:
	rm -f net.json genesis.json topology.json
