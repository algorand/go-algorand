# scenario1s is scenario1 but smaller, (100 nodes, 100 wallets) -> (20 nodes, 20 wallets), each algod gets single tenancy on a smaller ec2 instance
PARAMS=-w 20 -R 8 -N 20 -n 20 --npn-algod-nodes 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json

.PHONY:	clean all

HYBRID ?= no

all:	net.json genesis.json topology.json

node.json nonPartNode.json relay.json: copy-node-configs.py
	python3 copy-node-configs.py --hybrid=${HYBRID}

net.json:	node.json nonPartNode.json relay.json Makefile
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	Makefile
	netgoal generate -t genesis -r /tmp/wat -o genesis.l.json ${PARAMS}
	jq '.LastPartKeyRound=5000|.NetworkName="s1s-p2p"|.ConsensusProtocol="future"' < genesis.l.json > genesis.json
	rm genesis.l.json

topology.json:	../scenario1s/gen_topology.py
	python3 ../scenario1s/gen_topology.py

clean:
	rm -f net.json genesis.json node.json nonPartNode.json relay.json topology.json
