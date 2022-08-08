# scenario3s is scenario3 but smaller. (10000 wallets -> 500) (1000 algod participating nodes -> 100) It still keeps a global datacenter distribution.
PARAMS=-w 100 -R 20 -N 100 -n 100 -H 15 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json

SOURCES=node.json ${GOPATH}/bin/netgoal Makefile relay.json nonPartNode.json

all:	net.json genesis.json topology.json

net.json:	${SOURCES}
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${SOURCES}
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}
	mv genesis.json genesis.json.orig
	jq '.NetworkName="s3s"|.LastPartKeyRound=5000|.ConsensusProtocol="future"' < genesis.json.orig > genesis.json
	rm genesis.json.orig

topology.json: gen_topology.py
	python3 gen_topology.py

clean:
	rm -f net.json genesis.json
