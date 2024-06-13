# scenario1s is scenario1 but smaller, (100 nodes, 100 wallets) -> (20 nodes, 20 wallets), each algod gets single tenancy on a smaller ec2 instance
PARAMS=-w 20 -R 8 -N 20 -n 20 --npn-algod-nodes 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json

all:	net.json genesis.json topology.json bootstrappedFile.json

net.json:	node.json nonPartNode.json ${GOPATH}/bin/netgoal Makefile
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${GOPATH}/bin/netgoal Makefile
	netgoal generate -t genesis -r /tmp/wat -o genesis.l.json ${PARAMS}
	jq '.LastPartKeyRound=22000|.NetworkName="s1s"|.ConsensusProtocol="future"' < genesis.l.json > genesis.json
	rm genesis.l.json

topology.json:	gen_topology.py
	python3 gen_topology.py

clean:
	rm -f net.json genesis.json
