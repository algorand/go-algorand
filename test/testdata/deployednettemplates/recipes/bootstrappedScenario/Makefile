# bootstrappedScenario is scenario1s but with pre-built 30_000_000 accountdb
PARAMS=-w 20 -R 8 -N 20 -n 20 --npn-algod-nodes 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json --last-part-key-round 50000
FILEPARAMS=--rounds 1600 --ntxns 20000 --naccounts 30000000 --nassets 20000 --napps 20000 --wallet-name "wallet1" --bal 50000000 --bal 50000001 --deterministic

all:	net.json genesis.json topology.json bootstrappedFile.json

net.json:	node.json nonPartNode.json ${GOPATH}/bin/netgoal Makefile
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${GOPATH}/bin/netgoal Makefile
	netgoal generate -t genesis -r /tmp/wat -o genesis.l.json ${PARAMS}
	jq '.LastPartKeyRound=22000|.NetworkName="s1s"|.ConsensusProtocol="future"' < genesis.l.json > genesis.json
	rm genesis.l.json

topology.json:	gen_topology.py
	python3 gen_topology.py

bootstrappedFile.json:  ${GOPATH}/bin/netgoal Makefile
	netgoal generate -t loadingFile -r /tmp/wat -o bootstrappedFile.json ${FILEPARAMS}

clean:
	rm -f net.json genesis.json
