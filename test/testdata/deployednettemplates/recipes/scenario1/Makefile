PARAMS=-w 100 -R 8 -N 20 -n 100 -H 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json
FILEPARAMS=--rounds 5000 --ntrx 1000 --naccounts 3000000 --nassets 20000 --napps 20000 -wallet-name "wallet1"

all:	net.json genesis.json

net.json:	node.json nonPartNode.json ${GOPATH}/bin/netgoal
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${GOPATH}/bin/netgoal
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}

boostrappedFile.json:  ${GOPATH}/bin/netgoal
    netgoal generate -t genesis -r /tmp/wat -o boostrappedFile.json ${FILEPARAMS}
clean:
	rm -f net.json genesis.json
