PARAMS=-w 100 -R 8 -N 20 -n 100 -H 10 --node-template node.json --relay-template relay.json --non-participating-node-template nonPartNode.json --last-part-key-round 50000
FILEPARAMS=--rounds 5000 --ntxns 1000 --naccounts 3000000 --nassets 20000 --napps 20000 --wallet-name "wallet1" --bal 100000 --bal 1000000 --deterministic

all:	net.json genesis.json bootstrappedFile.json

net.json:	node.json nonPartNode.json ${GOPATH}/bin/netgoal
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${GOPATH}/bin/netgoal
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}

bootstrappedFile.json:  ${GOPATH}/bin/netgoal
	netgoal generate -t loadingFile -r /tmp/wat -o bootstrappedFile.json ${FILEPARAMS}

clean:
	rm -f net.json genesis.json
