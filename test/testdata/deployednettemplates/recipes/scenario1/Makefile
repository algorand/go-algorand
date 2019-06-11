PARAMS=-w 100 -R 5 -N 10 -n 10 --node-template node.json

all:	net.json genesis.json

net.json:	node.json ${GOPATH}/bin/netgoal
	netgoal generate -t net -r /tmp/wat -o net.json ${PARAMS}

genesis.json:	${GOPATH}/bin/netgoal
	netgoal generate -t genesis -r /tmp/wat -o genesis.json ${PARAMS}

clean:
	rm -f net.json genesis.json
