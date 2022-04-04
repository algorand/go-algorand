git checkout master
git pull
make
mkdir -p ~/Algorand/masterbin
cp -p "${GOPATH}"/bin/{algod,goal,kmd} ~/Algorand/masterbin
git checkout feature/txnsync
git pull
make
mkdir -p ~/Algorand/txnsyncbin
cp -p "${GOPATH}"/bin/{algod,goal,kmd} ~/Algorand/txnsyncbin


rm -rf ~/Algorand/tn3
~/Algorand/masterbin/goal network create -r ~/Algorand/tn3 -n tbd -t test/testdata/nettemplates/ThreeNodesEvenDist.json

# POINT OF DIVERGENCE: what kind of node is the relay? master or txnsync:
#~/Algorand/masterbin/algod -d ~/Algorand/tn3/Primary > ~/Algorand/tn3/Primary/algod.out 2>&1 &
#~/Algorand/txnsyncbin/algod -d ~/Algorand/tn3/Primary > ~/Algorand/tn3/Primary/algod.out 2>&1 &

~/Algorand/masterbin/algod -d ~/Algorand/tn3/Node1 -p $(cat ~/Algorand/tn3/Primary/algod-listen.net) > ~/Algorand/tn3/Primary/algod.out 2>&1 &

~/Algorand/txnsyncbin/algod -d ~/Algorand/tn3/Node2 -p $(cat ~/Algorand/tn3/Primary/algod-listen.net) > ~/Algorand/tn3/Primary/algod.out 2>&1 &

~/Algorand/masterbin/goal -d ~/Algorand/tn3/Primary node status

~/Algorand/masterbin/goal -d ~/Algorand/tn3/Primary node wait -w 15

~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account list

N1A1=$(~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account list|awk '{ print $2 }')

N2A1=$(~/Algorand/txnsyncbin/goal -d ~/Algorand/tn3/Node2 account list|awk '{ print $2 }')

echo $N1A1
echo $N2A1

~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account balance -a $N1A1; ~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account balance -a $N2A1

~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 clerk send -a 999000 -f $N1A1 -t $N2A1

~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account balance -a $N1A1; ~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account balance -a $N2A1

~/Algorand/txnsyncbin/goal -d ~/Algorand/tn3/Node2 clerk send -a 3000000 -f $N2A1 -t $N1A1

~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account balance -a $N1A1; ~/Algorand/masterbin/goal -d ~/Algorand/tn3/Node1 account balance -a $N2A1

python3 ~/Algorand/block_proposers.py ~/Algorand/tn3/Primary

kill $(cat ~/Algorand/tn3/Node1/algod.pid) $(cat ~/Algorand/tn3/Node2/algod.pid) $(cat ~/Algorand/tn3/Primary/algod.pid)
