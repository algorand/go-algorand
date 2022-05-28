# Example `goal` Snippets

Unless otherwise noted, it is assumed that the working directory
begins at the top level of the `go-algorand` repo.

## Starting a Single Node Dev Network 

### Q:
> Having just done a new build in go-algorand, how do I get a single node dev network up, with algos in an easily used wallet from goal?

### A:

```sh
# create a networks directory if you don't already have it: 
mkdir -p ~/networks

# Set this to where you want to keep the network files (and data dirs will go beneath)
NETWORKS=~/networks

# set this to "name" your network:
NAME=niftynetwork

goal network create -n $NAME -r $NETWORKS/$NAME -t ./test/testdata/nettemplates/OneNodeFuture.json
export ALGORAND_DATA=$NETWORKS/$NAME/Primary
goal node start

# see if it worked (run a few times, note block increasing)
goal node status
sleep 4
goal node status
sleep 4
goal node status

# Find the account with all the money
goal account list

# put it in a variable
ACCOUNT=`goal account list | awk '{print $2}'`
echo $ACCOUNT

# send some money from the account to itself:
goal clerk send --to ${ACCOUNT} --from ${ACCOUNT} --amount 10
```