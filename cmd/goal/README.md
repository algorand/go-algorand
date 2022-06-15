# Example `goal` Snippets

Unless otherwise noted, it is assumed that the working directory
begins at the top level of the `go-algorand` repo.

It is also assumed that the main README's installation instructions have been followed and `make install` run so that the `goal` executable is available via `${GOPATH}/bin/goal`.
You can verify this to be the case by comparing the output of `which goal` with the output of `echo ${GOPATH}/bin/goal`.

Finally, all the `goal` commands assume that `${ALGORAND_DATA}` has been set. See the first Q/A for how this is done.

## Starting a Single Node Dev Network

### Q: Having just completed a new build in go-algorand, how do I get a single node dev network up, with algos in an easily accessible wallet from goal?

### A:

```sh
# create a networks directory if you don't already have it
mkdir -p ~/networks

# set this to where you want to keep the network files (and data dirs will go beneath)
NETWORKS=~/networks

# set this to "name" your network
NAME=niftynetwork

goal network create -n ${NAME} -r ${NETWORKS}/${NAME} -t ./test/testdata/nettemplates/OneNodeFuture.json

# after the next command and for the rest of the README, we assume that `${ALGORAND_DATA}` is set
export ALGORAND_DATA=${NETWORKS}/${NAME}/Primary
echo $ALGORAND_DATA

# start the network
goal node start

# see if it worked (run a few times, note block increasing)
goal node status
sleep 4  # assuming you're copy/pasting this entire block
goal node status
sleep 4
goal node status

# find the account with all the money
goal account list

# put it in a variable
ACCOUNT=`goal account list | awk '{print $2}'`
echo $ACCOUNT

# send some money from the account to itself
goal clerk send --to ${ACCOUNT} --from ${ACCOUNT} --amount 10
```

### Q: How do I use goal to create an app?

### A:
Here's an example with the following assumptions:
* all the setup is as in the first question
* the approval program (which tests box functionality) has relative path `cmd/goal/examples/boxes.teal`
* the clear program has relative path `cmd/goal/examples/clear.teal`
* there are no local or global storage requirements

```sh
TEALDIR=cmd/goal/examples
echo $TEALDIR

# create the app and TAKE NOTE of its "app index"
goal app create --creator ${ACCOUNT} --approval-prog ${TEALDIR}/boxes.teal --clear-prog ${TEALDIR}/clear.teal --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0
```

### Q: How do I fund the app account so that it can satisfy its boxes min-balance requirement and allow for box creation?

### A:
Assuming you followed the previous step, and that the _app index_ is 2:

```sh
# store the app index for later usage
APPID=2
echo $APPID

# store the app's account address into a variable
APP_ACCOUNT=`goal app info --app-id ${APPID} | grep "Application account" | awk '{print $3}'`
echo $APP_ACCOUNT

# fund the app's account (here we're being very conservative and sending 10 algos)
goal clerk send --to ${APP_ACCOUNT} --from ${ACCOUNT} --amount 10000000

# verify the balance of the app's account
goal account balance --address ${APP_ACCOUNT}
```

### Q: How do I use boxes in goal? In particular, I'd like to make a goal app call which:
* accesses a particular box for a particular app
* the name of the box is defined as an ABI type

### A:
Here's an example with the following assumptions:

* the callers's account is given by `${ACCOUNT}` (see first answer)
* the program used is `boxes.teal` referenced above. In particular:
  * it routes to box subroutines using the method signifier `app-arg 0`
* the app id has been stored in `${APPID}` (see the previous answer)
* the box referenced in the first app-call has name `greatBox`
* another referenced box is named `[2,3,5]` of ABI-type `(byte,byte,byte)`
* this second box is provided contents `fourty two`

```sh
# create a box with a simple non-ABI name. Note how the `--box` flag needs to be set so as to refer to the box being touched
goal app call --from $ACCOUNT --app-id ${APPID} --box "str:greatBox" --app-arg "str:create" --app-arg "str:greatBox"

# create a box named by an ABI-type
goal app call --from ${ACCOUNT} --app-id ${APPID} --box "abi:(byte,byte,byte):[2,3,5]" --app-arg "str:create" --app-arg "abi:(byte,byte,byte):[2,3,5]"

# set the ABI-type box name contents
goal app call --from ${ACCOUNT} --app-id ${APPID} --box "${APPID},abi:(byte,byte,byte):[2,3,5]" --app-arg "str:set" --app-arg "abi:(byte,byte,byte):[2,3,5]" --app-arg "str:fourty two"
```