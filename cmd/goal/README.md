# Example `goal` Snippets

Unless otherwise noted, it is assumed that the working directory
begins at the top level of the `go-algorand` repo.

It is also assumed that the main README's installation instructions have been followed and `make install` run so that the `goal` executable has been rebuilt from the same source as this example and is available in the shell environment.
You can run `ls -l $(which goal)` after your `make install` and look at the installation time as a sanity check.

Finally, all the `goal` commands assume that `${ALGORAND_DATA}` has been set. See the first Q/A for how this is done.

## Starting a Single Node Dev Network

### Q: Having just completed a new build in go-algorand, how do I get a single node dev network up, with algos in an easily accessible wallet from goal?

### A:

```sh
# set this to where you want to keep the network files (and data dirs will go beneath)
NETWORKS=~/networks

# create a networks directory if you don't already have it
mkdir -p ${NETWORKS}

# set this to "name" your network
NAME=niftynetwork

# assuming here that are currently working out of the root directory of the go-algorand repo
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

## Creating Applications

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
goal app create --creator ${ACCOUNT} --approval-prog ${TEALDIR}/boxes.teal --clear-prog ${TEALDIR}/clear.teal
```

For the following questions, you'll need to use the app index. That will be shown in the last line printed. EG:

```sh
Attempting to create app (approval size 125, hash RKWO3VXBKQXF77PC6EHRLFXD4YTJYTJTGPTPWQ46YH5ESGPZ5JIA; clear size 3, hash IS4FW6ZCRMQRTDIINAVAQHD2GK6DXUNQHQ52IQGZEVPP4OEU56QA)
Issued transaction from account ECRQFXZ7P3PLNK6QLIEVX7AXU6NTVQZHFUSEXTXMBKKOA2NTIV4PCX7XNY, txid SZK3U7AARMPQSZUICZIGYRLC7UDXJCVPV34JCBN5LIBXMF635UKA (fee 1000)
Transaction SZK3U7AARMPQSZUICZIGYRLC7UDXJCVPV34JCBN5LIBXMF635UKA still pending as of round 12
Transaction SZK3U7AARMPQSZUICZIGYRLC7UDXJCVPV34JCBN5LIBXMF635UKA still pending as of round 13
Transaction SZK3U7AARMPQSZUICZIGYRLC7UDXJCVPV34JCBN5LIBXMF635UKA committed in round 14
Created app with app index 2
```

## Funding App-Accounts

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

## Application Boxes in `goal`

### Q: How do I use boxes in goal? In particular, I'd like to make a goal app call which:
* accesses a particular box for a particular app
* stores an ABI type as its contents

### A:
Here's an example with the following assumptions:

* the caller's account is given by `${ACCOUNT}` (see first answer)
* the program used is `boxes.teal` referenced above. In particular:
  * it routes to box subroutines using the app argument at index 0 as the method signifier
* the app id has been stored in `${APPID}` (see the previous answer)
* the box referenced in the first non-create app-call has name `greatBox`
* another referenced box is named `an_ABI_box`
  * this second box is provided contents `[2,3,5]` of ABI-type `(uint8,uint8,uint8)`

```sh
# create a box with a simple non-ABI name. Note how the `--box` flag needs to be set so as to refer to the box being touched
goal app call --from $ACCOUNT --app-id ${APPID} --box "str:greatBox" --app-arg "str:create" --app-arg "str:greatBox"

# create another box
goal app call --from ${ACCOUNT} --app-id ${APPID} --box "str:an_ABI_box" --app-arg "str:create" --app-arg "str:an_ABI_box"

# set the contents to ABI type `(uint8,uint8,uint8)` with value `[2,3,5]`
goal app call --from ${ACCOUNT} --app-id ${APPID} --box "str:an_ABI_box" --app-arg "str:set" --app-arg "str:an_ABI_box"  --app-arg "abi:(uint8,uint8,uint8):[2,3,5]"
```

### Q: How do I search for boxes in goal?

### A:
Assuming you followed the previous step to create `greatBox` and `an_ABI_box`:

```sh
# get all boxes for a given app
goal app box list --app-id ${APPID}

# get the box details for a given box
goal app box info --app-id ${APPID} --name "str:an_ABI_box"
```
