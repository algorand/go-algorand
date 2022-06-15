# Example `goal` Snippets

Unless otherwise noted, it is assumed that the working directory
begins at the top level of the `go-algorand` repo.

It is also assumed that the main README's installation instructions have been followed and `make install` run so that the `goal` executable is available via `${GOPATH}/bin/goal`. 
You can verify this to be the case by comparing the output of `which goal` with the output of `echo ${GOPATH}/bin/goal`.

## Starting a Single Node Dev Network 

### Q: Having just completed a new build in go-algorand, how do I get a single node dev network up, with algos in an easily accessible wallet from goal?

### A:

```sh
# create a networks directory if you don't already have it: 
mkdir -p ~/networks

# Set this to where you want to keep the network files (and data dirs will go beneath)
NETWORKS=~/networks

# set this to "name" your network:
NAME=niftynetwork

goal network create -n ${NAME} -r ${NETWORKS}/${NAME} -t ./test/testdata/nettemplates/OneNodeFuture.json
export ALGORAND_DATA=${NETWORKS}/${NAME}/Primary
goal node start

# see if it worked (run a few times, note block increasing)
goal node status
sleep 4  # assuming you're copy/pasting this entire block
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

# assuming the "app index" in the previous was 1, we'll need to store its address for funding purposes
```

### Q: How do I fund the app account so that it can satisfy its boxes min-balance requirement and allow for box creation?

### A:
Assuming you followed the previous step, and that the _app index_ is 1:

```sh
# store the app index for later usage:
APPID=1
echo $APPID

# Store app's account address into a variable
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
* displays the results as JSON

### A:
Here's an example with the following assumptions:

* the callers's account is given by `$ACCOUNT` (see first answer)
* the program used was created in as in the second question. In particular:
  * it routes to box subroutines using the method signifier `app-arg 0`
* the app id has been stored in `$APPID` (see the previous answer)
* the box referenced in the first app-call has name `greatBox`
* another referenced box has abi-name of type `(byte,byte,byte)` and name `[2,3,5]`
* this second box is provided contents `42`
* `msgpacktool` is used to decode to JSON
* it is assumed that `$ALGORAND_DATA` has been exported (see previous answer)

```sh
# create a box with a simple non-ABI name:
❯ goal app call --from $ACCOUNT --app-id ${APPID} --app-arg "str:create" --app-arg "str:greatBox" -o - | msgpacktool -d
{
  "txn": {
    "apaa": [
      "Y3JlYXRl",
      "Z3JlYXRCb3g="
    ],
    "apid": 1,
    "fee": 1000,
    "fv": 314,
    "gh:b64": "C6TkcPi8SaIgArGPLnbqRpQ+obwjMmgGnLJ+X0hQkFE=",
    "lv": 1314,
    "note:b64": "gd5dwCVwxpY=",
    "snd:b64": "GKgl/BbeLf7kecfIA8RKWlzr/p44bYt5tLtRsvt39Bc=",
    "type": "appl"
  }
}

# create a box named by an ABI-type:
❯ goal app call --from ${ACCOUNT} --app-id ${APPID} --app-arg "str:create" --app-arg "abi:(byte,byte,byte):[2,3,5]" -o - | msgpacktool -d
{
  "txn": {
    "apaa": [
      "Y3JlYXRl",
      "AgMF"
    ],
    "apid": 1,
    "fee": 1000,
    "fv": 589,
    "gh:b64": "ETw2drwLuKVe1YKOszAZVG4262GYFWo3Sv9FaPaxKyQ=",
    "lv": 1589,
    "note:b64": "mUpBGHTlBrI=",
    "snd:b64": "/vIHevqRpLcRyZkYoUr6jLBdGZdmfOUaVDuiNEIuz9g=",
    "type": "appl"
  }
}

# set the ABI-type box name contents. Note how the `--box` flag needs to be set so as to refer to the box being touched:
❯ goal app call --from ${ACCOUNT} --app-id ${APPID} --app-arg "str:set" --app-arg "abi:(byte,byte,byte):[2,3,5]" --app-arg "str:42" --box "${APPID},abi:(byte,byte,byte):[2,3,5]" -o - | msgpacktool -d
{
  "txn": {
    "apaa": [
      "c2V0",
      "AgMF",
      "NDI="
    ],
    "apbx": [
      {
        "n:b64": "AgMF"
      }
    ],
    "apid": 1,
    "fee": 1000,
    "fv": 413,
    "gh:b64": "C6TkcPi8SaIgArGPLnbqRpQ+obwjMmgGnLJ+X0hQkFE=",
    "lv": 1413,
    "note:b64": "h/N9VcxOBpw=",
    "snd:b64": "GKgl/BbeLf7kecfIA8RKWlzr/p44bYt5tLtRsvt39Bc=",
    "type": "appl"
  }
}
```