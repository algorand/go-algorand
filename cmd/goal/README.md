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

### Q: How do I make a goal app call which:
* accesses a particular box for a particular app
* the name of the box is defined as an ABI type
* displays the results as JSON

### A:
Here's an example with the following assumptions:

* the callers's account is given by `$ACCOUNT` (see previous answer)
* the `app-id` is 1
* the box referenced in the app-call has name `zeph`
  * this is also app arg 1
* the box referenced in the app-call will have contents `hi`
  * this is also app arg 2
* another referenced box has abi-name of type `(uint64,uint32)`
* `msgpacktool` is used to decode to JSON
* it is assumed that `$ALGORAND_DATA` has been exported (see previous answer)

```sh
# create a box with a non-abi name:
❯ goal app call --from $ACCOUNT --app-id 1 --app-arg str:create --app-arg str:zeph -o - | msgpacktool -d
{
  "txn": {
    "apaa": [
      "Y3JlYXRl",
      "emVwaA=="
    ],
    "apid": 1,
    "fee": 1000,
    "fv": 483,
    "gh:b64": "ETw2drwLuKVe1YKOszAZVG4262GYFWo3Sv9FaPaxKyQ=",
    "lv": 1483,
    "note:b64": "45mntbGnbrw=",
    "snd:b64": "/vIHevqRpLcRyZkYoUr6jLBdGZdmfOUaVDuiNEIuz9g=",
    "type": "appl"
  }
}

# create an abi-named box:
❯ goal app call --from $ACCOUNT --app-id 1 --app-arg str:create --app-arg "abi:(byte,byte,byte):[2,3,5]" -o - | msgpacktool -d
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

# set the non-abi box name contents:
❯ goal app call --from $ACCOUNT --app-id 1 --app-arg "str:set" --app-arg "abi:(byte,byte,byte):[2,3,5]" --app-arg "str:42" --box "1,abi:(byte,byte,byte):[2,3,5]" -o - | msgpacktool -d
{
  "txn": {
    "apaa": [
      "c2V0",
      "AgMF",
      "NDI="
    ],
    "apbx": [
      {
        "n": "\u0002\u0003\u0005"
      }
    ],
    "apid": 1,
    "fee": 1000,
    "fv": 656,
    "gh:b64": "ETw2drwLuKVe1YKOszAZVG4262GYFWo3Sv9FaPaxKyQ=",
    "lv": 1656,
    "note:b64": "+LdObo5T8fQ=",
    "snd:b64": "/vIHevqRpLcRyZkYoUr6jLBdGZdmfOUaVDuiNEIuz9g=",
    "type": "appl"
  }
}

# check the non-abi box name contents:
❯ goal app call --from $ACCOUNT --app-id 1 --app-arg "str:check" --app-arg "abi:(byte,byte,byte):[2,3,5]" --app-arg "str:42" --box "1,abi:(byte,byte,byte):[2,3,5]" -o - | msgpacktool -d
{
  "txn": {
    "apaa": [
      "Y2hlY2s=",
      "AgMF",
      "NDI="
    ],
    "apbx": [
      {
        "n": "\u0002\u0003\u0005"
      }
    ],
    "apid": 1,
    "fee": 1000,
    "fv": 709,
    "gh:b64": "ETw2drwLuKVe1YKOszAZVG4262GYFWo3Sv9FaPaxKyQ=",
    "lv": 1709,
    "note:b64": "shB7wsQotp4=",
    "snd:b64": "/vIHevqRpLcRyZkYoUr6jLBdGZdmfOUaVDuiNEIuz9g=",
    "type": "appl"
  }
}
```