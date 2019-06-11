# Overview

_*__Summary:__* Keys are generated. The `auctionmaster` is configured and
then used to generate an auction-initiating transaction. The
auction-initiating transaction is posted to the blockchain. Bid and
deposit transactions are generated and posted to the blockchain. When
the auction is over, the `auctionminion` reads the blockchain to
determine final state. This produces output for the `auctionmaster`
to consume. In turn, the `auctionmaster`  produces auction summary
outputs and payout transactions._  

There are two important types of keys for operating an auction: an
auction key and a dispensing key.  There is exactly one auction key
for an auction; it is used to sign the auction start (the `Params`
message) and to settle the auction (sign the settlement).  There can
be one or more dispensing keys; these form a multisig address used
to dispense winnings, as configured by `DispensingMultisig.PKs` and
`DispensingMultisig.Threshold` in `initparams.json`.

Each auction is identified by the auction public key and an auction ID.
Auction IDs must be unique for a given auction key.  An auction key can
be reused for multiple auctions, as long as the auction IDs are not reused
(e.g., by incrementing the auction IDs for each subsequent auction).

All of the keys used for operating an auction should be generated
using `algokey` (as suggested in the below notes), and their mnemonic
representation (words) should be written down on paper as a backup of
that key.  This backup should be used in case the computer storing the
auction key (or one of the dispensing keys) crashes before the auction
is settled.

As a general precaution, when operating the auction, check all of the
transactions using `msgpacktool -d -b32` before posting them on the
blockchain.  For example, before posting `auction%d.starttx`, examine it
using `cat auction%d.starttx | msgpacktool -d -b32` to make sure that the
amount is 0, that the transaction is sent from the auction's address,
and so on.

When settling the auction, use multiple replicas to compute the outcomes,
and ensure consistency of outcomes across replicas by comparing
`sha256sum` checksums.  `auctionmaster -skipsign` allows computing the
`auction%d.outcomes` and `auction%d.paymenttx` files on a computer without
a copy of `master.key` (each `auctionmaster` replica will need a copy of
the `auction%d.param` and `auction%d.multisig` files, but that's okay,
they do not need to be confidential).

Check that the payment transactions in the `auction%d.paymenttx` file
look sensible -- the amounts seem in line with what we expect for the
auction, the number of transactions is as expected, etc.  Again, this can be
done with `msgpacktool -d -b32`.

Sign the `auction%d.paymenttx` transactions using `algokey multisig`
on each computer with a dispensing key, to form a complete multisig
signature on all of the transactions.  Merge the signatures using `goal
clerk multisig merge` and post the transactions.

When generating transactions (such as the `settletx` or `paymenttx`) from
the `auctionmaster`, consider the `-txround` parameter carefully. You want
to leave enough time to get the transactions signed and onto an online
machine for posting to the transaction before the transaction submission 
window expires.

Step-by-step directions for running an auction follow. 

# Setting up an auction:

Auctions are run entirely on layer two. Layer two applications are applications external to the protocol-level `algod` node, which could be considered layer one. Layer two solutions tend to operate on data in transaction `Note` fields.

Each step will first be explained in prose, followed by the console commands. Where possible, console commands have further explanation after them. 

## CoinList sets up `auctionbank`
The auctionbank is a long-running process that provides `Deposit`s, attestations that a user has credit with which to `Bid`. The following commands create an initial auction bank database on the local machine, and then start the auctionbank process.
- `auctionbank -create`
- `auctionbank`

Auctionbank will then output its URI.

## Set up airgapped dispensing keys and airgapped `auctionmaster` key

### Dispensing Keys
The dispensing keys will form the multisig address used to pay auction winners. They will be used to sign `paymenttx`s.

On each airgapped machine, create a directory to hold the keys (here, called `dispense`). Then, run `algokey` to initialize keys. The public keys will be needed for later steps, so be sure to export them from the airgapped machine.
- `mkdir dispense`
- `algokey generate -f dispense/master.key -p dispense/master.pub`

To derive the final dispensing pubkey address, use `goal account multisig new` with the desired threshold.
- `goal account multisig new [addr1 addr2 ...] -k threshold`
This address will receive the payout pool of algos, and will need at least `threshold` signatures to pay out.
Alternatively, the `auctionmaster` will output the public dispensing address at the end of initialization.

### Master Key
The master key is the key that signs auction-starting `Params` and auction-ending `Settlement` messages. It is used by the short-lived `auctionmaster` process. The public master key is important, as it verifies signed `auctionmaster` messages and is used by the `auctionbank`, `auctionconsole`, and `auctionminion` to detect which transactions are related to the auction.

Create a directory to hold the auctionmaster keys (here, called `am`). Then, run `algokey` to initialize keys. Finally, fund the master key, so it can pay transaction fees.
- `mkdir am`
- `algokey generate -f am/master.key -p am/master.pub`
- Transfer some money to account `am/master.pub` using `goal` or the REST API. This money will be used to pay transaction fees.

## Auctionmaster machine: set up auction parameters
The `initparams.json` describes the initial `params` of the auction. 

Create the initial parameters file, `initparams.json`, from the provided template. Fill in desired parameters. Use `auctionmaster` to create a `starttx` (an `auctionmaster`-signed transaction with the `params` encoded into the message field). As noted in the overview, use a `txround` that is sufficiently far in the future such that the start transaction will not expire before it can be exported to an online machine.
- `auctionmaster -dir am -initparams`
- `cp am/initparams.json.tmpl am/initparams.json`
- Edit `am/initparams.json`, fill in the bank key from `auctionbank`, fill in other desired auction parameters.  Add one or more public keys to `DispensingMultisig.PKs`, and adjust `DispensingMultisig.Threshold` as needed.
- `auctionmaster -dir am -initparams -txround someround`
- Export `auctionX.starttx`, `auctionX.multisig`, `auctionX.param` files from the airgapped machine. Ensure the `.starttx` file looks correct using the `msgpacktool` (see overview).

## Set up `auctionminion` (does not need to be airgapped)
The `auctionminion` is a short-lived process that reads the blockchain to determine whether an auction has ended, and if so, what the relevant auction messages were. `auctionminion` usage needs to either occur on an online computer, or an offline computer with an up-to-date copy of the blockchain.

Initialize the `auctionminion`. Edit the `auctionminion.state` file to indicate the `auctionmaster` public key (for verifying `auctionmaster` signatures and detecting transactions to/from the `auctionmaster` account). Indicate the `AuctionID` for this auction: messages with a mismatched ID will be ignored. Also indicate the `AlgodToken`, for authorizing the `auctionminion` to make REST calls against its `algod` node. Finally, the `StartRound` is a hint to the `auctionminion`, which will start reading the blockchain from that round. 
- `auctionminion -init`
- Edit `auctionminion.state`, fill in all fields.

## Register auction with the bank (CoinList)
The bank needs to know about the auction being created by the `auctionmaster`. CoinList will provide the API for this. For sake of completeness, here is how to use `curl` to do this with a local `auctionbank`, `POST`ing the `auctionmaster` public key to the bank's `create-auctions` endpoint. 
- `curl -X POST --data-urlencode "auction=$(cat am/master.pub)" http://127.0.0.1:8123/create-auctions`

## Broadcast initial auction start 
Use `goal`'s raw transaction send feature, or the equivalent REST API call, to broadcast the auction start transaction to the network.
- Import `.starttx` to an online machine.
- `goal -d algodatadir clerk rawsend -f am/auctionX.starttx`

## CoinList allows users to participate in the auction
CoinList will post `Deposit`s and `Bid`s to the blockchain during the auction.

## Settle the auction
Once the final round as described by the `params` message has passed, the auction is over. Run `auctionminion` to read all auction messages from the blockchain. Export the resulting `.inputs` files to the offline `auctionmaster` machine. Run `auctionmaster` again, this time consuming the `.inputs` files. Use a `-txround` value that will give sufficient time to collect the multisig signatures (see overview).
- `auctionminion`
- Export `*.inputs` from online machine, import to airgapped `auctionmaster` machine. Here, they are placed in the folder `am`.
- `auctionmaster -dir am -txround someround`
- Export the `.settletx`, the `.paymenttx`, and the `.outcomes` files from the airgapped `auctionmaster` machine.
It is at this step that the `.settletx` and `.paymenttx` files should be examined using the `msgpacktool` (see overview). This step should also be cross-checked with other replica `auctionmaster`s (see overview).

## Broadcast auction settlement
To end the auction, use the raw transaction send feature to broadcast the resulting `settletx` transaction. The `settletx` summarizes auction results (so that observers can verify).
- Import `.settletx` to an online machine
- `goal -d algodatadir clerk rawsend -f auctionX.settletx`

## Sign and send payments
Finally, sign the `paymenttx` payment transactions to the auction winners.  To do this, use `algokey` to add multisig signatures from as many airgapped machines as needed:
- Import the `paymenttx` to the machine containing `some.multisig.key`
- `algokey multisig -k .../some.multisig.key -t auctionX.paymenttx -o am/auctionX.paymenttx.signed`
- Export the `.signed` file from the machine.

After enough signatures have been collected, merge the signatures and send the transactions:
- Import the `.signed` files to an online machine.
- `goal -d algodatadir clerk multisig merge -o merged.txs multiple-signed-paymenttx-files`
- `goal -d algodatadir clerk rawsend -f merged.txs`

## Feed auction settlement to `auctionbank`
The `auctionbank` needs to be informed of the auction outcomes, so that it can provide new accurate `Deposit` attestations in the next auction. In other words, it needs to know who spent their credit, and who still has credit with which to bid. CoinList will provide their own API for this. For sake of completeness, here is how to use `curl` to update a locally-running `auctionbank`.

Here, `curl` is used to `POST` the settlement information to the `auctionbank`'s `settle-auction` endpoint.
- `LASTID="$(cat am/lastsettled)"`
- `curl -X POST --data-urlencode "auction=$(cat am/master.pub)" --data-urlencode "outcomes=$(base64 am/auction${LASTID}.outcomes)" --data-urlencode "sigsettle=$(base64 am/auction${LASTID}.settle)" http://127.0.0.1:8123/settle-auction`

## During the auction: View state with the `auctionconsole`
The `auctionconsole` is a long-running process used to observe an auction's progression. It needs the `algod.token` to make REST calls against the algorand node and the `master` public key to detect auction transactions and verify `master` signatures.
- `auctionconsole -apitoken $(cat algodatadir/algod.token) -auctionkey $(cat am/master.pub) -debug`
This will produce a running stream of output describing the current auction state.