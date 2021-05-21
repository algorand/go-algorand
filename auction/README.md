# Setting up an auction:

Auctions are run entirely on layer two. Layer two applications are applications external to the protocol-level `algod` node, which could be considered layer one. Layer two solutions tend to operate on data in transaction `Note` fields.

Each step will first be explained in prose, followed by the console commands. Where possible, console commands have further explanation after them. 

## Set up `algod`
Create a data directory (here, called `xx`). Copy the genesis block, `genesis.json`, to the data directory. Start an algorand node using that data directory.
- `mkdir xx`
- `cp installer/genesis/devnet/genesis.json xx`
- `algod -d xx`

## Set up `auctionbank`
The auctionbank is a long-running process that provides `Deposit`s, attestations that a user has credit with which to `Bid`. The following commands create the initial auction bank database, and then start the auctionbank process.
- `auctionbank -create`
- `auctionbank`

## Set up `auctionmaster` key
The master key is the key that signs auction-starting `Params` and auction-ending `Settlement` messages. It is used by the short-lived `auctionmaster` process. The public master key is important, as it verifies signed `auctionmaster` messages and is used by the `auctionbank`, `auctionconsole`, and `auctionminion` to detect which transactions are related to the auction.

Create a directory to hold the auctionmaster keys (here, called `am`). Then, run `algokey` to initialize keys. Finally, fund the master key, so it can pay transaction fees.
- `mkdir am`
- `algokey generate -f am/master.key -p am/master.pub`
- Transfer some money to account `am/master.pub` using `goal` or the REST API

## Set up `auctionminion`
The `auctionminion` is a short-lived process that reads the blockchain to determine whether an auction has ended, and if so, what the relevant auction messages were.

Initialize the `auctionminion`. Edit the `auctionminion.state` file to indicate the `auctionmaster` public key (for verifying `auctionmaster` signatures and detecting transactions to/from the `auctionmaster` account). Also indicate the `AlgodToken`, for authorizing the `auctionminion` to make REST calls against the `algod` node.
- `auctionminion -init`
- Edit `auctionminion.state`, fill in `AuctionKey` from `am/master.pub` and `AlgodToken` from `xx/algod.token`

## Register auction with the bank
The bank needs to know about the auction being created by the `auctionmaster`. Use `curl` to `POST` the `auctionmaster` public key to the bank's `create-auctions` endpoint. 
- `curl -X POST --data-urlencode "auction=$(cat am/master.pub)" http://127.0.0.1:8123/create-auctions`

## Set up auction parameters
The `initparams.json` describes the initial `params` of the auction. Each subsequent auction `params` is determined from the previous `params` and the bids received in the previous auction. 

Create the initial parameters file, `initparams.json`, from the provided template. Fill in desired parameters. Use `auctionmaster` to create a `starttx` (an `auctionmaster`-signed transaction with the `params` encoded into the message field).
- `auctionmaster -dir am -initparams -payfee 1000 -notesfee 1000 -currentversion https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622 -genhash 4HkOQEL2o2bVh2P1wSpky3s6cwcEg/AAd5qlery942g=`
- `cp am/initparams.json.tmpl am/initparams.json`
- Edit `am/initparams.json`, fill in the bank key from `auctionbank`, fill in other desired auction parameters.  Add one or more public keys to `DispensingMultisig.PKs` (this could be the auction public key, for testing purposes), and adjust `DispensingMultisig.Threshold` as needed.
- `auctionmaster -dir am -initparams -txround $(goal -d xx node lastround) -payfee 1000 -notesfee 1000 -currentversion https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622 -genhash 4HkOQEL2o2bVh2P1wSpky3s6cwcEg/AAd5qlery942g=`

## Broadcast initial auction start
Use `goal`'s raw transaction send feature, or the equivalent REST API call, to broadcast the auction start transaction to the network.
- `goal -d xx clerk rawsend -f am/auction1.starttx`

## Start the `auctionconsole`
The `auctionconsole` is a long-running process used to observe an auction's progression. It needs the `algod.token` to make REST calls against the algorand node and the `master` public key to detect auction transactions and verify `master` signatures.
- `auctionconsole -apitoken $(cat xx/algod.token) -auctionkey $(cat am/master.pub) -debug`

## Participate in the auction

- Open `wallet/auction.html` in a browser
- Configure URLs and bank username; click "Reload"
- Enter your private key mnemonic
- Create bank username, if necessary
- Transfer in some money
- Enter bid currency amount and click "Go"

## Settle the auction
Once the final round as described by the `params` message has passed, the auction is over. Run `auctionminion` to read all auction messages from the blockchain. Move the resulting `.inputs` files somewhere convenient to pass to the `auctionmaster` (here, the `auctionmaster` directory `am` from earlier steps is used). Again, run `auctionmaster`, this time consuming the `.inputs` files.  Use a `-txround` value that will give sufficient time to collect the multisig signatures (see below).
- `auctionminion`
- `mv auction*.inputs am/`
- `auctionmaster -dir am -txround $(goal -d xx node lastround)`

## Broadcast auction settlement
To end the auction, use the raw transaction send feature to broadcast the resulting `settletx` transaction. The `settletx` summarizes auction results (so that observers can verify).
- `LASTID="$(cat am/lastsettled)"`
- `NEXTID="$(expr $LASTID + 1)"`
- `goal -d xx clerk rawsend -f am/auction${LASTID}.settletx`

## Sign and send payments
Finally, sign the `paymenttx` payment transactions to the auction winners.  To do this, use `algokey` to add multisig signatures from as many multisig keys as needed:
- `LASTID="$(cat am/lastsettled)"`
- `NEXTID="$(expr $LASTID + 1)"`
- `algokey multisig -k .../some.multisig.key -t am/auction${LASTID}.paymenttx -o am/auction${LASTID}.paymenttx.signed`

After enough signatures have been collected, merge the signatures and send the transactions:

- `goal -d xx clerk multisig merge -o merged.txs multiple-signed-paymenttx-files`
- `goal -d xx clerk rawsend -f merged.txs`

## Feed auction settlement to `auctionbank`
The `auctionbank` needs to be informed of the auction outcomes, so that it can provide new accurate `Deposit` attestations in the next auction. In other words, it needs to know who spent their credit, and who still has credit with which to bid.

Here, `curl` is used to `POST` the settlement information to the `auctionbank`'s `settle-auction` endpoint.
- `LASTID="$(cat am/lastsettled)"`
- `curl -X POST --data-urlencode "auction=$(cat am/master.pub)" --data-urlencode "outcomes=$(base64 am/auction${LASTID}.outcomes)" --data-urlencode "sigsettle=$(base64 am/auction${LASTID}.settle)" http://127.0.0.1:8123/settle-auction`

## Cancel auction 
- `auctionmaster -dir am -cancel -txround $(goal -d xx node lastround) -payfee 1000 -notesfee 1000 -currentversion https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622 -genhash 4HkOQEL2o2bVh2P1wSpky3s6cwcEg/AAd5qlery942g=`


# Operating an auction:

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
using `algokey` (as suggested in the above notes), and their mnemonic
representation (words) should be written down on paper as a backup of
that key.  This backup should be used in case the computer storing the
auction key (or one of the dispensing keys) crashes before the auction
is settled.

As a general precaution, when operating an auction, check all of the
transactions using `msgpacktool -d -b32` before posting them on the
blockchain.  For example, before posting `auction%d.starttx`, examine it
using `cat auction%d.starttx | msgpacktool -d -b32` to make sure that the
amount is 0, that the transaction is sent from the auction's address, etc.

When settling an auction, use multiple replicas to compute the outcomes,
and ensure consistency of outcomes across replicas by comparing
`sha256sum` checksums.  `auctionmaster -skipsign` allows computing the
`auction%d.outcomes` and `auction%d.paymenttx` files on a computer without
a copy of `master.key` (but you need to distribute `auction%d.param`
and `auction%d.multisig`, which aren't confidential).

Check that the payment transactions in the `auction%d.paymenttx` file
look sensible -- the amounts seem in line with what we expect for the
auction, the number of transactions is as expected, etc.  Use `msgpacktool
-d -b32`.

Sign the `auction%d.paymenttx` transactions using `algokey multisig`
on each computer with a dispensing key, to form a complete multisig
signature on all of the transactions.  Merge the signatures using `goal
clerk multisig merge` and post the transactions.

When settling an auction, use a `-txround` parameter that's far enough
in advance to be able to assemble all of the multisig signatures before
the transaction validity window expires.
