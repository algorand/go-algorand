#!/usr/bin/env bash

# first, you'll need to create an asset
goal asset create -d . --creator G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU --total 100000 --unitname e.g.Coin
# > Issued transaction from account G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU, txid JH7M5L43YLQ5DTRIVVBUUB2E4BFE7TPVAPPEGCUVNYSFRLT55Z3Q (fee 1000)
# > Transaction JH7M5L43YLQ5DTRIVVBUUB2E4BFE7TPVAPPEGCUVNYSFRLT55Z3Q still pending as of round 148369
# > Transaction JH7M5L43YLQ5DTRIVVBUUB2E4BFE7TPVAPPEGCUVNYSFRLT55Z3Q committed in round 148371
goal asset info --creator G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU -d . --unitname e.g.Coin
# > Asset ID:         39
# > Creator:          G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU
# > Asset name:       
# > Unit name:        e.g.Coin
# > Maximum issue:    100000 e.g.Coin
# > Reserve amount:   100000 e.g.Coin
# > Issued:           0 e.g.Coin
# > Default frozen:   false
# > Manager address:  G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU
# > Reserve address:  G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU
# > Freeze address:   G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU
# > Clawback address: G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU

# allow an account (we'll call her Alice) to accept this asset by sending a 0-asset transaction to yourself
goal asset send --creator G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU --assetid 39 --from SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --to SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --amount 0 -d .
# > Issued transaction from account SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I, txid ELLYMXT56IIZ57XT5U65QLERU5VQUDSU36AXI5IP4MPKQJDORKBQ (fee 1000)
# > Transaction ELLYMXT56IIZ57XT5U65QLERU5VQUDSU36AXI5IP4MPKQJDORKBQ still pending as of round 152630
# > Transaction ELLYMXT56IIZ57XT5U65QLERU5VQUDSU36AXI5IP4MPKQJDORKBQ committed in round 152632

# produce TEAL assembly for a limit order escrow: Alice will trade _more than_ 1000 Algos for at least 3/2 * 1000 of some asset
algotmpl -d `git rev-parse --show-toplevel`/tools/teal/templates limit-order --swapn 3 --swapd 2 --mintrd 1000 --own SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --fee 100000 --timeout 150000 --asset 39 > limit.teal

# compile TEAL assembly to TEAL bytecode
goal clerk compile limit.teal 
# > limit.teal: 33XB4ZSZBTUHMU5PQFO26K6PAR5OXWO73TYZTIR6ENR6626P6IUMHAITK4

# initialize the escrow by sending 1000000 microAlgos into it
goal clerk send --from SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --to 33XB4ZSZBTUHMU5PQFO26K6PAR5OXWO73TYZTIR6ENR6626P6IUMHAITK4 --amount 1000000 -d .
# > Sent 1000000 MicroAlgos from account SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I to address 33XB4ZSZBTUHMU5PQFO26K6PAR5OXWO73TYZTIR6ENR6626P6IUMHAITK4, transaction ID: Q564JY6YWGROG7QK6CCFFYIH4JT3OJ7S6GCBQDW3RMRG3JQ6HWMQ. Fee set to 1000
# > Transaction Q564JY6YWGROG7QK6CCFFYIH4JT3OJ7S6GCBQDW3RMRG3JQ6HWMQ still pending as of round 151473
# > Transaction Q564JY6YWGROG7QK6CCFFYIH4JT3OJ7S6GCBQDW3RMRG3JQ6HWMQ committed in round 151475

# at this point, Alice can publish limit.teal, and anyone can fill the order without interaction from her

# build the group transaction
# the first payment sends money (Algos) from Alice's escrow to the recipient (we'll call him Bob), closing the rest of the account to Alice
# the second payment sends money (the asset) from the Bob to the Alice
goal clerk send --from-program limit.teal --to G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU -c SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --amount 2000 -d . -o test.tx
goal asset send --creator G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU --assetid 39 --from G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU --to SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --amount 20000 -d . -o test2.tx
cat test.tx test2.tx > testcmb.tx
goal clerk group -i testcmb.tx -o testgrp.tx

# Bob must sign his half of the transaction (Alice's half is authorized by the logic program's escrow)
# we must resplit the transaction (but this time they have the group fields set correctly)
goal clerk split -i testgrp.tx -o testraw.tx
# > Wrote transaction 0 to testraw-0.tx
# > Wrote transaction 1 to testraw-1.tx
goal clerk sign -i testraw-1.tx -o testraw-1.stx -d .
cat testraw-0.tx testraw-1.stx > testraw.stx

# regroup the transactions and send the combined signed transactions to the network
goal clerk rawsend -f testraw.stx -d .
# > Raw transaction ID AJVGWKZJHN4HYOMJ45AW5RXVIBNYK3CFDUI737VZ2KQ3N7DVVQZQ issued
# > Raw transaction ID 5ALEOOLZYNYIMSQFILJ3OXS5B3JDBVEPB7DB4DKAPANBIC56TTUA issued
# > Transaction AJVGWKZJHN4HYOMJ45AW5RXVIBNYK3CFDUI737VZ2KQ3N7DVVQZQ still pending as of round 153304
# > Transaction AJVGWKZJHN4HYOMJ45AW5RXVIBNYK3CFDUI737VZ2KQ3N7DVVQZQ committed in round 153306
# > Transaction 5ALEOOLZYNYIMSQFILJ3OXS5B3JDBVEPB7DB4DKAPANBIC56TTUA committed in round 153306
