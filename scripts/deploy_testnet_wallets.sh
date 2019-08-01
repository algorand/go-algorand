#!/usr/bin/env bash

# This script can only be run from a machine with SSH keys authorized on Relays R1, R2, R3, and D1

cd gen/testnet

scp ./r1-r-testnet.* algo@r1.algodev.network:/home/algo/algorand/testnet/data/relay
scp ./r1-n-testnet.* algo@r1.algodev.network:/home/algo/algorand/testnet/data/node

scp ./r2-r-testnet.* algo@r2.algodev.network:/home/algo/algorand/testnet/data/relay
scp ./r2-n-testnet.* algo@r2.algodev.network:/home/algo/algorand/testnet/data/node

scp ./r3-n-testnet.* david@r3.algodev.network:/home/david/algorand/testnet/data/node

scp ./d1-n-testnet.* algo@bank.testnet.algodev.network:/home/algo/algorand/testnet/data/dispenser
