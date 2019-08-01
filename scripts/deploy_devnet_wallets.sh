#!/usr/bin/env bash

# This script can only be run from a machine with SSH keys authorized on Relays R1, R2, R3, and D1

cd gen/devnet

scp ./r1-r-devnet.* algo@r1.algodev.network:/home/algo/algorand/devnet/data/relay
scp ./r1-n-devnet.* algo@r1.algodev.network:/home/algo/algorand/devnet/data/node

scp ./r2-r-devnet.* algo@r2.algodev.network:/home/algo/algorand/devnet/data/relay
scp ./r2-n-devnet.* algo@r2.algodev.network:/home/algo/algorand/devnet/data/node

scp ./r3-r-devnet.* david@r3.algodev.network:/home/david/algorand/devnet/data/relay

scp ./d1-n-devnet.* algo@bank.devnet.algodev.network:/home/algo/algorand/devnet/data/dispenser
