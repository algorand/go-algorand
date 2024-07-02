# Scenario1s for P2P testing

This is a copy of scenario1s with the following changes in nodes configuration:
1. All nodes get `"EnableP2P": true` into their config.
1. All relays additionally get `"P2PBootstrap": true` to their netgoal config.

## Build

```sh
export GOPATH=~/go
make
```

## Run

Run as usual cluster test scenario with algonet.
