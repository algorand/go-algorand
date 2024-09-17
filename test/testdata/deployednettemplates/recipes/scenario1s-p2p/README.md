# Scenario1s for P2P testing

This is a copy of scenario1s with the following changes in nodes configuration:
1. All nodes get `"EnableP2P": true` into their config.
1. All relays additionally get `"P2PBootstrap": true` to their netgoal config.

## Build

```sh
make
```

If want to configure a hybrid net, set the `HYBRID` mode parameter to:
  - `p2p` meaning all nodes are p2pnet and 50% of them are hybrid
  - `ws` meaning all nodes are wsnet and 50% of them are hybrid

```sh
make -D HYBRID=p2p
```

## Run

Run as usual cluster test scenario with algonet.
