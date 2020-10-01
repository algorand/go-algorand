[![Build Status](https://travis-ci.com/algorand/go-algorand.svg?branch=master)](https://travis-ci.com/algorand/go-algorand)

go-algorand
====================
Algorand's official implementation in Go.

Algorand is a permissionless, pure proof-of-stake blockchain that delivers
decentralization, scalability, security, and transaction finality.

## Getting Started ##

Our [developer website][developer site url] has the most up to date information
about using and installing the algorand platform.

## Building from source ##

Development is done using the [Go Programming Language](https://golang.org/).
The version of go is specified in the project's [go.mod](go.mod) file. This document assumes that you have a functioning
environment setup. If you need assistance setting up an environment please visit
the [official Go documentation website](https://golang.org/doc/).

### Linux / OSX ###

We currently strive to support Debian based distributions with Ubuntu 18.04
being our official release target. Our core engineering team uses Linux and OSX,
so both environments are well supported for development.

OSX only: [Homebrew (brew)](https://brew.sh) must be installed before
continuing. [Here](https://docs.brew.sh/Installation) are the installation
requirements.

Initial environment setup:
```bash
git clone https://github.com/algorand/go-algorand
cd go-algorand
./scripts/configure_dev.sh
```

At this point you are ready to build go-algorand. We use `make` and have a
number of targets to automate common tasks.

#### build
```bash
make install
```

#### test
```bash
# unit tests
make test

# integration tests
make integration
```

#### style and checks
```bash
make fmt
make lint
make fix
make vet
```
or alternatively
```bash
make sanity
```

### Running a node

Once the software is built you'll find binaries in `${GOPATH}/bin`, and a data
directory will be initialized at `~/.algorand`. Start your node with
`${GOPATH}/bin/goal node start -d ~/.algorand`, use `${GOPATH}/bin/carpenter -d
~/.algorand` to see activity. Refer to the [developer website][developer site
url] for how to use the different tools.

#### Providing your own data directory
You can run a node out of other directories than `~/.algorand` and join networks
other than mainnet. Just make a new directory and copy into it the
`genesis.json` file for the network. For example:
```bash
mkdir ~/testnet_data
cp installer/genesis/testnet/genesis.json ~/testnet_data/genesis.json
${GOPATH}/bin/goal node start -d ~/testnet_data
```
Genesis files for mainnet, testnet, and betanet can be found in
`installer/genesis/`.

## Contributing (Code, Documentation, Bugs, Etc) ##

Please refer to our [CONTRIBUTING](CONTRIBUTING.md) document.


## Project Layout ##

`go-algorand` is split into various subpackages.

The following packages provide core functionality to the `algod` and `kmd`
daemons, as well as other tools and commands:

  - `crypto` contains the cryptographic constructions we're using for hashing,
    signatures, and VRFs. There are also some Algorand-specific details here
    about spending keys, protocols keys, one-time-use signing keys, and how they
    relate to each other.
  - `config` holds configuration parameters.  These include parameters used
    locally by the node as well as parameters which must be agreed upon by the
    protocol.
  - `data` defines various types used throughout the codebase.
     - `basics` holds basic types such as MicroAlgos, account data, and
       addresses.
     - `account` defines accounts, including "root" accounts (which can
       spend money) and "participation" accounts (which can participate in
       the agreement protocol).
     - `transactions` defines transactions that accounts can issue against
       the Algorand state.  These include standard payments and also
       participation key registration transactions.
     - `bookkeeping` defines blocks, which are batches of transactions
       atomically committed to Algorand.
     - `pools` implements the transaction pool.  The transaction pool holds
       transactions seen by a node in memory before they are proposed in a
       block.
     - `committee` implements the credentials that authenticate a
       participating account's membership in the agreement protocol.
  - `ledger` ([README](ledger/README.md)) contains the Algorand Ledger state
    machine, which holds the sequence of blocks.  The Ledger executes the state
    transitions that result from applying these blocks.  It answers queries on
    blocks (e.g., what transactions were in the last committed block?) and on
    accounts (e.g., what is my balance?).
  - `protocol` declares constants used to identify protocol versions, tags for
    routing network messages, and prefixes for domain separation of
    cryptographic inputs.  It also implements the canonical encoder.
  - `network` contains the code for participating in a mesh network based on
    websockets. Maintains connection to some number of peers, (optionally)
    accepts connections from peers, sends point to point and broadcast messages,
    and receives messages routing them to various handler code
    (e.g. agreement/gossip/network.go registers three handlers).
     - `rpcs` contains the HTTP RPCs used by `algod` processes to query one
       another.
  - `agreement` ([README](agreement/README.md)) contains the agreement service,
    which implements Algorand's Byzantine Agreement protocol.  This protocol
    allows participating accounts to quickly confirm blocks in a fork-safe
    manner, provided that sufficient account stake is correctly executing the
    protocol.
  - `node` integrates the components above and handles initialization and
    shutdown.  It provides queries into these components.

`daemon` defines the two daemons which provide Algorand clients with services:

  - `daemon/algod` holds the `algod` daemon, which implements a participating
    node.  `algod` allows a node to participate in the agreement protocol,
    submit and confirm transactions, and view the state of the Algorand Ledger.
     - `daemon/algod/api` ([README](daemon/algod/api/README.md)) is the REST
       interface used for interactions with algod.
  - `daemon/kmd` ([README](daemon/kmd/README.md)) holds the `kmd` daemon.  This
    daemon allows a node to sign transactions.  Because `kmd` is separate from
    `algod`, `kmd` allows a user to sign transactions on an air-gapped computer.

The following packages allow developers to interface with the Algorand system:

  - `cmd` holds the primary commands defining entry points into the system.
     - `cmd/catchupsrv` ([README](cmd/catchupsrv/README.md)) is a tool to
       assist with processing historic blocks on a new node.
  - `libgoal` exports a Go interface useful for developers of Algorand clients.
  - `debug` holds secondary commands which assist developers during debugging.

The `auction` package implements the Algorand auctions.

The following packages contain tools to help Algorand developers deploy networks
of their own:

  - `nodecontrol`
  - `tools`
  - `docker`
  - `commandandcontrol` ([README](test/commandandcontrol/README.md)) is a tool to
    automate a network of algod instances.
  - `components`
  - `netdeploy`

A number of packages provide utilities for the various components:

  - `logging` is a wrapper around `logrus`.
  - `util` contains a variety of utilities, including a codec, a sqlite wrapper,
    a goroutine pool, a timer interface, node metrics, and more.

`test` ([README](test/README.md)) contains end-to-end tests and utilities for the above components.


## License
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](COPYING)

Please see the [COPYING_FAQ](COPYING_FAQ) for details about how to apply our license.

Copyright (C) 2019-2020, Algorand Inc.

[developer site url]: https://developer.algorand.org/
