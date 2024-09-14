
# go-algorand
| **Branch**      | **Build Status** |
| --------------- | ---------------- |
| **rel/stable**  | [![CircleCI](https://circleci.com/gh/algorand/go-algorand/tree/rel%2Fstable.svg?style=svg)](https://circleci.com/gh/algorand/go-algorand/tree/rel%2Fstable) |
| **rel/beta**    | [![CircleCI](https://circleci.com/gh/algorand/go-algorand/tree/rel%2Fbeta.svg?style=svg)](https://circleci.com/gh/algorand/go-algorand/tree/rel%2Fbeta) |
| **rel/nightly** | [![CircleCI](https://circleci.com/gh/algorand/go-algorand/tree/rel%2Fnightly.svg?style=svg)](https://circleci.com/gh/algorand/go-algorand/tree/rel%2Fnightly) |


**Algorand's** official implementation in Go.

Algorand is a permissionless, pure proof-of-stake blockchain that delivers decentralization, scalability, security, and transaction finality.

## Getting Started

Visit our [developer website](https://developer.algorand.org/) for the most up-to-date information about using and installing the Algorand platform.

## Building from Source

Development is done using the Go Programming Language. The Go version is specified in the project's [go.mod](go.mod) file. This document assumes you have a functioning environment set up. If you need assistance setting up an environment, please visit the [official Go documentation website](https://golang.org/doc/).

### Linux / OSX

We currently strive to support Debian-based distributions, with Ubuntu 20.04 as our official release target. Building on Arch Linux also works well. Our core engineering team uses Linux and OSX, so both environments are well-supported for development.

**OSX Only**: [Homebrew (brew)](https://brew.sh) must be installed before continuing. [Here](https://docs.brew.sh/Installation) are the installation requirements.

### Initial Environment Setup

```bash
git clone https://github.com/algorand/go-algorand
cd go-algorand
./scripts/configure_dev.sh
./scripts/buildtools/install_buildtools.sh
```

At this point, you are ready to build go-algorand. We use `make` and have several targets to automate common tasks.

### Build

```bash
make install
```

### Test

```bash
# Unit tests
make test

# Integration tests
make integration
```

### Style and Checks

```bash
make fmt
make lint
make fix
make vet
```

Alternatively, run:

```bash
make sanity
```

## Running a Node

Once the software is built, you'll find binaries in `${GOPATH}/bin`, and a data directory will be initialized at `~/.algorand`. Start your node with:

```bash
${GOPATH}/bin/goal node start -d ~/.algorand
```

Use:

```bash
${GOPATH}/bin/carpenter -d ~/.algorand
```

to see activity. Refer to the [developer website](https://developer.algorand.org/) for instructions on using different tools.

### Providing Your Own Data Directory

You can run a node out of other directories than `~/.algorand` and join networks other than mainnet. Just make a new directory and copy the `genesis.json` file for the network into it. For example:

```bash
mkdir ~/testnet_data
cp installer/genesis/testnet/genesis.json ~/testnet_data/genesis.json
${GOPATH}/bin/goal node start -d ~/testnet_data
```

Genesis files for mainnet, testnet, and betanet can be found in `installer/genesis/`.

## Contributing

Please refer to our [CONTRIBUTING](CONTRIBUTING.md) document.

## Project Layout

`go-algorand` is organized into various subsystems and packages:

### Core

Provides core functionality to the `algod` and `kmd` daemons, as well as other tools and commands:

- **crypto**: Contains the cryptographic constructions used for hashing, signatures, and VRFs. It also includes Algorand-specific details about spending keys, protocol keys, one-time-use signing keys, and how they relate to each other.
- **config**: Holds configuration parameters, including those used locally by the node and those that must be agreed upon by the protocol.
- **data**: Defines various types used throughout the codebase.
  - **basics**: Holds basic types such as MicroAlgos, account data, and addresses.
  - **account**: Defines accounts, including "root" accounts (which can spend money) and "participation" accounts (which can participate in the agreement protocol).
  - **transactions**: Defines transactions that accounts can issue against the Algorand state, including standard payments and participation key registration transactions.
  - **bookkeeping**: Defines blocks, which are batches of transactions atomically committed to Algorand.
  - **pools**: Implements the transaction pool, holding transactions seen by a node in memory before they are proposed in a block.
  - **committee**: Implements the credentials that authenticate a participating account's membership in the agreement protocol.
- **ledger** ([README](ledger/README.md)): Contains the Algorand Ledger state machine, which holds the sequence of blocks. The Ledger executes the state transitions resulting from applying these blocks. It answers queries on blocks (e.g., what transactions were in the last committed block?) and on accounts (e.g., what is my balance?).
- **protocol**: Declares constants used to identify protocol versions, tags for routing network messages, and prefixes for domain separation of cryptographic inputs. It also implements the canonical encoder.
- **network**: Contains the code for participating in a mesh network based on WebSockets. It maintains connections to some number of peers, (optionally) accepts connections from peers, sends point-to-point and broadcast messages, and receives messages, routing them to various handler code (e.g., agreement/gossip/network.go registers three handlers).
  - **rpcs**: Contains the HTTP RPCs used by `algod` processes to query one another.
- **agreement** ([README](agreement/README.md)): Contains the agreement service, which implements Algorand's Byzantine Agreement protocol. This protocol allows participating accounts to quickly confirm blocks in a fork-safe manner, provided that sufficient account stake is correctly executing the protocol.
- **node**: Integrates the components above and handles initialization and shutdown. It provides queries into these components.

### Daemon

Contains the two daemons that provide Algorand clients with services:

- **daemon/algod**: Holds the `algod` daemon, which implements a participating node. `algod` allows a node to participate in the agreement protocol, submit and confirm transactions, and view the state of the Algorand Ledger.
  - **daemon/algod/api** ([README](daemon/algod/api/README.md)): The REST interface used for interactions with `algod`.
- **daemon/kmd** ([README](daemon/kmd/README.md)): Holds the `kmd` daemon, which allows a node to sign transactions. Since `kmd` is separate from `algod`, it enables a user to sign transactions on an air-gapped computer.

### Interfacing

Enables developers to interface with the Algorand system:

- **cmd**: Contains the primary commands defining entry points into the system.
  - **cmd/catchupsrv** ([README](cmd/catchupsrv/README.md)): A tool to assist with processing historic blocks on a new node.
- **libgoal**: Exports a Go interface useful for developers of Algorand clients.
- **tools** ([README](tools/README.md)): Various tools and utilities that don’t have a better place to go.
- **tools/debug**: Holds secondary commands that assist developers during debugging.
- **tools/misc** ([README](tools/misc/README.md)): Small tools that are handy in a pinch.

### Deployment

Helps Algorand developers deploy networks of their own:

- **nodecontrol**
- **docker**
- **commandandcontrol** ([README](test/commandandcontrol/README.md)): A tool to automate a network of `algod` instances.
- **components**
- **netdeploy**

### Utilities

Provides utilities for the various components:

- **logging**: A wrapper around `logrus`.
- **util**: Contains a variety of utilities, including a codec, a SQLite wrapper, a goroutine pool, a timer interface, node metrics, and more.

### Test

- **test** ([README](test/README.md)): Contains end-to-end tests and utilities for the above components.

## License

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](COPYING)

Please see the [COPYING_FAQ](COPYING_FAQ) for details on how to apply our license.

Copyright (C) 2019-2024, Algorand Inc.

