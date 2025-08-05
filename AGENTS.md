# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Common Development Commands

### Build
```bash
make build          # Build all binaries
make install        # Build and install binaries to $GOPATH/bin
make buildsrc       # Build main source (faster than full build)
```

### Testing
```bash
make test           # Run unit tests
make fulltest       # Run unit tests with race detection
make shorttest      # Run short tests with race detection
make integration    # Run integration tests
make testall        # Run all tests (unit + integration)
```

### Code Quality
```bash
make sanity         # Run all checks (fmt, lint, fix, tidy)
make fmt            # Format code and check licenses
make lint           # Run linter (requires deps)
make fix            # Run algofix tool
make vet            # Run go vet
make tidy           # Clean up go.mod files
```

### Code Generation

Some code must be re-generated after changes. Run the following to regenerate auto-generated code if changes are made to relevant files.

```
make rebuild_kmd_swagger                       # Rebuild swagger.json files
make generate                                  # Regenerate for stringer et al.
make expectlint                                # Run expect linter
touch data/transactions/logic/fields_string.go # Ensure rebuild of teal specs
make -C data/transactions/logic                # Update TEAL Specs
touch daemon/algod/api/algod.oas2.json         # Ensure rebuild of API spec
make -C daemon/algod/api generate              # Regenerate REST server
make msgp                                      # Regenerate msgp files
```

To verify that this wasn't missed, we run verification steps, which can be found in `scripts/travis/codegen_verification.sh`. If code is not clean, it will fail CI checks.

### Development Setup
```bash
./scripts/configure_dev.sh                    # Initial environment setup
./scripts/buildtools/install_buildtools.sh   # Install build tools
make deps                                     # Check/install dependencies
```

### Single Test Execution
```bash
go test -v -run TestName ./path/to/package    # Run specific test
go test -v ./agreement/...                    # Run tests in package tree rooted at agreement
go test -v ./agreement/                       # Run tests for just the agreement package
```

### Running E2E tests
E2E tests run one or more algod processes, each with their own data directory containing logs and configuration (created in a subdirectory of TESTDIR). If an E2E test fails, useful information can often be found in the node.log files produced by algod while running the test. For example:
```bash
export NODEBINDIR=~/go/bin # path to algod, goal, etc. Code changes to goal or algod require rebuilding with "make" to place new binaries here before running E2E tests.
export TESTDATADIR=`pwd`/test/testdata # path to go-algorand/test/testdata
export TESTDIR=/tmp
# network and node data will be created in /tmp/TestAssetSend/, logs in /tmp/TestAssetSend/Primary/node.log and /tmp/TestAssetSend/Node/node.log
go test ./test/e2e-go/features/transactions -run TestAssetSend -v -timeout=0
```

## Architecture Overview

### Main Binaries
- **`algod`**: Core blockchain node daemon (consensus, networking, REST API)
- **`kmd`**: Key Management Daemon (secure wallet operations, isolated process)
- **`goal`**: Primary CLI tool for node interaction and account management
- **`algokey`**: Standalone key generation and management utility

### Core Components

#### Node Layer (`node/`)
Central orchestrator that integrates all subsystems. The `AlgorandFullNode` struct manages:
- Ledger state and transaction pool
- Network communication and message routing
- Agreement service for consensus participation
- Catchup service for blockchain synchronization

#### Agreement Layer (`agreement/`)
Implements Algorand's Byzantine Agreement protocol:
- **Service**: Main consensus coordinator
- **State Machine**: Manages consensus rounds, periods, and steps
- **Vote/Proposal Managers**: Handle consensus message flow
- **CryptoVerifier**: Asynchronous signature verification

#### Ledger Layer (`ledger/`)
Manages blockchain state using tracker-based architecture:
- **Blockchain Storage**: Sequential block storage with certificates
- **Trackers**: Independent state machines consuming blockchain events
  - `accountUpdates`: Account balances and application state
  - `acctsOnline`: Online account tracking for consensus
  - `catchpointTracker`: Catchpoint generation for fast sync
  - `txTail`: Recent transaction tracking
- **Atomic Updates**: Coordinated state transitions across trackers

#### Network Layer (`network/`)
Supports multiple networking implementations through `GossipNode` interface:
- **WebSocket Network**: Traditional relay-based topology
- **P2P Network**: LibP2P-based peer-to-peer networking
- **Hybrid Network**: Combines both approaches

#### Data Layer (`data/`)
- **Transaction Pool**: Manages pending transactions
- **Transaction Handler**: Processes incoming network transactions
- **Account Manager**: Handles participation key lifecycle
- **Core Types**: Transactions, blocks, accounts, and protocol structures

#### Cryptography (`crypto/`)
- Ed25519 signatures, multisig, LogicSig (smart signatures)
- VRF (Verifiable Random Functions) for consensus leader selection
- State proof cryptography for light client verification
- Merkle tree implementations for data integrity

### Key Architectural Patterns

#### Interface-Based Design
System boundaries defined by Go interfaces:
- `GossipNode`: Network abstraction
- `BlockValidator`/`BlockFactory`: Consensus integration
- `Ledger`: Storage abstraction
- `KeyManager`: Cryptographic operations

#### Tracker Pattern
Ledger uses independent state machines that can rebuild from blockchain events, enabling:
- Stateless tracker logic with optional persistent caching
- Atomic coordinated updates across different state types
- Efficient state rebuilding and validation

#### Concurrent Architecture
- Agreement service separates concurrent I/O from serialized protocol logic
- Crypto verification runs in dedicated thread pools
- Network and disk operations use separate goroutines

#### Security Isolation
- KMD runs as separate process to isolate key material
- Transaction verification separated from consensus participation
- Clear boundaries between trusted and untrusted operations

## Development Guidelines

### Testing Strategy
- Unit tests focus on individual component logic
- Integration tests verify cross-component interactions
- Race detection enabled for concurrent code validation
- Benchmark tests for performance-critical paths

### Code Organization
- Interface-first design for testability and modularity
- Dependency injection for component assembly
- Clear separation between protocol logic and implementation details
- Consistent error handling patterns throughout

### Performance Considerations
- Tracker pattern enables efficient state caching
- Asynchronous block writing with in-memory queues
- Parallel transaction verification
- Catchpoint mechanism for fast node synchronization

### Protocol Evolution
- Consensus parameters support versioning for upgrades
- Backward compatibility maintained through careful interface design
- Feature flags and gradual rollout mechanisms
