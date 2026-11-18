# go-algorand threat model

go-algorand is the reference implementation of the Algorand blockchain: the `algod` node (consensus, networking,
ledger, transaction processing, the AVM smart contract VM, and the REST API), the `kmd` key management daemon, and
CLI tools such as `goal` and `algokey`.

## Who is trusted

| Source | Trust | Notes |
|---|---|---|
| Gossip peers (WebSocket and P2P), inbound and outbound | Untrusted | Anyone can connect to a relay. Relays are run by known operators, but nodes must not rely on them for safety. |
| Transactions, transaction groups and AVM programs | Untrusted | Anyone can submit transactions and deploy or call programs, paying only fees and minimum balances. |
| Consensus messages, and blocks and certificates fetched during catchup | Untrusted | Must not break safety or liveness without more stake than the protocol assumes (see Protocol versions). |
| algod REST API, with the non-admin token | Untrusted | Public API endpoints are common; treat the non-admin token as known to an attacker. |
| algod admin API token holders | Trusted | |
| kmd API token holders | Trusted | A caller without the token, or without the wallet password, must not obtain keys or signatures. |
| Catchpoint labels and files used for fast catchup | Trusted | The catchpoint label must come from a source the operator trusts. |
| The local machine: data directory (`config.json`, `genesis.json`, ledger databases, participation keys, token files), kmd wallet files, flags, environment | Trusted | Anything needing local access or write access to these is out of scope. A corrupted file counts only if a remote party, or an ordinary event such as a crash or full disk, can produce it. |
| Callers of `goal`, `algokey`, `libgoal` and other CLI tools | Trusted | Their arguments (data directories, file paths, wallet names) are not attacker-controlled. A malicious remote node or API response compromising a CLI or `libgoal` user is in scope. |

## Scope

Everything in `algod` and `kmd` is in scope. Prioritise code reachable from the untrusted sources above.

Block evaluation must be deterministic. Any behaviour that can differ between nodes splits consensus. Examples
include map iteration order, platform or architecture differences, floating point, timing, and resource use that
some nodes survive and others do not.

Out of scope: `test/`, `tools/`, `netdeploy`, `nodecontrol`, `gen/`, `scripts/`, `installer/`, `docker/`,
`cmd/pingpong`, and other load-testing and developer tooling. Third-party Go dependencies and upstream libsodium code
count only when go-algorand reaches the affected code. Algorand-specific code in `crypto/libsodium-fork` (VRF and
related changes) is in scope.

## Protocol versions

Consensus rules are versioned in `config/consensus.go`. Behaviour only enabled in `vFuture`, or only reachable
under consensus versions MainNet has already moved past, cannot currently affect MainNet. Still report it, but say
which consensus versions are affected and rate it one level lower than the same bug in the current protocol. A bug in
`vFuture` that would become live in the next upgrade is still worth reporting promptly.

Attacks that require more stake or network control than Algorand's security assumptions allow (for example,
controlling a large fraction of online stake, or partitioning the network for long periods) are not vulnerabilities
on their own. An attack that breaks safety or liveness with less than that is.

## Configuration

Rate findings against the defaults in `config/localTemplate.go`, and name any non-default options a finding needs.
Two deployments are standard, not unusual configurations:

- **Relays**: `NetAddress` set to accept incoming gossip connections, usually with `EnableBlockService` enabled.
- **P2P and hybrid networking** (`EnableP2P`, `EnableP2PHybridMode`): off by default, but used by node operators
  today. Rate libp2p findings like the same bug in the WebSocket network.

Findings that need these off-by-default debugging or developer features are lower severity, typically one level
down: `EnableDeveloperAPI`, `EnableExperimentalAPI`, `EnableProfiler`, `EnableTxnEvalTracer`, `EnableFollowMode`,
`DisableAPIAuth`, and the various metrics and logging options.

Behaviour in `devMode` or single-node private networks created for testing is out of scope unless it also applies to
normal networks.

## How to exercise it

- Unit tests are colocated with the code. `data/transactions/logic` has helpers for running programs directly
  (see `testApp`, `testProg` and friends in its `*_test.go` files). Ledger evaluation tests in `ledger/` use the
  helpers in `ledger/testing` and `ledger/simple_test.go`-style setups to apply transactions to a test ledger.
- Run tests with the same tags CI uses, which the image sets in `GOFLAGS`:
  `go test -run TestName ./path/to/package`. Add `-race` for concurrency bugs.
- End-to-end tests in `test/e2e-go` start local private networks of real `algod` processes, using binaries in
  `/go/bin` (already built). `NODEBINDIR`, `TESTDATADIR` and `TESTDIR` are set in the image. See `AGENTS.md`.
- `/go/bin/algod`, `goal`, `kmd`, `algokey`, `msgpacktool` and the other binaries are installed in the image.
- Unit tests run with `go-deadlock` enabled, which reports lock-order inversions and locks held too long. The
  installed binaries have it off, as in release builds. A deadlock that a peer, transaction or API request can
  trigger is a node stall: report it.

## How we rate severity

- **Critical**: consensus safety failures (forks, two certified blocks for one round, nodes disagreeing on
  ledger state); creating, stealing, freezing or destroying funds, assets or application state without
  authorization; bypassing signature, multisig, LogicSig, VRF or state proof verification; a transaction, program,
  or unauthenticated network message that crashes or halts most nodes, or halts block production; remote code
  execution on a node.
- **High**: crashing or stalling a single node, or exhausting its memory, CPU or disk, by an unauthenticated peer or
  a submitted transaction with modest resources; causing a node to accept forged blocks through block-by-block
  catchup; AVM budget, cost or fee accounting bypasses; kmd key or signature disclosure without the
  token or wallet password; admin-only algod API actions reachable without the admin token.
- **Medium**: denial of service that requires sustained or significant attacker resources or the non-admin API
  token; algod REST API denial of service; information disclosure beyond what is public on chain.
- **Low**: issues requiring operator misconfiguration or a malicious local user, hardening, and CLI-only issues.

## Reports and patches

- One report per root cause. If the same bug is reachable from several entry points (e.g. both gossip and the
  REST API), list them in one report.
- Provide the reproducer as a Go test: a unit test in the package it targets, or an e2e test under `test/e2e-go`
  when the bug needs real nodes or a network.
- Patches should be minimal, follow the surrounding style, and include a regression test. If a fix changes
  consensus behaviour, say so explicitly: such fixes must be gated behind a new consensus parameter, and the patch
  should show where that gate would go.
