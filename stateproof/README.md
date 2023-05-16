# StateProof

## Background

A State Proof is a cryptographic proof of state changes that occur in a given set of blocks. State Proofs are created and signed by the network.
The same participants that reach consensus on new blocks sign a message attesting to a summary of recent Algorand transactions. 
These signatures are then compressed into a compact certificate of collective knowledge, also known as a State Proof.
After a State Proof is created, a State Proof transaction, which includes the State Proof and the message it proves, is created and sent to the Algorand network for validation. 
The transaction goes through consensus like any other pending Algorand transaction: it gets validated by participation nodes, included in a block proposal, and written to the blockchain.

The crypto package implements the cryptography behind State Proofs. This package, stateproof, implements the orchestration logic for State Proofs. 
Specifically, it is responsible for the following:
- Producing signatures for State Proof messages for online accounts.
- Collecting signatures in order to create a State Proof. 
- Gathering block information and online account balances from the ledger.
- Generating the State Proof transactions


## State Proof Modules

- `verify` responsible for making a decision on whether or not to accept a State Proof for the round
  in which it is was proposed. The network aims to accept the most compact State Proof
  it can produce while also producing a State Proof every `StateProofInterval` rounds.
  For this reason, the network might not accept a valid State Proof when there is a chance a better (more compact) State Proof could be produced.
- `Signer` A go-routine that is triggered on every new block.
  - Generates the State Proof message when needed.
  - Signs the message using every online account's private State Proof key.
  - Persists signatures into the State Proof database.
- `Builder` A go-routine that is triggered on every new block.
  - Broadcasts participants' signatures over gossip. In order to prevent network congestion, every address has a designated round slot
  in which it can send its signature.
  - Creates a State Proof transaction and passes it to the transaction pool once enough SignedWeight is collected. It does this by
    keeping track of `stateproof.Prover` for every target State Proof round.
  - Responsible for removing `stateproof.Prover` data structure, signatures, and ephemeral keys once the relevant State Proof is committed.

  In addition, the `Builder` module implements the signature verification handling procedure. A relay invokes this procedure on every signature it receives
  to make sure that it collects only valid signatures for the State Proof.

## State Proof Chain Liveness

The Algorand ledger only stores a limited number of historical blocks and online account balances (needed for the creation of State Proofs). If the State Proof
chain were to lag behind regular consensus, this could theoretically make it impossible to create new State Proofs. For this reason, the `Builder`
maintains its own database and backs-up necessary data from the ledger so that it can create State Proofs even if the ledger is far ahead.

On catchup scenarios, The `Builder` gets notified (`OnPrepareVoterCommit`) before the ledger removes data and stores it into the State Proof database.

