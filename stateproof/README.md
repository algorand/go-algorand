# StateProof

The stateproof package implements the orchestration logic for state proof. 
While the crypto package implements the cryptography behind state proofs, this package is responsible for
- Signatures collection
- Signatures production
- Ledger data gathering
- State proof transaction generation.


## State Proof Modules

- `verify` responsible for making a decision on whether or not to accept a state proof with respect to the round
  in which it is was proposed. The network aims to accept the most compact state proof
  it can produce while on the other hand, produce a proof every `StateProofInterval` rounds.
  For that reason, the network might not accept a state proof even if it is valid in order to
  give a chance to a better (more compact) state proof to be produced.
- `Signer` A go-routine that is triggered on every new block.
  - Generates the state proof message when needed.
  - Signs the message using every online account's private state proof key.
  - Persist signatures into the state proof database.
- `Builder` A go-routine that is triggered on every new block.
  - Broadcasts participants' signatures over gossip. In order to prevent network congestion, every address has a designated round slot
  in which it can send its signature.
  - Creates a state proof transaction and pass it to the transaction pool once enough SignedWeight was collected. It does that by
  keeping track of `stateproof.Prover` for every target state proof round.
  - Responsible for removing `stateproof.Prover` data structure, signatures, and ephemeral keys once the relevant state proof is committed.
  
  In addition, `Builder` module implements the signature verification handling procedure. A relay invokes this procedure on every signature it receives
to make sure that it collects only valid signatures for the state proof.

## State Proof Chain Liveness

The ledger of the Algorand node limits the storage of blocks and online account balances (needed for the creation of state proofs). If the state proof
chain is lagging behind regular consensus this might lead to permanently lose the ability to create state proofs. For that reason the `Builder` 
maintains its own database and backs-up data from the ledger so it will be able to create state proofs even if the ledger advances.

On catchup scenarios, The `Builder` is getting notified (`OnPrepareVoterCommit`) before the ledger removes data and stores it into the state proof database.

