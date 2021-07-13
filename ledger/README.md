# Ledger

The ledger represents the state of an Algorand node.  The core state of
the ledger is a sequence of blocks (the blockchain).  The ledger also
maintains several _trackers_: state machines that consume the blockchain
as input.  One example of a tracker is the account state tracker, which
keeps track of the state of individual accounts (balance, status, etc).

The external API for the ledger (for use by callers outside of this
package) is defined in `ledger.go`.

## Blocks

The ledger exposes the following functions for managing the blocks:

- `AddBlock(block, cert)` adds a new block to the ledger, along with a
  certificate for that block.  The ledger does _not_ check the
  certificate's validity.  If the block is not from the correct round
  (i.e., latest known plus one), an error is returned.  The block is
  added to an in-memory queue of pending blocks, and is flushed to
  disk in the background for performance.

- `WaitForCommit(round)` waits for the block for `round` to be written
  to persistent storage.  After `WaitForCommit(round)` returns, the
  ledger guarantees that the block will be present even after a crash.

- `Latest()` returns the last block added to the ledger.

- `LatestCommitted()` returns the last block written to durable storage
  as well as the round of the latest block added to the ledger.

- `Block(round)` returns the block for `round`, or `ErrNoEntry` if no
  such block has been added.  Similarly, `BlockCert(round)` will return
  the block and the associated certificate.

- `Wait(round)` allows the caller to wait for a block to be added to
  the ledger for `round`, by returning a channel that will be closed
  when a block for `round` is added.

## Tracker API

The ledger comes with a set of trackers.  Each tracker maintains a
state machine based on the blockchain contents.  Trackers are logically
stateless: that is, they can reconstruct their state by consuming
all blocks from the beginning of the blockchain.  As an optimization,
the ledger allows trackers to store persistent state, so that they can
reconstruct their state quickly, without considering every block.

The interface between ledger and trackers is defined in `trackers.go`.

Trackers have access to the ledger through a restricted API defined by
`ledgerForTracker`.  This allows trackers to access the ledger's SQLite
database, to query for blocks, etc.

Conversely, the ledger accesses trackers through the `ledgerTracker`
interface:

- `loadFromDisk(ledgerForTracker)` initializes the state of the tracker.
  The tracker can use the `ledgerForTracker` argument to load persistent
  state (e.g., for the accounts database).  The tracker can also query
  for recent blocks, if the tracker's state depends only on recent blocks
  (e.g., for the tracker that keeps track of the recently committed
  transactions).

- `newBlock(rnd, delta)` tells the tracker about a new block added to
  the ledger.  `delta` describes the changes made by this block; this
  will be described in more details under block evaluation later.

- `committedUpTo(rnd)` tells the tracker that all blocks up to and
  including `rnd` are written to persistent storage.  This call is
  important for trackers that store persistent state themselves, since
  the tracker must be able to restore its state correctly after a crash,
  and may need to answer queries about older blocks after a crash if
  some recent non-committed blocks are lost.

- `close()` frees up any resources held by this tracker.

The ledger serializes all updates to the trackers with a reader-writer
lock.

## Trackers

An individual tracker exposes tracker-specific APIs for accessing the
state maintained by that tracker.  These are currently passed through the
`Ledger` object, so that the ledger can provide appropriate reader-writer
locking.

### Account tracker

- `Lookup(round, address)` uses the account tracker to look up the
  state of an account as of `round`.

- `AllBalances(round)` uses the account tracker to return the set
  of all account states as of `round`.  This is likely to be large,
  so it's intended for debug purposes only.

- `Totals(round)` returns the totals of accounts, using the account
  tracker.

### Time tracker

- `Timestamp(round)` uses the time tracker to return the time as
  of `round`.

### Recent transactions tracker

- `Committed(txnid)` returns whether `txid` has been recently committed,
  using the transaction tail tracker.

### Participation tracker

- `ParticipationThresholds()` returns the participation thresholds,
  from the participation tracker.

### Delegator tracker

- `DumpDelegatorsTree()` returns the tree of delegators for offline
  rewards, from the delegator tracker, for debug purposes.

### Notification tracker

- `RegisterBlockListeners(listeners)` registers listeners for new
  blocks, based on the `pools.BlockListener` API.

## Block evaluation

Finally, the ledger implements logic to evaluate blocks.  It supports
three functions:

- Construct a new block, based on a pool of potential transactions
  and rewards, that will be valid.  This is done by using
  the `Ledger.StartEvaluator(hdr, paysetHint, maxTxnBytesPerBlock)` method.
  This returns a `BlockEvaluator`, which can then accept tentative transactions
  and rewards (using `BlockEvaluator.Transaction()` and
  `BlockEvaluator.Reward()`).  The caller can finalize the block by
  calling `BlockEvaluator.GenerateBlock()`.  `paysetHint` provides a hint
  to the evaluator for the upcoming number of transactions. `maxTxnBytesPerBlock`
  allows the evaluator to adjust the size of the block dynamically.

- Validate a block.  This is done by calling `Ledger.Validate(block, txcache)`.
  Under the covers, it executes the same logic using a `BlockEvaluator`.

- Evaluate a block to produce a `delta` describing the changes that
  this block implies for all of the trackers.  This is the `delta`
  passed to the `newBlock()` method of trackers.

Block evaluation also produces auxiliary state, `evalAux`, which describes
the state needed to evaluate a block.  Currently, this consists of
the set of offline rewards.  Computing `evalAux` may require access to
past blocks or the old state of various state trackers (in particular,
for the offline rewards, it requires access to the past state of the
delegator tracker).  However, given an `evalAux`, it is possible to
evaluate the block.  The `BlockEvaluator` computes the `evalAux` when
first evaluating a block, and the ledger saves the `evalAux` state to
re-evaluate the block after a crash as needed.
