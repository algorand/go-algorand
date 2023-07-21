# Agreement

```
           ^_^        :o)
            o          o
    :-O                      ಠ_ಠ
     o [B]->                  o
:-)     |                        >:(
 o      V                         o
    x_x                      uwu
     o                        o
           :-)        :-3
            o          o
```

The Algorand Byzantine Agreement protocol enables all nodes to
consistently update the state of the system.

The `agreement.Service` establishes a consensus on the ordering of
`Blocks`. This ordering is defined by a `Round` number, which indexes
into the ordered log of `Blocks`.

Clients instantiate an `agreement.Service` by providing it several
parameters:
 - `Ledger` represents a data store which supports the reading and
   writing of data stored within `Block`s.
 - `BlockFactory` produces `Block`s for a given round.
 - `BlockValidator` validates `Block`s for a given round.
 - `KeyManager` holds the participation keys necessary to participate
   in the protocol.
 - `Network` provides an abstraction over the underlying network.
 - `timers.Clock` provides timekeeping services for timeouts.
 - `db.Accessor` provides persistent storage for internal state.

 `Block`s for which consensus is completed are written using
 `Ledger.EnsureBlock` alongside `Certificate` objects, which are
 cryptographic proofs that a `Block` was confirmed for a given
 round.

If `Ledger` and `db.Accessor` provide crash-safe storage, `agreement`
will also recover safely after crashes.

## Specification

The specification for the protocol implemented by this package is
located [here](https://github.com/algorandfoundation/specs).

Optimizations from and other deviations from the spec will be noted
throughout this file.

### Terminology

Certain terms in this implementation are used as shorthands for
specific concepts:
 - "Threshold" and "quorum" both refer to the total weight of votes
   needed to form a bundle for a given value.
 - A "proposal-vote" refers to a vote whose step is "propose"=0.
 - A "payload" refers to the body of a proposal which contains, among
   other fields, a `Block`.
 - "Freshness" generally refers to the relevance of some message or
   event.  Message relay rules which refer to a round, period, or step
   may be referred to as freshness rules.  Freshness may also be used
   to describe the relevance of bundles.
 - The "frozen" value in a period p refers to the proposal-value in the
   proposal-vote which was observed by the state machine to have the lowest
   credential (i.e., mu(S, r, p)).
 - The "staging" value in a period p refers to the proposal-value which received
   a quorum of soft votes (i.e., sigma(S, r, p)).
 - Additional terminology is described in the [agreement service doc](../docs/agreement_service.md).

## Design

At the top level, an `agreement.Service` encapsulates the parameters
and the goroutines which execute the protocol.

Our implementation divides its tasks into two components: a
concurrent component, which communicates with the network, disk, and
timeouts, and performs expensive CPU operations, and a serialized
state machine, which executes protocol logic and makes decisions on
what abstract actions to take.

These two components communicate with each other using the
abstractions of `event`s and `action`s. `event` objects describe
communication from the concurrent component to the state machine,
encapsulating external input to the machine. For each input `event`,
the state machine emits an output `[]action`, which lists a sequence
of control operations and operations which are potentially observable
by the outside universe. Communication occurs between these components
through a pair of Go channels in `service.demuxLoop` and
`service.mainLoop`.

`event`s are also used for internal communication between components
of the state machine.

The concurrent and serialized components share a variety of static
data structures, such as `vote`, `bundle`, and `proposal`. These data
types have distinct unauthenticated versions, which allows routines to
specify that they accept untrusted input.

## Concurrent Component

The `demux` object demultiplexes over a variety of channels which all
represent inputs to the system. Inputs include:
 - Receiving a message from the `Network`
 - Receiving a timeout from the `Clock`
 - Notification to stop waiting for a block in the current `Round`
   (`Ledger.Wait`)
 - Authenticated messages from the `cryptoVerifier`

The `cryptoVerifier` parallelizes expensive cryptographic operations
such as authentication of votes, bundles, and proposal payloads so as
to maximize CPU core utilization.

A special case of the node behavior is encapsulated in the
`pseudonode`: to increase ease of testing and to minimize code
duplication, the state machine produces votes and proposals by
directing the pseudonode to create them from participation key
data. The pseudonode then directs the votes and proposals back to the
state machine, as if they arrived from some external source. The state
machine validates these messages in the same way it validates real
network messages and relays them back into the network as
appropriate.

### Spec Notes: Additional Events

Because signature verification is expected to be a computational
bottleneck in the agreement code, it executes concurrently with
respect to the state machine.  As a result, the relay rules described
in the specification of the protocol are altered slightly: for
instance, properties of messages are checked twice when determining
whether to ignore them: once before cryptographic verification, and
once after cryptographic verification.  Checking before cryptographic
verification is not strictly necessary but is an optimization that
reduces CPU costs in non-adversarial cases; e.g., duplicate votes are
discarded before signature verification is attempted.

In the specification, each participant in the agreement protocol is
associated with a single set of keys.  In practice, nodes may wish to
participate on behalf of many keys simultaneously.  These keys are
encapsulated in the `KeyManager`, and the `pseudonode` allows the
agreement protocol to multiplex across these keys.  For all intents
and purposes, these keys may be modelled as distinct participants
which all exhibit identical behavior, and whose messages are all
serialized through a single participant.  For instance, if two keys
are both selected to propose a block, then this node may or may not
transmit the block belonging to the key with the lower-priority
credential.

This implementation thus extends the set of "external" events handled
by the state machine.  In addition to handling timeouts and network
events, the state machine thus also handles concurrent writes to the
`Ledger` via `Wait`, and it handles the output of cryptographic
verification concurrently.  Moreover, the implementation abstracts
over multiple keys by generating synthetic network events from the
`pseudonode`.

## Serialized State Machine

The logic of the agreement protocol is implemented as a state machine.
This state machine is composed of many smaller state machines, which
represent different subtasks required by the protocol. All state
machines communicate with each other by sending `event`s to each other
and by receiving `event`s as replies (except for `player`, which is at
the root of the state machine tree). This communication takes place
through the `router`, which relays messages between machines. After it
receives a message, a state machine will `handle` it, producing an
`event` in response and possibly updating its own state.

For the router to route information correctly, all instances of all
state machines must be uniquely identified for the router. Every
_type_ of state machine corresponds to a unique `stateMachineTag`
(`<machine>.T()`). Certain state machines have many _instances_; for
instance, there is one machine which tracks votes for each step, and
there is one machine which tracks proposals for each period. These
instances are distinguished from each other by a
(round, period, step)-triplet.  For a given type of state machine, the
less specific fields in the triplet are ignored: for example, to send
a message to the state machine handling proposals in round 100,
period 2, both (100, 2, 0) and (100, 2, 6) identify this instance,
since it handles messages for any step in period 2.

State machines are arranged hierarchically in the _state machine
tree_.  At the top of the tree is the `player`, which has two
children: the root vote machine and the root proposal machine.  The
vote machines and the proposal machines are both hierarchically
arranged first by round, then by period, and finally by step.  Thus
the hierarchy is as follows:
 - player
   - vote
     - vote round 0
       - vote (round, period) (0, 0)
         - vote (round, period, step) (0, 0, 0)
         - vote (round, period, step) (0, 0, 1)
         - ...
       - vote (round, period) (0, 1)
       - ...
     - vote round 1
     - ...
   - proposal
     - proposal round 0
       - proposal (round, period) (0, 0)
         - proposal (round, period, step) (0, 0, 0)
         - proposal (round, period, step) (0, 0, 1)
         - ...
       - proposal (round, period) (0, 1)
       - ...
     - proposal round 1
     - ...
A state machine in the hierarchy can deliver events and queries to any
of its children but not its parents.  All state machines also receive
a read-only copy of the `player` state when receiving any event.

State machines may be wrapped in `Contract`s which specify pre- and
post-conditions for events received and emitted by a state machine.
These contracts may be checked at runtime to find violations and
possible bugs.

The `tracer` records the path of messages as they travel through the
state machine for debugging, inspection, and post-mortem
functionality.

## The `player` machine

The root of the state machine tree is the `player` machine. This
machine holds the current `round`, `period`, and `step` of the node,
as well as some metadata to ensure correct propagation of received
messages. All events are first routed to the `player`, which may
forward them to other state machines. `player` is special in two ways:
first of all, it is an event `actor`, which means that its `handle`
method emits `[]action`, and second, it is passed (by value) to all
children state machines so that they are aware of the current state of
the node.

The `player` consumes `messageEvent`s which it forwards to the
appropriate state machines. `bundle`s and non-proposal-`vote`s (i.e.,
votes with step =/= 0) are forwarded to the vote threshold machines,
while `proposalPayload`s and proposal-`vote`s (i.e. votes with step =
0) are forwarded to the proposal machines. Based on their outputs, the
`player` chooses to `relay` or `ignore` these messages.

The `player` consumes `timeout`s events.  The `player` communicates
its next timeout by setting its `Deadline` and `Napping` fields.

The `player` produces `action`s which transmit messages to the
`pseudonode` (e.g., `attest` to `vote`s, `assemble` `Block`s,
`repropose` `proposals`) when appropriate. The player may issue
queries to determine how to vote; for instance, the `player` will
ask the proposal machine whether a `Block` is "committable" i.e.,
whether the entire `Block` has arrived along with a soft-threshold for
that digest.

The `player` changes the round and period of the node according to
`thresholdEvent`s it receives from the vote threshold machine (and
also potentially upon receiving a `roundInterruptionEvent`). It
changes `step` according to timeout events it has received. On
conclusion of a round, the `player` queries the `Block` from the
proposal machine and then writes them along with the `Certificate` to
the `Ledger`.

The remaining state machines are subordinate to `player` and handle
two broad kinds of functonality: detecting when a threshold of `vote`s
has been reached, and managing `Block` proposals. The `voteMachine`s
create `thresholdEvent`s and gives them to the `player` machine, while
the `proposalMachine`s track proposals and reconstruct them from
network messages.

### Spec Notes: Reordering

In the spec of the agreement protocol, messages are delivered on an
ordered but best-effort basis.  This means that the agreement protocol
is resilient to message reordering in the network layer.  However,
good ordering improves the liveness of the agreement protocol and
improves the rate at which the protocol converges.

One ordering constraint which impacts performance and also test
reliability is the ordering of proposal-votes with respect to their
matching proposal payloads.  If the proposal payload is received
before its corresponding proposal-vote, the agreement protocol will
drop the payload and must recover into a new period.

The introduction of a concurrent cryptographic verification pool
exacerbates this problem: a received proposal-vote will enter
cryptographic verification before any state changes.  If the
corresponding payload arrives before cryptographic verification
finishes, which is likely on a fast network or on a machine with a
loaded CPU, the node will drop the payload and must again recover into
a new period.

As a result, the implementation bundles together matching
proposal-votes and proposal payloads into a `compoundMessage`.  Nodes
process a `compoundMessage` by first processing the proposal-vote (if
it exists) and then following by processing the payload afterwards.
To retain a handle on the proposal payload associated with a
proposal-vote which is sent into the `cryptoVerifier`, the `player`
maintains a `proposalTable` which associates outstanding proposal-vote
verification requests with their corresponding payload.

## The vote threshold machines

The vote threshold machines convert votes and bundles into events
which signal that a quorum of valid votes has formed for some step and
for some value.

At the root level, the `voteAggregator` receives raw and authenticated
network messages that hold votes and bundles. It performs basic
duplicate filtering and then forwards these messages to
`voteTrackerRound` machines.

In addition to forwarding these messages to `voteTrackerPeriod`
machines, `voteTrackerRound` machines also hold the _freshest_
threshold event which they have seen. This serves two purposes: on
arriving in a new period, the `player` must process any threshold
event which has been pipelined, and during partitions, these events
hold bundles which the node must propagate to neighbors.

`voteTrackerPeriod` machines respond to queries for the thresholds
which have been observed by the node in some period.

`voteTracker` machines implement the core vote counting logic for a
given step.  Whenever the number of votes passes the threshold
required for that step, the machine generates the threshold event
exactly once and then returns the event up the state machine tree.  It
also records duplicate votes received in a given period, up to sender
equivocation.

## The proposal management machines

The proposal management machines track and store `Block` proposals
across periods as the node executes the Byzantine Agreement protocol.

The `proposalManager` receives raw and authenticated `proposalPayload`
messages. It also receives raw and authenticated `vote`s for which
`step = 0 (= propose)`. These special "proposal-votes" represent the
proposal messages `Block` proposers send at the beginning of a round
and propagate in the network independently from the `Block`s
themselves, which are contained in `proposalPayload` messages.

The `proposalManager` performs duplicate filtering and then forwards
messages as appropriate. It also issues the control messages required
to change round and period.

The `proposalStore` tracks the set of proposal-values and payloads
which are relevant to a given round.  It also maintains the correct
setting of the _pinned_ proposal-value.  When a new period arrives, it
garbage-collects old proposals and updates the pinned value as
necessary.  When a new round arrives, it returns any enqueued payload
events as necessary.

The `proposalTracker` maintains two proposal-values: one corresponding
to the lowest proposal-credential seen in a period (the _frozen_
proposal-value), and one corresponding to the sole value for which a
quorum of soft-votes has been observed in the period (the _staging_
proposal-value).  It also records duplicate proposal-votes received in
a given period.

The staging slot for a given period is important because its state is
the precursor to cert and next votes. Once both a soft threshold for a
value and the `Block` corresponding to this value has been observed by
the node, a proposal `committableEvent` is emitted, which indicates
that the node may cert or next-vote for the proposal.
