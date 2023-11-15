# Follower Node

When started with `"EnableFollowMode": true`, algod starts with a special
property which allows it to be paused. This allows software to be written
which runs synchronously with a node. If you need account balances at each
round, or at a particular round, this is the only way to do it. On start
the node will be paused, the REST API is used to resume and select a new
round.

It also allows fetching a `Ledger State Delta` object for recent rounds.
This object is not designed for external users, but may be useful for
advanced applications if you're willing to figure things out. It contains
complete information for transitioning a database to the next round,
including new account balances, changes to application and asset states,
and new box information. Such information was previously unavailable to
application developers.

This mode has a number of [restrictions](#restrictions), which are described
below.

Follower mode was initially created to be a data source for [Conduit](https://github.com/algorand/conduit).

## Configuration

Behavior is controlled with the `config.json` file:

| property | description |
| -------- | ----------- |
| EnableFollowMode | When set to `true` the node starts as a network follower. |
| MaxAcctLookback | The number of additional `Ledger State Delta` objects available. The default can be used, increasing to 64 or higher could help performance. |
| CatchupParallelBlocks | The number of blocks that are fetched concurrently. The default can be used, increasing to 64 or higher could help performance. |

## Usage

On startup, a follower node will be paused (synchronized) with its ledger's
current round. For a new deployment configured as a follower node, the
initial sync round is 0. When a sync round is set, the node advances
`MaxAcctLookback-1` rounds. The node is synchronized for the availability
of `Ledger State Delta` data. This means the minimum sync round is provided
and the node advances to cache future rounds.

New public endpoints are available to control the sync round:
* `GET /v2/ledger/sync` - fetch the current sync round.
* `DELETE /v2/ledger/sync` - resume normal catchup by deleting the sync round.
* `POST /v2/ledger/sync/{round}` - set the sync round.

The `Ledger State Delta` is not designed for external consumption, but may
still be useful for advanced applications. When the sync round is set, this
endpoint can be used to fetch the `Ledger State Delta` for that round and up
to `MaxAcctLookback - 1` ahead of it:
* `GET /v2/deltas/{round}` - Fetch the raw Ledger State Delta, optionally provide `format=msgp` for the internal msgp encoded object.

## Restrictions

The follower node was stripped of all functionality not directly related to
assisting with data-gathering capabilities. Since it is designed to run
alongside another application, it was made as lightweight as possible.
Other restrictions relate to the fact that this node is designed to be
paused. So there are no guarantees that its internal state matches the
current round of consensus.

In particular, the follower node cannot participate in consensus or send
transactions to the network. Any attempt to register participation keys or
submit transactions will be rejected.
