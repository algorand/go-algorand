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

## Configuration

Several options in the `config.json` file are needed:

| property | description |
| EnableFollowMode | When set to `true` the node starts as a network follower. | 
| MaxAcctLookback | The number of additional `Ledger State Delta` objects available. |
| CatchupParallelBlocks | This is useful for performance tuning. |

## Usage

New public endpoints are available to control the node:
* `GET /v2/ledger/sync` - fetch the current minimum sync round.
* `DELETE /v2/ledger/sync` - resume normal catchup by deleting the sync round.
* `POST /v2/ledger/sync/{round}` - set the sync round.

The `Ledger State Delta` object is not designed for external consumption,
but may still be useful for advanced applications:
* `GET /v2/deltas/{round}` - Fetch the raw Ledger State Delta, optionally provide `format=msgp` for the internal msgp encoded object.

## Performance

Increasing `MaxAcctLookback` and `CatchupParallelBlocks` is helpful for
increasing performance. We have found `64` to be a good value which allows
algod to at near full speed while a fast synchronous application processes
`Ledger State Delta` objects.

## Restrictions

The follower node was stripped of all functionality not directly related to
assisting with data-gathering capabilities. Since it is designed to run
alongside another application, it was made as lightweight as possible.
Other restrictions relate to the fact that this node is designed to be
paused. So there are no guarantees that it's internal state matches the
current round of consensus.

In particular, the follower node cannot participate in consensus or send
transactions to the network. Any attempt to register participation keys or
submit transactions will be rejected.
