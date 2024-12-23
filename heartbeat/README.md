# Block Payouts, Suspensions, and Heartbeats

Running a validator node on Algorand is a relatively lightweight operation. Therefore, participation
in consensus was not compensated. There was an expectation that financially motivated holders of Algos
would run nodes in order to help secure their holdings.

Although simple participation is not terribly resource intensive, running _any_ service with high
uptime becomes expensive when one considers that it should be monitored for uptime, be somewhat
over-provisioned to handle unexpected load spikes, and plans need to be in place to restart in the
face of hardware failure (or the accounts should leave consensus properly).

With those burdens in mind, fewer Algo holders chose to run participation nodes than would be
preferred to provide security against well-financed bad actors.  To alleviate this problem, a
mechanism to reward block proposers has been created.  With these _block payouts_ in place,
Algo holders are incentivized to run participation nodes in order to earn more Algos, increasing
security for the entire Algorand network.

With the financial incentive to run participation nodes comes the risk that some nodes may be
operated without sufficient care.  Therefore, a mechanism to _suspend_ nodes that appear to be
performing poorly (or not at all) is required. Appearances can be deceiving, however. Since Algorand is a
probabilistic consensus protocol, pure chance might lead to a node appearing to be delinquent. A new
transaction type, the _heartbeat_, allows a node to explicitly indicate that it is online even if it
does not propose blocks due to "bad luck".

# Payouts

Payouts are made in every block, if the proposer has opted into receiving them, has an Algo balance
in an appropriate range, and has not been suspended for poor behavior since opting-in.  The size of
the payout is indicated in the block header, and comes from the `FeeSink`. The block payout consists
of two components. First, a portion of the block fees (currently 50%) are paid to the proposer.
This component incentivizes fuller blocks which lead to larger payouts. Second, a _bonus_ payout is
made according to an exponentially decaying formula.  This bonus is (intentionally) unsustainable
from protocol fees.  It is expected that the Algorand Foundation will seed the `FeeSink` with
sufficient funds to allow the bonuses to be paid out according to the formula for several years.  If
the `FeeSink` has insufficient funds for the sum of these components, the payout will be as high as
possible while maintaining the `FeeSink`'s minimum balance.  These calculations are performed in
`endOfBlock` in `eval/eval.go`.

To opt-in to receive block payouts, an account includes an extra fee in the `keyreg`
transaction. The amount is controlled by the consensus parameter `Payouts.GoOnlineFee`. When such a
fee is included, a new account state bit, `IncentiveEligible` is set to true.

Even when an account is `IncentiveEligible` there is a proposal-time check of the account's online
stake.  If the account has too much or too little, no payout is performed (though
`IncentiveEligible` remains true). As explained below, this check occurs in `agreement` code in
`payoutEligible()`. The balance check is performed on the _online_ stake, that is the stake from 320
rounds earlier, so a clever proposer can not move Algos in the round it proposes in order to receive
the payout. Finally, in an interesting corner case, a proposing account could be closed at proposal
time, since voting is based on the earlier balance. Such an account receives no payout, even if its
balance was in the proper range 320 rounds ago.

A surprising complication in the implementation of these payouts is that when a block is prepared by
a node, it does not know which account is the proposer. Until now, `algod` could prepare a single
block which would be used by any of the accounts it was participating for.  The block would be
handed off to `agreement` which would manipulate the block only to add the appropriate block seed
(which depended upon the proposer).  That interaction between `eval` and `agreement` was widened
(see `WithProposer()`) to allow `agreement` to modify the block to include the proper `Proposer`,
and to zero the `ProposerPayout` if the account that proposed was not actually eligible to receive a
payout.

# Suspensions

Accounts can be _suspended_ for poor behavior.  There are two forms of poor behavior that can lead
to suspension. First, an account is considered _absent_ if it fails to propose as often as it
should. Second, an account can be suspended for failing to respond to a _challenge_ issued by the
network at random.

## Absenteeism

An account can be expected to propose once every `n = TotalOnlineStake/AccountOnlineStake` rounds.
For example, a node with 2% of online stake ought to propose once every 50 rounds.  Of course the
actual proposer is chosen by random sortition.  To make false positive suspensions unlikely, a node
is considered absent if it fails to produce a block over the course of `20n` rounds.

The suspension mechanism is implemented in `generateKnockOfflineAccountsList` in `eval/eval.go`.  It
is closely modeled on the mechanism that knocks accounts offline if their voting keys have expired.
An absent account is added to the `AbsentParticipationAccounts` list of the block header. When
evaluating a block, accounts in `AbsentParticipationAccounts` are suspended by changing their
`Status` to `Offline` and setting `IncentiveEligible` to false, but retaining their voting keys.

### Keyreg and `LastHeartbeat`

As described so far, 320 rounds after a `keyreg` to go online, an account suddenly is expected to
have proposed more recently than 20 times its new expected interval. That would be impossible, since
it was not online until that round.  Therefore, when a `keyreg` is used to go online and become
`IncentiveEligible`, the account's `LastHeartbeat` field is set 320 rounds into the future. In
effect, the account is treated as though it proposed in the first round it is online.

### Large Algo increases and `LastHeartbeat`

A similar problem can occur when an online account receives Algos. 320 rounds after receiving the
new Algos, the account's expected proposal interval will shrink. If, for example, such an account
increases by a factor of 10, then it is reasonably likely that it will not have proposed recently
enough, and will be suspended immediately.  To mitigate this risk, any time an online,
`IncentiveEligible` account balance doubles from a single `Pay`, its `LastHeartbeat` is incremented
to 320 rounds past the current round.

## Challenges

The absenteeism checks quickly suspend a high-value account if it becomes inoperative.  For example,
an account with 2% of stake can be marked absent after 500 rounds (about 24 minutes). After
suspension, the effect on consensus is mitigated after 320 more rounds (about 15
minutes). Therefore, the suspension mechanism makes Algorand significantly more robust in the face
of operational errors.

However, the absenteeism mechanism is very slow to notice small accounts.  An account with 30,000
Algos might represent 1/100,000 or less of total stake. It would only be considered absent after a
million or more rounds without a proposal.  At current network speeds, this is about a month. With such
slow detection, a financially motivated entity might make the decision to run a node even if they lack
the wherewithal to run the node with excellent uptime. A worst case scenario might be a node that is
turned off daily, overnight.  Such a node would generate profit for the runner, would probably never
be marked offline by the absenteeism mechanism, yet would impact consensus negatively. Algorand
can't make progress with 1/3 of nodes offline at any given time for a nightly rest.

To combat this scenario, the network generates random _challenges_ periodically.  Every
`Payouts.ChallengeInterval` rounds (currently 1000), a random selected portion (currently 1/32) of
all online accounts are challenged.  They must _heartbeat_ within `Payouts.ChallengeGracePeriod`
rounds (currently 200), or they will be subject to suspension. With the current consensus
parameters, nodes can be expected to be challenged daily.  When suspended, accounts must `keyreg`
with the `GoOnlineFee` in order to receive block payouts again, so it becomes unprofitable for
these low-stake nodes to operate with poor uptimes.

# Heartbeats

The absenteeism mechanism is subject to rare false positives.  The challenge mechanism explicitly
requires an affirmative response from nodes to indicate they are operating properly on behalf of a
challenged account.  Both of these needs are addressed by a new transaction type --- _Heartbeat_. A
Heartbeat transaction contains a signature (`HbProof`) of the blockseed (`HbSeed`) of the
transaction's FirstValid block under the participation key of the account (`HbAddress`) in
question. Note that the account being heartbeat for is _not_ the `Sender` of the transaction, which
can be any address. Signing a recent block seed makes it more difficult to pre-sign heartbeats that
another machine might send on your behalf. Signing the FirstValid's blockseed (rather than
FirstValid-1) simply enforces a best practice: emit a transaction with FirstValid set to a committed
round, not a future round, avoiding a race. The node you send transactions to might not have
committed your latest round yet.

It is relatively easy for a bad actor to emit Heartbeats for its accounts without actually
participating. However, there is no financial incentive to do so.  Pretending to be operational when
offline does not earn block payouts.  Furthermore, running a server to monitor the blockchain to
notice challenges and gather the recent blockseed is not significantly cheaper than simply running a
functional node. It is _already_ possible for malicious, well-resourced accounts to cause consensus
difficulties by putting significant stake online without actually participating.  Heartbeats do not
mitigate that risk. Heartbeats have rather been designed to avoid _motivating_ such behavior, so
that they can accomplish their actual goal of noticing poor behavior stemming from _inadvertent_
operational problems.

## Free Heartbeats

Challenges occur frequently, so it important that `algod` can easily send Heartbeats as
required. How should these transactions be paid for? Many accounts, especially high-value accounts,
would not want to keep their spending keys available for automatic use by `algod`. Further, creating
(and keeping funded) a low-value side account to pay for Heartbeats would be an annoying operational
overhead.  Therefore, when required by challenges, heartbeat transactions do not require a fee.
Therefore, any account, even an unfunded logicsig, can send heartbeats for an account under
challenge.

The conditions for a free Heartbeat are:

1. The Heartbeat is not part of a larger group, and has a zero `GroupID`.
1. The `HbAddress` is Online and under challenge with the grace period at least half over.
1. The `HbAddress` is `IncentiveEligible`.
1. There is no `Note`, `Lease`, or `RekeyTo`.

## Heartbeat Service

The Heartbeat Service (`heartbeat/service.go`) watches the state of all accounts for which `algod`
has participation keys.  If any of those accounts meets the requirements above, a heartbeat
transaction is sent, starting with the round following half a grace period from the challenge. It
uses the (presumably unfunded) logicsig that does nothing except preclude rekey operations.

The heartbeat service does _not_ heartbeat if an account is unlucky and threatened to be considered
absent.  We presume such false positives to be so unlikely that, if they occur, the node must be
brought back online manually. It would be reasonable to consider in the future:

1. Making heartbeats free for accounts that are "nearly absent".

or

2. Allowing for paid heartbeats by the heartbeat service when configured with access to a funded
   account's spending key.
