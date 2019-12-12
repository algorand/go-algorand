# Limit Order (Contract Owner Has Algos)

## Functionality

Suppose you want to purchase units of an [asset](https://developer.algorand.org/docs/asa), and are willing to pay up to some number of microAlgos per unit of that asset. This contract allows you place a limit order offering such a trade, and to additionally cancel the order after some timeout. The contract is intended to be used as a "contract only" account, not as a "delegated contract" account. In other words, this contract should not be signed by a spending key.

The contract is configured with several parameters describing the order. The first two parameters, `TMPL_SWAPN` and `TMPL_SWAPD`, specify the exchange rate. They encode that we are willing to purchase `N` units of the asset per `D` microAlgos.

After fully specifying the contract with parameters below, the contract should be funded with the maximum number of algos willing to be traded by the owner.

The contract will approve transactions spending algos from itself under two circumstances:

  1. In a group of size two, where:
    - The first transaction is a payment spending algos from this contract to some address
    - The fee of the first transaction is less than or equal to `TMPL_FEE`
    - The second transaction transfers units of `TMPL_ASSET` into `TMPL_OWN`
    - The ratio of `gtxn 1 AssetAmount / gtxn 0 Amount` is at least `TMPL_SWAPN / TMPL_SWAPD`
    - The number of microAlgos being spent out of this contract is at least `TMPL_MINTRD`
  2. In a group of size one, where:
    - The transaction is a payment
    - The fee of the transaction is less than or equal to `TMPL_FEE`
    - `FirstValid` is greater than `TMPL_TIMEOUT`
    - The transaction is closing out all funds to `TMPL_OWN`

Note that the first case (Scenario 1) can be executed until the account has been closed out (Scenario 2). Even if round `TMPL_TIMEOUT` has already passed, the limit order can still be filled until Scenario 2 is triggered.

## Parameters

  - `TMPL_ASSET`: Integer ID of the asset
  - `TMPL_SWAPN`: Numerator of the exchange rate (`TMPL_SWAPN` assets per `TMPL_SWAPD` microAlgos, or better)
  - `TMPL_SWAPD`: Denominator of the exchange rate (`TMPL_SWAPN` assets per `TMPL_SWAPD` microAlgos, or better)
  - `TMPL_TIMEOUT`: The round after which all of the algos in this contract may be closed back to `TMPL_OWN`
  - `TMPL_OWN`: The recipient of the asset (if the order is filled), or of the contract's algo balance (after `TMPL_TIMEOUT`)
  - `TMPL_FEE`: The maximum fee used in any transaction spending out of this contract
  - `TMPL_MINTRD`: The minimum number of microAlgos that may be spent out of this contract as part of a trade

## Code overview

### Initial checks

First, check that transactions being spent from this contract always appear at the beginning of their transaction group, that they're payment transactions, and that the fee never exceeds `TMPL_FEE`. Fold these checks into a single boolean.

```
txn GroupIndex
int 0
==

txn TypeEnum
int 1
==
&&

txn Fee
int TMPL_FEE
<=
&&
```

Next, we'll check if we are closing out or if we are trying to fill an order. If `GroupSize` is 1, then we should be closing out. Jump to the "Scenario 2" section below.

```
global GroupSize
int 1
==
bnz closeOut
```

### Scenario 1: Limit order

If the `GroupSize` wasn't 1, then it better be 2. Check that that's true.

```
global GroupSize
int 2
==
```

Check that the transaction is worth spending a transaction fee on, by ensuring we are spending enough microAlgos out of this contract.

```
txn Amount
int TMPL_MINTRD
>
&&
```

Check that we're making a normal payment transaction out of this contract, not a closeout transaction that would transfer the remainder of funds somewhere else.

```
txn CloseRemainderTo
global ZeroAddress
==
&&
```

Check that the type of the second transaction in the group is an `AssetTransfer`, that it's transferring the correct asset, that the recipient of the transfer is `TMPL_OWN`, and that it's not a `Clawback` transaction (`Clawback` transactions are special transactions with a nonzero `AssetSender` -- when that field is the zero address, the sender of the asset is simply the sender of the transaction).

```
gtxn 1 TypeEnum
int 4
==
&&

gtxn 1 XferAsset
int TMPL_ASSET
==
&&

gtxn 1 AssetReceiver
addr TMPL_OWN
==
&&

gtxn 1 AssetSender
global ZeroAddress
==
&&
```

Now we'll do some math to ensure that the exchange rate implied by the transaction amounts is acceptable. We want to ensure that:
`Transaction 1's Asset Amount / Transaction 0's microAlgo Amount >= TMPL_N / TMPL_D`

If the actual ratio implied by the transactions is too large, that implies that we are getting more assets per microAlgo than we originally asked for, which is certainly okay with us as the contract owner.

Cross multiplying the inequality above, it becomes:

`Transaction 1's Asset Amount * TMPL_SWAPD >= Transaction 0's microAlgo Amount * TMPL_SWAPN`

Compute the left half of the above inequality. Since both `gtxn 1 AssetAmount` and `TMPL_SWAPD` are 64-bit integers, their product can be 128-bits long. To allow results of this size, we use the `mulw` instruction, which pushes the low-order 64 bits of the product to the stack (interpreted as a 64-bit integer), followed by the high-order 64 bits (interpreted as a 64-bit integer).

We store the low-order bits into scratch space index 2, and the high-order bits into scratch space index 1.

```
gtxn 1 AssetAmount
int TMPL_SWAPD
mulw
store 2 // Low 64 bits
store 1 // High 64 bits
```

Next, we compute the right half of the inequality, storing `uint64(result & (2**64 - 1))` into scratch space index 4 and `uint64(result >> 64)` into scratch space index 3.

```
txn Amount
int TMPL_SWAPN
mulw
store 4 // Low 64 bits
store 3 // High 64 bits
```

If the high-order bits of the left half of the inequality are larger than the high-order bits of the right half, then certainly the left half is larger. Jump to the `done` label if this is the case.

```
load 1
load 3
>
bnz done
```

If the high-order bits of the left half of the inequality are equal to the high-order bits of the right half, then we just need to compare the low-order bits. Jump to the `done` label if left half of the inequality is greater than or equal to the right half.

```
load 1
load 3
==
load 2
load 4
>=
&&
bnz done
```

If we made it here, the ratio implied by the transaction amounts was unacceptable. Error out.

```
err
```

### Scenario 2: Contract has timed out

First, check that the `CloseRemainderTo` field is set to be the `TMPL_OWN` address (presumably initialized to be the original owner of the funds).

```
closeOut:
txn CloseRemainderTo
addr TMPL_OWN
==
```

Next, check that this transaction is occurring after round `TMPL_TIMEOUT`.

```
txn FirstValid
int TMPL_TIMEOUT
>
&&
```

We only want to allow close-out transactions that close out all of the funds, so ensure the receiver address is empty and that the amount is zero.

```
txn Receiver
global ZeroAddress
==
&&

txn Amount
int 0
==
&&
```

### Finishing up

Fold the scenario-specific checks into the initial checks.

```
done:
&&
```

At this point, the stack contains just one value: a boolean indicating whether or not it has been approved by this contract.
