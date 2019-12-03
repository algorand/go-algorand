# Split

## Functionality

The purpose of this contract is to allow two addresses, `TMPL_RCV1` and `TMPL_RCV2`, to withdraw funds in a particular ratio specified by `TMPL_RAT1` and `TMPL_RAT2`. Additionally, for each withdrawal pair, `TMPL_RCV1` must receive at least `TMPL_MINPAY` microAlgos for the group to be approved.

For example, if `TMPL_RAT1` is set to 1, `TMPL_RAT2` is set to 5, and `TMPL_MINPAY` is set to 1,000,000 microAlgos, then this contract will approve a group transaction that sends 1,000,000 microAlgo to `TMPL_RCV1` and 5,000,000 microAlgos to `TMPL_RCV2`.

This contract additionally takes a timeout round `TMPL_TIMEOUT`, after which all remaining funds may be recovered to the address `TMPL_OWN` and the contract will be closed. Note that the regular split withdrawal functionality will still work until after the contract is explicitly closed.

This contract is intended to be used as a contract-only account, and *not* as a delegated contract (in other words, this contract should never be signed by an account).

## Parameters

  - `TMPL_RCV1`: the first recipient of the funds
  - `TMPL_RCV2`: the second recipient of the funds
  - `TMPL_RAT1`: for each `TMPL_RAT2` microAlgos received by `TMPL_RCV2`, `TMPL_RAT1` specifies how many are received by `TMPL_RCV1`
  - `TMPL_RAT2`: for each `TMPL_RAT1` microAlgos received by `TMPL_RCV1`, `TMPL_RAT2` specifies how many are received by `TMPL_RCV2`
  - `TMPL_MINPAY`: the minimum number of microAlgos that must be received by `TMPL_RCV1` for a split withdrawal to succeed
  - `TMPL_TIMEOUT`: the round after which funds may be closed back to `TMPL_OWN`
  - `TMPL_OWN`: the address that funds may be closed to after `TMPL_TIMEOUT`
  - `TMPL_FEE`: the maximum fee that may be used by any individual transaction approved by this contract

## Code overview

### Initial checks

First, check that this is a payment transaction. This should be the case for any transaction approved by this contract. The possible valid values of this enum may be found [here](https://github.com/algorand/go-algorand/blob/9978b3aed0643751246af82f5538ba1e7de47310/data/transactions/logic/assembler.go#L569).

```
txn TypeEnum
int 1
==
```

Next, check that the fee of this transaction is less than or equal to `TMPL_FEE`. Fold this check into the above check with a logical `AND`.

```
txn Fee
int TMPL_FEE
<=
&&
```

Next, we will check if we are trying to make a split withdrawal. We will assume this is the case when the transaction appears in a group of size two. If this is the case, jump ahead to the "split" section. Otherwise, fall through.

```
global GroupSize
int 2
==
bnz split
```

### Fall through: closeout case

If the transaction group size was not two, assume that we want to close out the contract. We will also hit this case if the group size is greater than 2; because we will only approve closeout transactions in that case, this is not a vulnerability.

Check that the `CloseRemainderTo` field, `Receiver` field, and `Amount` field are set such that we will close out all funds to `TMPL_OWN`.

```
txn CloseRemainderTo
addr TMPL_OWN
==
txn Receiver
global ZeroAddress
==
&&
txn Amount
int 0
==
&&
```

Check that we are after the `TMPL_TIMEOUT` round, when closing out is allowed.

```
txn FirstValid
int TMPL_TIMEOUT
>
&&
```

Unconditionally jump to the `done` section.

```
int 1
bnz done
```

### Split case

If we made it here, the transaction group must have exactly two transactions, indicating we want to split funds.

Check that the `Sender` of the two transactions is the same. Since we're evaluating this contract, this implicitly means that both transactions are evaluating this contract. This also means that both transactions went through the same checks in the "Initial checks" section.

```
split:
gtxn 0 Sender
gtxn 1 Sender
==
```

Ensure that `CloseRemainderTo` is not set during a split transaction. This contract only wants to close out in the closeout case mentioned above. This check will apply to both transactions since they are both running this script.

```
txn CloseRemainderTo
global ZeroAddress
==
&&
```

Check that the recipients of the funds are `TMPL_RCV1` and `TMPL_RCV2` in the first and second transactions, respectively.

```
gtxn 0 Receiver
addr TMPL_RCV1
==
&&
gtxn 1 Receiver
addr TMPL_RCV2
==
&&
```

Now check that funds are being split as described by `TMPL_RAT1` and `TMPL_RAT2`. We want to ensure that:

`group txn 0 amount / group txn 1 amount = TMPL_RAT1 / TMPL_RAT2`

Cross multiplying, this is the same as:

`(group txn 0 amount) * (TMPL_RAT2) = (group txn 1 amount) * (TMPL_RAT1)`

Perform this check.

```
gtxn 0 Amount
int TMPL_RAT2
*
gtxn 1 Amount
int TMPL_RAT1
*
==
&&
```

Check that we are paying at least `TMPL_MINPAY` microAlgos to `TMPL_RCV1`.

```
gtxn 0 Amount
int TMPL_MINPAY
>=
&&
```

Finally, fold all of the checks together into a single boolean with a logical `AND`.

```
done:
&&
```

At this point, the stack contains just one value: a boolean indicating whether or not it has been approved by this contract.
