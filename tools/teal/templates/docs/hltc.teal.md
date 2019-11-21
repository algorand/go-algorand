# Hash Time Lock Contract (HTLC)

## Functionality

This contract implements a "hash time lock". It is intended to be used as a "contract only" account, not as a "delegated contract" account. In other words, this contract should not be signed by a spending key.

The contract will approve transactions spending algos from itself under two circumstances:

  1. If an argument `arg_0` is passed to the script such that `TMPL_HASHFN(arg_0)` is equal to `TMPL_HASHIMG`, then funds may be closed out to `TMPL_RCV`. 
  2. If `txn.FirstValid` is greater than `TMPL_TIMEOUT`, then funds may be closed out to `TMPL_OWN`.

The idea is that by knowing the preimage to `TMPL_HASHIMG`, funds may be released to `TMPL_RCV` (Scenario 1). Alternatively, after some timeout round `TMPL_TIMEOUT`, funds may be closed back to their original owner, `TMPL_OWN` (Scenario 2). Note that Scenario 1 may occur up until Scenario 2 occurs, even if `TMPL_TIMEOUT` has already passed.

## Parameters

  - `TMPL_RCV`: the address to send funds to when the preimage is supplied
  - `TMPL_HASHFN`: the specific hash function (`sha256` or `keccak256`) to use
  - `TMPL_HASHIMG`: the image of the hash function for which knowing the preimage under `TMPL_HASHFN` will release funds
  - `TMPL_TIMEOUT`: the round after which funds may be closed out to `TMPL_OWN`
  - `TMPL_OWN`: the address to refund funds to on timeout
  - `TMPL_FEE`: maximum fee of any transactions approved by this contract
  
## Code overview

### Initial checks

First, check that the fee of this transaction is less than or equal to `TMPL_FEE`.

```
txn Fee
int TMPL_FEE
<=
```

Next, check that this is a payment transaction. The possible valid values of this enum may be found [here](https://github.com/algorand/go-algorand/blob/9978b3aed0643751246af82f5538ba1e7de47310/data/transactions/logic/assembler.go#L569).

```
txn TypeEnum
int 1
==
```

Fold the above two checks into a single boolean.

```
&&
```

Next, check that the `Receiver` field for this transaction is empty (and fold this result into the above checks). Because this contract can approve transactions that close out its entire balance, it should never have a receiver.

```
txn Receiver
global ZeroAddress
==
&&
```

Next, check that the `Amount` of algos transferred is `0`. This is for the same reason as above: we only allow transactions that close out this account completely, which having a non-zero-address `CloseRemainderTo` will handle for us. Also, fold this check into the above checks.

```
txn Amount
int 0
==
&&
```

### Payout scenarios

At this point in the execution, there is one boolean variable on the stack that must be `true` in order for the transaction to be valid. The checks we have done above apply to any transaction that may be approved by this script.

We will now check if we are in one of the two payment scenarios described in the functionality section.

#### Scenario 1: Hash preimage has been revealed

First, check that the `CloseRemainderTo` field is set to be the `TMPL_RCV` address.

```
txn CloseRemainderTo
addr TMPL_RCV
==
```

Next, we will check that `arg_0` is the correct preimage for `TMPL_HASHIMG` under `TMPL_HASHFN`. Push `TMPL_HASHFN(arg_0)` to the stack.

```
arg_0
TMPL_HASHFN
```

Push the expected hash result to the stack and compare it with our computed hash.

```
byte base64 TMPL_HASHIMG
==
```

Fold the "Scenario 1" checks into a single boolean.

```
&&
```

#### Scenario 2: Contract has timed out

First, check that the `CloseRemainderTo` field is set to be the `TMPL_OWN` address (presumably initialized to be the original owner of the funds).

```
txn CloseRemainderTo
addr TMPL_OWN
==
```

Next, check that this transaction has only occurred after the `TMPL_TIMEOUT` round.

```
txn FirstValid
int TMPL_TIMEOUT
>
```

Fold the "Scenario 2" checks into a single boolean.

```
&&
```

### Final checks

At this point in the program's execution, the stack has three values. At the base of the stack is a boolean holding the results of the initial transaction validity checks. This is followed by two booleans indicating the results of the scenario 1 and 2 checks.

We want to approve this transaction if we are in scenario 1 or 2. So we logically `OR` the results of those checks together.

```
||
```

Finally, we logically `AND` the scenario checks with the initial checks.

```
&&
```

At this point, the stack contains just one value: a boolean indicating whether or not it has been approved by this contract.
