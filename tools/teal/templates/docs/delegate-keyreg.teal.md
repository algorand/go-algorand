# Delegate Key Registration

## Functionality

For accounts in cold storage that still want to participate in the Algorand protocol, it is undesirable to thaw the spending key whenever new participation keys need to be registered. This contract allows you to delegate a key whose sole permission is to sign `KeyReg` transactions for its associated account.

This contract is intended to be used as a "delegated" script, *not* as a contract-only account. A spending key should sign this contract.

The contract is designed to approve transactions that meet the following criteria:
  1. The transaction is a `KeyReg` transaction
  2. The transaction's `FirstValid` round is a multiple of `TMPL_PERIOD`
  3. The transaction's `LastValid` round is within `TMPL_DUR` of its `FirstValid`
  4. The transaction's `LastValid` is before the expiration round `TMPL_EXPIRE`
  5. The transaction's `Lease` field is exactly `TMPL_LEASE`
  6. The transaction's `Fee` is less than `TMPL_FEE`
  7. The transaction's `TxID` has been signed by `TMPL_AUTH`, and a valid signature can be found in `arg_0`

Signatures for use in `arg_0` can be generated using the `algokey` and `dsign` tools. Check out `go-algorand/tools/teal/examples/keyreg.sh` for an example.

## Parameters:

  - `TMPL_AUTH`: public key of key that can authorize `KeyReg` transactions
  - `TMPL_EXPIRE`: round at which key expires
  - `TMPL_PERIOD`: round multiple where a key registration period begins
  - `TMPL_DUR`: duration of an allowed registration period
  - `TMPL_LEASE`: transaction lease used for replay protection
  - `TMPL_FEE`: maximum fee used by authorized transactions

## Code overview

### Initial checks

First, check that this is a key registration transaction. The possible valid values of this enum may be found [here](https://github.com/algorand/go-algorand/blob/9978b3aed0643751246af82f5538ba1e7de47310/data/transactions/logic/assembler.go#L569).

```
txn TypeEnum
int 2
==
```

Next, check that the fee of this transaction is less than or equal to `TMPL_FEE`. Fold this check into above with a logical `AND`.

```
txn Fee
int TMPL_FEE
<=
&&
```

Third, check that this contract hasn't expired by checking if `LastValid` is less than `TMPL_EXPIRE`.

```
txn LastValid
int TMPL_EXPIRE
<
&&
```

Next, check that this transaction is valid for exactly `TMPL_DUR` rounds by making sure that `LastValid` is equal to `FirstValid + TMPL_DUR`.

```
txn LastValid
int TMPL_DUR
txn FirstValid
+
==
&&
```

Next, check that `FirstValid` is a multiple of `TMPL_PERIOD` rounds.

```
txn FirstValid
int TMPL_PERIOD
%
int 0
==
&&
```

Next, check that the lease field is exactly `TMPL_LEASE`. This prevents the delegated key from draining the account by making many transactions, each with its own fee. By ensuring that `FirstValid` is an exact multiple of `TMPL_PERIOD`, and that `TMPL_LEASE` is a specific value, this allows at most one transaction to be approved by this contract per `TMPL_PERIOD`.

```
txn Lease
byte base64 TMPL_LEASE
==
&&
```

Finally, check that the transaction's `TxID` has been signed by `TMPL_AUTH` and that this signature was passed in `arg_0`.

```
txn TxID
arg_0
addr TMPL_AUTH
ed25519verify
&&
```

At this point, the stack contains just one value: a boolean indicating whether or not it has been approved by this contract.
