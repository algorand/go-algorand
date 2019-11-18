# Dynamic Fee

## Functionality

Suppose the owner of account A wants to send a payment to account `TMPL_TO`, but does not want to pay a transaction fee. If account A signs the following contract with the appropriate parameters (specifying all of the necessary details of the payment transaction), then anyone can cover a fee for that payment on account A's behalf.

The contract works by approving a group of two transactions (meaning the two transactions will occur together or not at all). The first transaction must spend the transaction fee _into_ account A, and the second transaction must be the specified payment transaction _from_ account A to account `TMPL_TO`.

## Parameters:

  - `TMPL_TO`: the recipient of the payment from account A
  - `TMPL_AMT`: the amount to send from account A to `TMPL_TO` in microAlgos
  - `TMPL_CLS`: the account to close out the remainder of account A's funds to after paying `TMPL_AMT` to `TMPL_TO`
  - `TMPL_FV`: the required first valid round of the payment from account A
  - `TMPL_LV`: the required last valid round of the payment from account A
  - `TMPL_LEASE`: the string to use for the transaction lease in the payment from account A (to avoid replay attacks)

## Code overview

First, check that the transaction group contains exactly two transactions. Push the result of this check to the stack.

```
global GroupSize
int 2
==
```

Next, check that the first transaction is a payment, which is required since the first transaction should be paying the fee for the second. The possible valid values of this enum may be found [here](https://github.com/algorand/go-algorand/blob/9978b3aed0643751246af82f5538ba1e7de47310/data/transactions/logic/assembler.go#L569).

Additionally, fold the result of this check into the previous one with a logical `AND`.

```
gtxn 0 TypeEnum
int 1
==
&&
```

Next, specify that the receiver of funds from the first transaction is equal to the sender of the second transaction (since the first transaction is paying the second transaction's fee).

```
gtxn 0 Receiver
txn Sender
==
&&
```

Next, check that the first transaction's amount is equal to the fee of the second transaction.

```
gtxn 0 Amount
txn Fee
==
&&
```

Now check that the transaction associated with this contract (the payment whose fee is being paid for) is the second transaction in the group.

When writing contracts intended to be used in group transactions, it is a good idea to check that the group is laid out as expected. If you don't do this, a contract might be tricked into serving multiple, unexpected roles within the group.

```
txn GroupIndex
int 1
==
&&
```

Check that the second transaction is a payment.

```
txn TypeEnum
int 1
==
&&
```

Finally, check that all of the fields in the second transaction are equal to their corresponding contract parameters. Fold all of these checks into a single boolean.

```
txn Receiver
addr TMPL_TO
==
&&
txn CloseRemainderTo
addr TMPL_CLS
==
&&
txn Amount
int TMPL_AMT
==
&&
txn FirstValid
int TMPL_FV
==
&&
txn LastValid
int TMPL_LV
==
&&
txn Lease
byte base64 TMPL_LEASE
==
&&
```

At this point, the stack contains just one value: a boolean indicating whether or not the transaction has been approved by this contract.
