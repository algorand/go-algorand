## Summary

Make sensitive LogicSig operations opt-in starting with AVM v14.

This adds the LogicSig-only `allow F` opcode. An authorization is recorded only when the opcode executes, and applies only to the transaction whose LogicSig is being evaluated. A successful v14+ LogicSig must execute the corresponding authorization for:

- a nonzero `RekeyTo` on any transaction type;
- a payment with a nonzero `CloseRemainderTo`;
- an asset transfer with a nonzero `AssetCloseTo`;
- an asset transfer with a nonzero `AssetSender`, enabling a clawback; and
- any `KeyRegistration` transaction, including online, offline, and nonparticipating registrations.

For example, a LogicSig that has validated a rekey operation can authorize it with `allow RekeyTo`. If the program returns successfully without executing that opcode, evaluation fails. A program that returns false remains a normal LogicSig rejection, even when the transaction would otherwise require an allowance.

Programs below v14 retain their existing behavior. Allowances are isolated between transactions in a group, and the per-field version metadata allows future authorization kinds to be introduced without making them available to earlier program versions.

## Open questions

Does this protect the right set of operations?
Requiring an allowance reduces the risk of accidental authorization, at the cost of introducing the risk of accidental rejection when the corresponding `allow` is omitted.

## Test Plan

New tests:

- `data/transactions/logic/eval_test.go` adds `TestLogicSigAllow`, covering every protected operation, v13 compatibility, v14 enforcement, executed-path and transaction-group isolation, independent allowances when a transaction requires more than one, and false program results.
- `data/transactions/logic/eval_test.go` adds `TestLogicSigAllowOpcode`, covering opcode version gating and invalid immediates.
- `data/transactions/verify/txn_test.go` adds `TestTxnValidationLogicSigAllow`, which exercises end-to-end transaction verification for both contract-account and delegated LogicSigs, covering rekeying and key registration with and without the required v14 allowances.
