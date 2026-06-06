# Rekey Safety Flow

This document describes the rekey-safety protections added to the CLI signing flow to reduce social-engineering risk from hidden rekey operations in transaction files.

## Problem

A malicious transaction file or group can contain a valid rekey operation mixed with unrelated-looking actions (for example, ASA opt-in). If a user signs that group blindly, account authority can be transferred.

## Design Goals

- Keep protocol-level rekey functionality intact for legitimate operators.
- Make dangerous rekey usage explicit and opt-in at CLI level.
- Block accidental signing of hidden rekeyed transactions by default.
- Detect and call out high-risk pattern: ASA opt-in grouped with rekey.

## High-Level Behavior

By default:

- Creating a transaction with `--rekey-to` is refused.
- Signing input files that contain any rekey transaction is refused.

To proceed intentionally, operator must pass:

- `--allow-rekey`

This is a deliberate, explicit acknowledgement.

## Goal Flow

### 1. Transaction Construction Guard

When commands build unsigned transactions and set `Txn.RekeyTo`, the code uses:

- `parseRekeyWithSafety(...)`

This validates the rekey target and enforces that `--allow-rekey` is present for non-empty rekey target.

If not present, command exits with a clear refusal message.

### 2. Signing Guard

Before signing in file-based flows, code scans decoded signed-txn input and evaluates:

- any transaction with non-zero `Txn.RekeyTo`
- grouped risk pattern (asset opt-in + rekey in same group)

If rekey exists and `--allow-rekey` is not set, signing is refused.

### 3. Risk Pattern Detection

The scanner identifies ASA opt-in transactions as:

- `Type == AssetTransferTx`
- `XferAsset != 0`
- `AssetAmount == 0`
- `AssetSender == ZeroAddress`
- `AssetReceiver == Sender`
- `AssetCloseTo == ZeroAddress`

If such opt-in appears in a group that also contains rekey, the error message explicitly reports this high-risk grouping.

### 4. Affected goal Paths

- Common txn flag plumbing for `--allow-rekey`
- `goal clerk send`
- `goal clerk sign`
- `goal clerk multisig sign`
- `goal account` status/renew/nonparticipating flows that expose `--rekey-to`
- `goal asset` transaction constructors
- `goal app` create/call/update/etc constructors
- ABI method-call flow that ingests transaction arguments and forms groups

## Algokey Flow

`algokey` has parallel protections:

- `algokey sign`
- `algokey multisig`

Both decode all input transactions, run the same rekey/risk scan, and refuse signing unless `--allow-rekey` is provided.

## Why CLI-Level and Not Consensus-Level

Consensus cannot infer scam intent from valid transaction semantics. Rekey is a legitimate protocol feature.

Therefore, prevention is implemented as user-safety policy in tooling:

- safer defaults
- explicit dangerous-action opt-in
- targeted high-risk detection

## Testing

Added focused unit coverage for:

- rekey parsing with safety gate
- signer refusal without `--allow-rekey`
- acceptance with `--allow-rekey`
- grouped ASA opt-in + rekey detection

Validated package-level tests for:

- `./cmd/goal`
- `./cmd/algokey`

## Operator Notes

For legitimate rekey operations (key rotation, custody migration, etc.), use:

- `--rekey-to <address>`
- `--allow-rekey`

Always verify transaction intent with `goal clerk inspect` (or equivalent) before signing or broadcasting.
