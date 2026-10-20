---
name: promote-vfuture
description: Promote the parameters currently staged in vFuture into a brand-new numbered consensus version, and open a fresh (empty) vFuture with an incremented LogicSigVersion. Use when the user asks to "promote vFuture", "cut a new consensus version", "release vFuture as vN", or "do the vFuture upgrade".
argument-hint: [optional spec github url]
allowed-tools: [Bash, Read, Edit, Write, Grep, Glob]
---

# Promote vFuture to a New Consensus Version

Turn the features staged in `vFuture` into a released, numbered consensus version
(the next natural number, `vN+1`), re-open `vFuture` as an empty shell with an
incremented `LogicSigVersion`, bump the AVM's `LogicVersion` so held-back
experimental opcodes have a home, and repair the tests that the shift exposes. This
mirrors past release commits (e.g. the v41 upgrade, PR #6422) and must leave
`TestReleasedVersion` passing.

This skill ships in the `go-algorand` repo and runs from its root.

## The mental model

At rest, the code has a **current** top version `vN` (whatever
`protocol.ConsensusCurrentVersion` points at) and a **vFuture** built from `vN` that
layers on the not-yet-released parameters. Promotion "freezes" today's vFuture into
`vN+1`, wires the `vN -> vN+1` upgrade path, and starts a new vFuture from `vN+1`.

Every promoted feature parameter moves **out** of the vFuture block and **into** the
new numbered block. The fresh vFuture block ends up with only one line of substance:
a `LogicSigVersion` one higher than the version just released.

Two things track `vFuture.LogicSigVersion` and must move with it:
- The AVM `LogicVersion` (`data/transactions/logic/opcodes.go`) — the max version the
  assembler/evaluator supports. See Step 2b.
- Nothing else automatically. `docVersion` (the published-langspec ceiling) does
  **not** move — it stays at the released version. See Step 4.

## Step 0: Discover the current state and get the URL

1. Find the current top version and vFuture block:
   ```bash
   grep -n "ConsensusCurrentVersion = " protocol/consensus.go
   grep -n "vFuture :=\|ConsensusFuture\] = vFuture\|LogicSigVersion" config/consensus.go
   ```
   From `vFuture := vN` and `ConsensusCurrentVersion = ConsensusVN`, fix the numbers:
   the released version is `vN`, the new one is `vN+1`. Read the whole vFuture block in
   `config/consensus.go` and note `vFuture.LogicSigVersion` (call it `L` — the new
   version gets `L`, the new vFuture gets `L+1`) and every `vFuture.<Param> = ...` line.

2. **Ask the user for the spec GitHub URL** for the new version's constant string.
   Often the real URL is not ready. If so, use a placeholder that **keeps the real
   spec-repo prefix but has an obviously-fake tail**, e.g.:
   ```go
   const ConsensusV42 = ConsensusVersion(
       "https://github.com/algorandfoundation/specs/tree/TODO-REPLACE-BEFORE-RELEASE-v42",
   )
   ```
   The prefix is mandatory, not cosmetic: `config`'s `TestConsensusUpgrades` (via
   `checkConsensusVersionName`) rejects any version string in the upgrade path that does
   not start with `https://github.com/algorandfoundation/specs/tree/` (or the older
   `https://github.com/algorand/spec/tree/`). A bare `TODO`-style string fails that
   test. Flag the placeholder loudly so it is replaced before release.

## Step 1: `protocol/consensus.go`

1. Add the new version constant immediately **before** `ConsensusFuture`, doc comment
   summarizing the promoted features (paraphrase the vFuture params and the new TEAL
   version):
   ```go
   // ConsensusV42 enables <summary of promoted features> and TEAL v<L>.
   const ConsensusV42 = ConsensusVersion(
       "<url-or-placeholder-with-real-prefix>",
   )
   ```
2. Update the current-version pointer: `const ConsensusCurrentVersion = ConsensusV42`.

## Step 2a: `config/consensus.go` — the core transformation

Convert the existing `vFuture := vN` block into the new numbered block, then add a new
empty vFuture after it. The block that today reads:

```go
	// ConsensusFuture is used to test features that are implemented
	// but not yet released in a production protocol version.
	vFuture := v41
	vFuture.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	vFuture.LogicSigVersion = 13 // When moving this to a release, put a new higher LogicSigVersion here
	vFuture.AppSizeUpdates = true
	vFuture.<...more feature params...>

	Consensus[protocol.ConsensusFuture] = vFuture
```

becomes:

```go
	v42 := v41
	v42.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	v42.LogicSigVersion = 13
	v42.AppSizeUpdates = true
	v42.<...more feature params...>

	Consensus[protocol.ConsensusV42] = v42

	// v41 can be upgraded to v42, with an update delay of 7d:
	// 208000 = (7 * 24 * 60 * 60 / 2.9 ballpark round times)
	// our current max is 250000
	v41.ApprovedUpgrades[protocol.ConsensusV42] = 208000

	// ConsensusFuture is used to test features that are implemented
	// but not yet released in a production protocol version.
	vFuture := v42
	vFuture.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	vFuture.LogicSigVersion = 14 // When moving this to a release, put a new higher LogicSigVersion here

	Consensus[protocol.ConsensusFuture] = vFuture
```

Checklist:
- Rename every `vFuture.` in the old block to `v42.`, keeping all feature params.
- The new version's `LogicSigVersion` is `L`; **drop** the "When moving this to a
  release..." trailing comment there.
- Move the `// ConsensusFuture is used to test...` comment to the new vFuture block.
- Change `Consensus[protocol.ConsensusFuture] = vFuture` to
  `Consensus[protocol.ConsensusV42] = v42` for the promoted block.
- Add `vN.ApprovedUpgrades[protocol.ConsensusV42] = 208000` (208000 = 7-day delay).
- The **new** vFuture block starts from `v42` and carries only `LogicSigVersion = L+1`.
  No feature params — they were all promoted.

## Step 2b: `data/transactions/logic/opcodes.go` — LogicVersion & experimental opcodes

Bumping `vFuture.LogicSigVersion` to `L+1` means the AVM must actually support version
`L+1`, so opcodes staged for the next release have a home. Bump:

```go
const LogicVersion = 14 // was 13
```

Now deal with the experimental opcodes. There is a small `experiments` list (in
`assembler_test.go`) guarded by `TestExperimental`, which is *designed to fail* when
`vFuture.LogicSigVersion` increments. Each experimental opcode has a version const near
the top of `opcodes.go` (e.g. `sumhashVersion`) currently equal to `L`. For each one,
decide **with the user**:
- **Release it**: it ships in the new numbered version. Remove it from `experiments`;
  its version const stays `L`. Simplest path — no further test churn.
- **Hold it experimental**: it belongs in the next dev version. Bump its version const
  to `L+1`. This is why `LogicVersion` had to move to `L+1` — otherwise the opcode
  would reference a version the assembler cannot target. Holding a stateless opcode back
  ripples into its own tests (see Step 5).

Do **not** bump `docVersion` (Step 4) — the published langspec must stop at the released
version `L`.

## Step 3: `ledger/testing/consensusRange.go`

Add the new version to `consensusByNumber`, immediately before `ConsensusFuture`, with
a short comment summarizing what it houses:

```go
	protocol.ConsensusV41, // AVM v12, txn access, Sha512BlockHash, AppVersioning
	protocol.ConsensusV42, // AVM v13, <summary of promoted features>
	protocol.ConsensusFuture,
```

This is what makes `versionStringFromIndex`/`TestConsensusRange` map the new number to
a real version instead of "vFuture".

## Step 4: Regenerate the language spec

```bash
touch data/transactions/logic/fields_string.go
make -C data/transactions/logic
```

`git diff --stat data/transactions/logic` — expect `langspec_v*.json` `LogicSigVersion`
bumps (`L-1` -> `L`). If you held an experimental opcode back to `L+1`, it also drops
out of the released version's langspec and `TEAL_opcodes_v<L>.md`. There should be **no
new `langspec_v(L+1).json`** — that only appears once `docVersion` is bumped in a later
release, so verify one wasn't generated.

## Step 5: Build and fix broken tests

```bash
make buildsrc
go test ./config/... ./ledger/testing/... ./data/transactions/logic/... ./ledger/...
```

Failures fall into two kinds. Diagnose which before "fixing".

### (a) Tests pinned to Current/Future identity

A test asserts "this feature is on/off" by comparing to `ConsensusCurrentVersion` or
`ConsensusFuture`, and the assertion flips when Current moves. Rewrite it to depend on
the **numeric** version, so it keeps meaning the same thing after the next promotion:
- `TestConsensusRange(t, start, stop, fn)` (`ledger/testing`) when the claim is "works
  from version X onward"; `start` is the numeric index, `stop` of `0` means "through
  vFuture".
- Otherwise **parameterize** the body over specific versions pulled from
  `consensusByNumber[i]` — typically the boundary pair (last version without the
  feature, first with it).

### (b) Tests that break because Current gained a *feature*

Current now enables something vFuture used to (this promotion: `LoadTracking`, which
requires validated blocks to carry a computed `Load` header field). Tests that
hand-build blocks, or otherwise construct protocol data structures directly, now omit a
newly-required field and fail (e.g. `bad load: 0 != N`).

**Do NOT pin these to an old numeric version to dodge the feature.** That hides the
feature from the test forever and defeats the point. Instead:
1. **Build the data properly.** Prefer the shared test helper over inlined
   construction. Here, `ledger/ledger_test.go`'s `endOfBlock` helper is "a simplified
   `BlockEvaluator.endOfBlock` so our test blocks can pass validation" — teach it to set
   the new gated field, and have the offending tests call it instead of inlining
   `PaysetCommit`/`FeesCollected`:
   ```go
   if proto.LoadTracking {
       blockTxBytes := 0
       for i := range blk.Payset {
           blockTxBytes += blk.Payset[i].GetEncodedLength()
       }
       blk.BlockHeader.Load = eval.ComputeLoad(blockTxBytes, proto.MaxTxnBytesPerBlock)
   }
   ```
2. **Run the test against Current AND Future**, so the *next* vFuture feature breaks it
   during development rather than at release:
   ```go
   for _, cv := range []protocol.ConsensusVersion{protocol.ConsensusCurrentVersion, protocol.ConsensusFuture} {
       t.Run(string(cv), func(t *testing.T) { testFooImpl(t, cv) })
   }
   ```
   with the body parameterized on `cv` (used for `config.Consensus[cv]` and
   `GenerateInitState(t, cv, ...)`). The guiding principle: **tests should already
   exercise vFuture, so that promotion is a non-event.** A test that only ran at Current
   is why this break surfaced at release time instead of when the feature landed.

Always propose test changes to the user rather than rewriting silently — the `start`
version, the boundary, and the "build it properly" fix are judgment calls.

### The `TestExperimental` gate and the autosalt ripple (both expected)

- **`TestExperimental`** (`data/transactions/logic/assembler_test.go`) fails by design
  when `vFuture.LogicSigVersion` increments. Resolve per Step 2b (release, or hold and
  bump the version const).
- **Held-back experimental opcodes** ripple into their own scaffolding: their opcode
  moves out of the released version's assembly, so the per-version golden tables in
  `assembler_test.go` need a new `v(L+1)Nonsense`/`v(L+1)Compiled` (and map entries),
  and per-version programs in `eval_test.go` (`globalV(L+1)TestProgram` +
  `TestAllGlobals` map; `testTxnProgramTextV(L+1)` + `TestTxn` map) need a v(L+1) entry
  (usually identical to v`L`, since no new fields). A dedicated test like `TestSumhash`
  that hardcoded the opcode's version should reference the version const instead. When
  `L+1` introduces no encoding change, `v(L+1)Compiled = vLCompiled + <moved-op bytes>`.
- **Autosalt fragility (`LogicSigOffCurveVersion`).** Bumping `LogicVersion` changes the
  program version byte, which changes every stateless program's hash, which flips
  whether it hashes on-curve. At `LogicSigOffCurveVersion` and above, a stateless
  (non-app) program that lands on-curve gets an auto-salt `intcblock` constant appended
  by the assembler. That silently changes assembled bytes (breaking golden-hex assembler
  tests) and adds an opcode of cost (breaking exact opcode-budget assertions, e.g. an
  off-by-one in `TestIncrementCheck`). Tests broken this way are stateless programs whose
  exact bytes/cost matter; fix each by disabling the salt with a `#pragma autosalt false`
  line at the top of the program source. (Stateful programs — those with app/box opcodes
  — never auto-salt, so `TestAssemble`'s nonsense, which includes `app_box_*`, is
  immune.)

## Step 6: Verify

1. The linchpin:
   ```bash
   go test ./ledger/testing/ -run TestReleasedVersion -v
   ```
   It checks the version below vFuture has no `ApprovedUpgrades`, vFuture's
   `LogicSigVersion` is strictly greater than the released one, and every
   `consensusByNumber` entry resolves to real params. Failure means Step 2a or 3 is
   incomplete.
2. `go test ./data/transactions/logic/ -run 'TestExperimental|TestReleased|TestAssemble'`
   and the Step 5 packages.
3. `git status --porcelain` — the changed set should be roughly: `config/consensus.go`,
   `protocol/consensus.go`, `ledger/testing/consensusRange.go`,
   `data/transactions/logic/opcodes.go`, generated
   `data/transactions/logic/langspec_v*.json` (+ `TEAL_opcodes_v<L>.md`), plus the test
   files you repaired. If unsure whether generated output is complete, consult
   `scripts/travis/codegen_verification.sh`.

## Notes

- New/changed consensus parameters warrant a spec update, but that is the
  `spec-consensus-param` skill's job and was presumably done when the params first
  landed in vFuture. This skill is only the promotion mechanics.
- Do not commit or open a PR unless asked; leave the tree for review. If a placeholder
  URL was used, call it out explicitly in your summary so it is not forgotten.
- Per `../CLAUDE.md`, a PR takes a single-word area prefix (e.g. "Consensus:") and an
  "enhancement" tag.
```
