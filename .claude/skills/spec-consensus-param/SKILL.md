---
name: spec-consensus-param
description: Draft an Algorand specification (sibling specs repo) update describing a new or changed consensus parameter in go-algorand. Use when the user asks to "update the spec for <param>", "document <feature> in the specs repo", or "write a spec update for a new consensus parameter".
argument-hint: [consensus-parameter-name]
allowed-tools: [Bash, Read, Edit, Write, Grep, Glob]
---

# Spec Update for a Consensus Parameter

Turn a new/changed consensus parameter in `go-algorand` into a normative update to
the Algorand Specification in the sibling `specs` repo. The goal is prose that reads
as though the feature has always been part of the protocol, matching the surrounding
spec's style and rigor.

This skill ships in the `go-algorand` repo and assumes it runs from that repo's root.
The specification source is in a separate checkout of
[`algorandfoundation/specs`](https://github.com/algorandfoundation/specs), commonly a
sibling directory at `../specs`. If it is elsewhere (or not checked out), ask the user
for its path before editing.

## Arguments

The name of the consensus parameter (the field on `config.ConsensusParams`), e.g.
`AppSizeUpdates`. If omitted, ask which parameter, or infer it from the branch/PR
under discussion.

## Step 1: Understand the parameter in go-algorand

1. Read the declaration and its doc comment:
   ```bash
   grep -rn "<PARAM>" config/consensus.go
   ```
   The comment usually states the intent. Note which `vFuture`/version block sets it
   `true` — that tells you the protocol version, but see the style rule in Step 4.

2. Find everywhere it gates behavior, separating the two layers:
   ```bash
   grep -rn "\.<PARAM>" --include=*.go | grep -v _test.go
   ```
   - **Stateless validation** (`wellFormed`, `data/transactions/...`): what
     transactions/fields become newly legal or newly rejected.
   - **Stateful semantics** (`ledger/apply/...`, `ledger/eval/...`): what actually
     changes in account/application/asset state, MBR accounting, and in what order
     relative to program execution.

3. Find supporting surface area the spec may need to mention:
   - New persisted fields: `data/basics/userBalance.go` (and `ledger/store/trackerdb`).
   - New AVM fields/opcodes: `data/transactions/logic/fields.go` (these are usually
     already regenerated into the spec's `src/avm/avm-appendix-a.md` via `make logic`).
   - New REST fields: `daemon/algod/api/.../model/types.go` (codec + json name).
   - `goal` surface: `cmd/goal/...`.

4. Read the introducing PR for rationale and the full blast radius:
   ```bash
   git log -S "<PARAM>" --oneline
   git show <commit> --stat
   ```

Summarize to the user, in one paragraph, what the parameter does across both layers
before touching the spec. Confirm your understanding of any subtle rule (shrink
limits, who pays MBR, ordering, which sibling fields are affected but *not* changed).

## Step 2: Locate the spec files

Spec source lives under `<specs>/src` (e.g. `../specs/src`). Find the affected pages:

```bash
grep -rln "<relevant terms>" ../specs/src
```

Application/asset/payment features usually touch a *field* page, a *semantics* page,
and a *data model* page. For apps, that is typically:
- `src/ledger/ledger-txn-application-call.md` — transaction fields.
- `src/ledger/ledger-txn-semantics-application.md` — the numbered procedure.
- `src/ledger/ledger-applications.md` — the persistent data model and MBR rules.

Read all candidate pages fully before editing; the spec is cross-referential and
consistent wording matters.

## Step 3: Write the update

Cover, as applicable, each layer you found in Step 1:
- **Data model page**: change field descriptions (e.g. drop "immutable"), add any new
  persisted field with its msgpack codec name and AVM exposure, and update MBR prose.
  If the feature adds a genuinely new concept, add a dedicated `##` section.
- **Fields page**: adjust when/where a field applies; state validation constraints.
- **Semantics page**: add the effect into the correct numbered step, using the
  **FAIL**/**SUCCEED** vocabulary already in that file.

## Step 4: Conventions (follow exactly)

- **Describe only the current protocol, as one coherent version.** Do NOT write "from
  the protocol version that introduces X" or "as of vN" for ledger/transaction rules.
  A rule that changed simply reads in its new form; the old form drops out.
  - *Exception*: AVM-version gating persists ("For AVM Version 4 or higher..."),
    because old programs must still be evaluated under old AVM rules — so old AVM
    versions are part of the *current* protocol. Ledger/transaction rules are not
    versioned this way.
- **Normative keywords**: **MUST**, **MUST NOT**, **MAY**, **SHALL**, and the
  **FAIL**/**SUCCEED** terms in semantics pages. Bold them as the surrounding text does.
- **Math and constants** use the LaTeX macros defined in the `$$...$$` block at the
  top of each page (e.g. `\\( \MaxGlobalSchemaEntries \\)`). Reuse existing macros;
  only add a new `\newcommand` if the constant is genuinely new.
- **Cross-reference** with relative links plus lowercase-hyphenated heading anchors,
  e.g. `[size sponsor](./ledger-applications.md#size-sponsor)`,
  `[Step 6](./ledger-txn-semantics-application.md#step-6)`.
- **Codec names**: cite the real msgpack tag from the Go struct (e.g. `SizeSponsor`
  is `ss`), not a guess.
- Match the page's existing voice, list style, and line-wrapping.

## Step 5: Review

```bash
git -C ../specs diff | cat
```

Check that: any pre-existing uncommitted spec changes (often auto-generated AVM
appendix/opcode files from `make logic`) are left untouched; every new anchor link
resolves to a real heading; and normative claims match the Go code, not intuition.

Present the diff summary to the user and flag any judgment calls (e.g. a rule whose
history is now dropped by the "current protocol only" convention) rather than
deciding silently.

## Notes

- Per `go-algorand/CLAUDE.md`: "new consensus parameters, or changes to existing
  parameters will require an update to the specification." This skill is that update.
- New REST endpoints/transaction fields may also need `go-algorand-sdk` changes —
  out of scope here, but worth mentioning to the user.
- Do not commit or open PRs unless asked; leave the working tree for review.
