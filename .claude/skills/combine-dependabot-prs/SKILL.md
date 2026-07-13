---
name: combine-dependabot-prs
description: Combines open dependabot PRs on algorand/go-algorand into a single branch and PR. Use when the user asks to "combine dependabot PRs", "batch dependabot upgrades", or "roll up dependency bumps".
argument-hint: [branch-date-suffix]
allowed-tools: [Bash, Read, Glob, Grep]
---

# Combine Dependabot PRs

Combines all open dependabot PRs on `algorand/go-algorand` into one branch and PR, using `go get` + `go mod tidy` rather than cherry-picking.

## Arguments

Optional date suffix for the branch name (e.g. `4-13-26`). If omitted, derive one from today's date.

Branch name format: `dependabot-<date-suffix>` (e.g. `dependabot-4-13-26`).

## Instructions

### 1. Create the branch

```bash
git fetch upstream
git checkout -b dependabot-<DATE> upstream/master
```

### 2. List open dependabot PRs

```bash
gh pr list --repo algorand/go-algorand --author "app/dependabot" --state open --limit 50 --json number,headRefName,title
```

### 3. Check current dependency versions

Before applying any PR, read the current versions from the affected `go.mod` files:
- `go.mod` (main module)
- `tools/block-generator/go.mod`
- `tools/debug/algodump/go.mod`

Compare against what each dependabot PR wants to change. **Skip any PR whose target version is already behind the version currently in the file** — this happens when a later dependabot PR supersedes an earlier one (e.g. quic-go already at v0.59.0 when a PR targets v0.57.0).

To read a PR's diff:
```bash
gh pr diff <NUMBER> --repo algorand/go-algorand
```

### 4. Apply upgrades with `go get`

For each module that needs changes, run `go get` with all target packages at their new versions in one command, then tidy:

**Main module:**
```bash
go get <pkg1>@<ver1> <pkg2>@<ver2> ...
go mod tidy
```

**Sub-modules** (must use absolute path since the shell may be in a different directory):
```bash
cd /path/to/repo/tools/block-generator && go get ... && go mod tidy && cd -
cd /path/to/repo/tools/debug/algodump  && go get ... && go mod tidy && cd -
```

For otel upgrades, include all related packages together since they version in lockstep:
```
go.opentelemetry.io/otel
go.opentelemetry.io/otel/metric
go.opentelemetry.io/otel/sdk
go.opentelemetry.io/otel/sdk/metric
go.opentelemetry.io/otel/trace
```

### 5. Commit

Stage only the `go.mod` and `go.sum` files:

```bash
git add go.mod go.sum \
        tools/block-generator/go.mod tools/block-generator/go.sum \
        tools/debug/algodump/go.mod  tools/debug/algodump/go.sum
git commit -m "build: combine dependabot dependency upgrades (<month> <year>)

Combines open dependabot PRs #XXXX, ... into a single commit.
<Skips #XXXX (pkg) since the codebase already has vX.Y.Z.>

Upgrades across main module, tools/block-generator, and
tools/debug/algodump:
- pkg vOLD -> vNEW"
```

### 6. Push the branch

Push explicitly to a named remote branch (not the default):

```bash
git push origin HEAD:refs/heads/dependabot-<DATE>
```

> **Gotcha:** `git push -u origin <branchname>` may push to `origin/master`
> instead of creating a new remote branch if the local branch tracks
> `upstream/master`. Always use `HEAD:refs/heads/<branchname>` to be safe.

### 7. Pick three random reviewers

Choose three reviewers at random from the fixed pool `nullun cce
algorandskiy cusma giuliop`:

```bash
REVIEWERS=$(printf '%s\n' nullun cce algorandskiy cusma giuliop | sort -R | head -3 | paste -sd, -)
echo "Requesting review from: $REVIEWERS"
```

### 8. Create the PR

The PR title is `build: dependabot-<DATE>` (same date suffix as the
branch), tagged `enhancement`, with the three random reviewers:

```bash
gh pr create \
  --repo algorand/go-algorand \
  --head jannotti:dependabot-<DATE> \
  --base master \
  --title "build: dependabot-<DATE>" \
  --body "..." \
  --label enhancement \
  --reviewer "$REVIEWERS"
```

PR body should list: which PRs are combined (with `closes #XXXX`), which are skipped and why, and a test plan.

## Notes

- The three Go modules (`/`, `tools/block-generator`, `tools/debug/algodump`) are independent; each needs its own `go get` + `go mod tidy`.
- `go mod tidy` may pull in additional transitive-dependency version bumps beyond what the dependabot PR listed; that is expected and fine.
- Do not include unrelated untracked files (e.g. work-in-progress source files) in the commit.
