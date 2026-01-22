# PR Auto-labeling and Prefix Automation

## Overview

The `pr-auto-label-prefix.yml` workflow automatically:
1. Detects the appropriate prefix for PR titles based on changed files
2. Adds the prefix to PR titles if missing
3. Applies the most appropriate label from the required set

## How It Works

### Prefix Detection

The workflow analyzes all changed files and determines which top-level directory has the most changes. It maps directories to prefixes:

| Directory | Prefix |
|-----------|--------|
| `network/` | `network` |
| `ledger/` | `ledger` |
| `agreement/` | `agreement` |
| `data/` | `data` |
| `cmd/` | `cmd` |
| `daemon/` | `daemon` |
| `crypto/` | `crypto` |
| `node/` | `node` |
| `config/` | `config` |
| `test/` | `test` |
| *(and more)* | *(see workflow)* |

If the PR touches files in multiple directories, the directory with the most changes is used.

### Label Classification

The workflow applies one of these labels based on PR analysis:

**Bug-Fix** - Applied when:
- Title/body contains: "fix", "bug", "regression", "crash", "panic", "deadlock", "race"
- Appears to be fixing existing functionality

**Skip-Release-Notes** - Applied when:
- Only test files changed
- Only documentation changed
- Only refactoring/cleanup with no new functionality

**New Feature** - Applied when:
- Multiple new files added (3+)
- Title/body contains: "add", "implement", "introduce", "new feature"

**Not-Yet-Enabled** - Applied when:
- Title/body mentions: "experimental", "not yet enabled", "feature flag"

**Enhancement** - Applied when:
- None of the above criteria match (default)
- Modifying existing functionality
- Improvements or optimizations

## Customization

### Adding New Prefix Mappings

Edit the `case` statement in the "Analyze PR" step:

```bash
case "$max_dir" in
  yournewdir) prefix="yournewdir" ;;
  # ... existing mappings ...
esac
```

### Adjusting Label Logic

Modify the label detection logic in the "Analyze PR" step. The current logic uses:
- Pattern matching on PR title/body
- File type analysis (tests, docs)
- New file detection
- Change volume analysis

### Changing Confidence Thresholds

Currently set to "always apply best guess". To make it more conservative:

1. Add confidence scoring to the analyze step
2. Only apply label/prefix if confidence > threshold
3. Otherwise, just leave a comment with suggestions

## Workflow Triggers

Runs automatically on:
- PR opened
- PR reopened

Does NOT run on:
- PR synchronized (new commits) - to avoid re-applying after manual corrections
- PR edited - to respect manual changes

## Manual Overrides

Authors can always:
- Edit the PR title to change the prefix
- Remove and add different labels
- The automation will not re-run and override manual changes

## Example

**Before automation:**
- Title: `Add support for metrics tracking in transaction pool`
- Labels: (none)

**After automation:**
- Title: `metrics: Add support for metrics tracking in transaction pool`
- Labels: `Enhancement`
- Comment: Explains the detection logic and invites corrections

## Maintenance

The workflow requires no external dependencies or API keys. It runs entirely on GitHub Actions free tier.

To disable:
- Delete or rename `.github/workflows/pr-auto-label-prefix.yml`

## Testing

To test changes to the workflow:
1. Create a test PR in your fork
2. Check the Actions tab for the workflow run
3. Review the "Analyze PR" step summary for detection logic
4. Verify the title and labels were updated correctly

## Limitations

- Cannot detect intent perfectly - some manual corrections will be needed
- Multi-component PRs may get suboptimal prefixes (uses most-changed directory)
- Works best for focused PRs touching 1-2 main areas
- Keyword matching for labels may occasionally miss nuanced cases

## Feedback

If you notice patterns where the automation consistently makes mistakes:
1. Open an issue describing the pattern
2. Update the workflow rules to handle that case
3. The rules can be continuously refined based on real usage
