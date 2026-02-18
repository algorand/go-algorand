# Algorand Developer Contribution Guide

If you are interested in contributing to the project, we welcome and thank you. We want to make the best decentralized and effective blockchain platform available and we appreciate your willingness to help us.

The [Algorand GitHub Organization](https://github.com/algorand) has all of our open source projects, and dependencies which we fork and use in those projects. While technical details in this document are specific to `go-algorand`, the general ideas are applicable to all of our projects.

## Non-code Contributions

While contributions come in many forms, this document is focused on code. For other types of involvement, see the following:
* [Reporting issues and features requests.][go-algorand-issues]
* [Security vulnerability disclosures.][security-disclosure]
* [Documentation improvements.][algorand-docs]

## Contribution Model

All changes to `go-algorand` are made through the same process: a pull request targeting the `master` branch. This goes for internal and external contributions. To familiarize yourself with the process we recommend that you review the current open pull requests, and the GitHub documentation for [creating a pull request from a fork][gh-pr-process].

Note: some of our other projects are using gitflow, for these the process is the same but you will target pull requests against the `develop` branch.

## Communication Channels

The core development team monitors the Algorand [discord community](https://discord.gg/algorand) and regularly responds to questions and suggestions. For very technical questions and implementation discussions GitHub Issues and Pull Requests are a good way to reach maintainers.

## Pull Requests

All changes are made via pull requests.

Small changes are easier to review and merge than large ones, so the more focused a PR the better. If a feature requires refactoring, the refactoring should be a separate PR. If refactoring uncovers a bug, the fix should be a separate PR. These are not strict rules, but generally speaking, they make things easier to review which speeds up the PR process.

### General Guidelines

* Have a clear well-formatted description in the pull request. This helps reviewers and later serves as documentation in the release notes.
* Code must adhere to the [Go formatting guidelines](https://golang.org/doc/effective_go.html).
* All tests must be passing.
* New unit and integration tests should be added to ensure correctness and prevent regressions where appropriate.
* Run linting and code formatting tools, see [the README](README.md) for details.
* All CI checks should pass.
* Use draft mode for PRs that are still in progress.

### Peer Review

This is the single most important part of introducing new code to `go-algorand`.

#### Concept Review

Because code reviews are a considerable time commitment, the first step for peer review is convincing reviewers that it is worth their time. Typically this is done by keeping changes small, writing a thorough description to clearly explain the need for a given improvement, or discussing larger changes ahead of time through one of the communication channels.

If reviewers are not convinced about the merits of a change, they may reject a PR instead of reviewing it. All rejections should include the rationale for how that decision was reached. It is not uncommon for this to occur. Some users opt to maintain long running forks to add features which are not suitable for the upstream repo at this time.

#### Code Review

Reviewers will leave feedback directly on the pull request, typically inline with the code. This is an opportunity to discuss the changes. If a PR is left open with unresolved feedback it may eventually be closed.

The project maintainers are responsible for the code in `go-algorand`, so ultimately whether or not a pull request is merged depends on their involvement.

#### Merge

All changes are subject to a minimum of two reviews from subject matter experts prior to merge. Once this approval is reached a small number of committers are responsible for merging the changes. The list of committers is limited for practical and security reasons.

[gh-pr-process]: https://help.github.com/en/articles/creating-a-pull-request-from-a-fork
[go-algorand-issues]: https://github.com/algorand/go-algorand/issues/new/choose
[security-disclosure]: https://github.com/algorand/go-algorand/security/policy
[algorand-docs]: https://github.com/algorand/docs/blob/staging/CONTRIBUTING.md
