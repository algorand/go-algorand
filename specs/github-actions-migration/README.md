# GitHub Actions Migration Specification

This directory contains specifications for migrating the go-algorand build and release process from Jenkins/Mule to GitHub Actions.

## Overview

**Goal**: Replace the existing Jenkins + Mule CI/CD pipeline with native GitHub Actions workflows, simplifying the build process while adding modern security features (SBOM, attestations, provenance).

**Timeline**: ~2-3 months

**Status**: Planning/Specification Phase

## Documents

| Document | Purpose |
|----------|---------|
| [context.md](./context.md) | Key context for agents/processes working on this migration |
| [architecture.md](./architecture.md) | Overall architecture and design decisions |
| [release-workflow.md](./release-workflow.md) | Specification for tagged release builds |
| [nightly-workflow.md](./nightly-workflow.md) | Specification for nightly builds |
| [artifacts.md](./artifacts.md) | Detailed artifact matrix and packaging |
| [security.md](./security.md) | Signing, SBOM, attestation details |
| [fork-testing.md](./fork-testing.md) | Guide for testing from a fork before upstream merge |
| [implementation-checklist.md](./implementation-checklist.md) | Trackable implementation tasks |

## Key Decisions

1. **Eliminate Mule CLI** - Use native GitHub Actions YAML
2. **Eliminate self-hosted Mac** - Use GitHub's `macos-14` runners
3. **Trunk-based development** - Tag releases from master, no rel/ branches for CI
4. **Simplify macOS artifacts** - Ship only universal binaries
5. **Modern signing** - GitHub Attestations (Sigstore-based) for provenance
6. **Version scheme** - Parse from tags for releases, datestamp for nightlies

## Migration Phases

| Phase | Description | Duration |
|-------|-------------|----------|
| 1 | Build workflow (compile binaries) | 2 weeks |
| 2 | Packaging (.deb, .rpm, tarballs) | 1-2 weeks |
| 3 | Signing & attestation | 1-2 weeks |
| 4 | Publishing (GitHub Releases, S3) | 1 week |
| 5 | Nightly workflow | 1 week |
| 6 | Parallel running & cutover | 2-4 weeks |

## Out of Scope (Deferred)

- Apt/Yum repository management
- Docker image builds
- releases.algorand.com updates
- Deprecating rel/ branches (organizational change)
