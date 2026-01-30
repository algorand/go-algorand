# Architecture: GitHub Actions Migration

## Current Architecture (Jenkins + Mule)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Jenkins Pipeline                               │
│                         (go-algorand-ci repo)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Jenkinsfile ──► muleCI.groovy ──► Mule CLI ──► mule.yaml              │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │ Kubernetes Pod  │  │ Kubernetes Pod  │  │ Self-hosted Mac │         │
│  │ (linux-amd64)   │  │ (linux-arm64)   │  │ (M1 darwin)     │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                    │                   │
│           └──────────┬─────────┴────────────────────┘                   │
│                      ▼                                                  │
│           ┌─────────────────┐                                           │
│           │   S3 Stash      │  (artifact storage between stages)        │
│           └────────┬────────┘                                           │
│                    ▼                                                    │
│           ┌─────────────────┐                                           │
│           │ Kubernetes Pod  │  (packaging: deb/rpm)                     │
│           └────────┬────────┘                                           │
│                    ▼                                                    │
│           ┌─────────────────┐                                           │
│           │ On-prem Signer  │  (GPG signing)                            │
│           └────────┬────────┘                                           │
│                    ▼                                                    │
│           ┌─────────────────┐                                           │
│           │   S3 Archive    │                                           │
│           └─────────────────┘                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

**Problems with current architecture:**
- Two repositories involved (go-algorand, go-algorand-ci)
- Custom tooling (Mule) requires maintenance
- Self-hosted Mac agent requires maintenance
- Complex artifact passing via S3
- GPG signing tied to on-prem infrastructure
- Jenkins + Kubernetes complexity

## Target Architecture (GitHub Actions)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    .github/workflows/release.yml                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  on: push tags v*-beta, v*-stable                                      │
│  on: workflow_dispatch                                                  │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    prepare (compute version/channel)             │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                 │                                       │
│                                 ▼                                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │  ubuntu-24.04   │  │ubuntu-24.04-arm │  │    macos-14     │         │
│  │  (linux-amd64)  │  │  (linux-arm64)  │  │(darwin-universal)│        │
│  │                 │  │                 │  │                 │         │
│  │ • make libsodium│  │ • make libsodium│  │ • make libsodium│         │
│  │ • make ci-build │  │ • make ci-build │  │ • make ci-build │         │
│  │                 │  │                 │  │   -universal    │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                    │                   │
│           │    GitHub Artifacts (upload-artifact)   │                   │
│           └──────────┬─────────┴────────────────────┘                   │
│                      ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    package-linux (matrix: amd64, arm64)          │   │
│  │                                                                  │   │
│  │  • Download build artifacts                                      │   │
│  │  • scripts/release/mule/package/deb/package.sh                  │   │
│  │  • scripts/release/mule/package/rpm/package.sh (in container)   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                 │                                       │
│                                 ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    finalize                                      │   │
│  │                                                                  │   │
│  │  • Collect all artifacts                                        │   │
│  │  • Generate checksums (hashes_*)                                │   │
│  │  • Generate SBOM (syft)                                         │   │
│  │  • Create attestations (provenance, SBOM)                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                 │                                       │
│                                 ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    publish                                       │   │
│  │                                                                  │   │
│  │  • Create GitHub Release                                        │   │
│  │  • Upload to S3 (via OIDC, no static credentials)              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Design Decisions

### 1. Single Repository

All CI configuration lives in go-algorand itself:
- `.github/workflows/release.yml`
- `.github/workflows/nightly.yml`
- `.github/actions/setup-build/action.yml`

No dependency on go-algorand-ci repository for builds.

### 2. GitHub-Hosted Runners Only

| Platform | Runner | Notes |
|----------|--------|-------|
| Linux amd64 | `ubuntu-24.04` | Standard GitHub runner |
| Linux arm64 | `ubuntu-24.04-arm` | Native ARM runner (not emulation) |
| macOS | `macos-14` | Apple Silicon (M1/M3), free for open source |

No self-hosted runners required.

### 3. Native Artifact Storage

Use GitHub's built-in artifact system instead of S3 for intermediate artifacts:
- `actions/upload-artifact@v4`
- `actions/download-artifact@v4`

Benefits:
- No AWS credentials needed for build jobs
- Automatic cleanup
- Integrated with GitHub UI

S3 is still used for final publishing (updater compatibility).

### 4. Sigstore-Based Signing

Replace GPG signing with GitHub Attestations:
- `actions/attest-build-provenance@v2`
- `actions/attest-sbom@v1`

Benefits:
- No key management
- Transparency log (publicly auditable)
- SLSA provenance included
- Verification via `gh attestation verify`

### 5. Trunk-Based Development

Releases are tagged directly on master:
```
master ──●────●────●────●────●────●─────
         │              │    │
         │              │    └─ v4.6.0-stable
         │              └─ v4.6.0-beta
         └─ nightly (cron)
```

No rel/ branches needed for CI purposes.

### 6. Reuse Existing Scripts

The existing packaging scripts work well and should be reused:
- `scripts/release/mule/package/deb/package.sh`
- `scripts/release/mule/package/rpm/package.sh`
- `scripts/build_packages.sh`

Only the orchestration (mule) is being replaced, not the actual build logic.

## Job Dependency Graph

```
                    ┌──────────┐
                    │ prepare  │
                    └────┬─────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
   ┌───────────┐  ┌───────────┐  ┌───────────┐
   │  build    │  │  build    │  │  build    │
   │linux-amd64│  │linux-arm64│  │  darwin   │
   └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
         │               │               │
         ▼               ▼               │
   ┌───────────┐  ┌───────────┐         │
   │ package   │  │ package   │         │
   │linux-amd64│  │linux-arm64│         │
   └─────┬─────┘  └─────┬─────┘         │
         │               │               │
         └───────────────┼───────────────┘
                         ▼
                  ┌───────────┐
                  │ finalize  │
                  │(sbom,hash)│
                  └─────┬─────┘
                        ▼
                  ┌───────────┐
                  │  publish  │
                  └───────────┘
```

## Security Model

### Build Isolation
- Each job runs in a fresh VM
- No persistent state between jobs
- Artifacts are the only data passing mechanism

### Credential Management
- **AWS**: OIDC federation (no static credentials)
- **Signing**: Sigstore OIDC (no keys to manage)
- **GitHub**: Automatic `GITHUB_TOKEN`

### Supply Chain Security
- SBOM generated for every release
- SLSA provenance attestation
- Dependency scanning (govulncheck, grype)
- All attestations logged to Sigstore transparency log

### Permissions (Principle of Least Privilege)
```yaml
permissions:
  contents: write       # Create releases
  id-token: write       # OIDC for AWS and Sigstore
  attestations: write   # Create attestations
```
