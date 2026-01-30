# Context for GitHub Actions Migration

This document contains essential context for any agent or process working on the GitHub Actions migration. It should be included in context windows when working on related tasks.

## Repository Overview

- **Repository**: `github.com/algorand/go-algorand`
- **Language**: Go with CGO (libsodium cryptography)
- **Current CI**: Jenkins + custom Python tool called "Mule"
- **Target CI**: GitHub Actions

## Critical Technical Details

### CGO and libsodium

The project uses CGO with a forked libsodium library:
- Source: `crypto/libsodium-fork/`
- Built at compile time via `make libsodium`
- Produces: `crypto/libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a`
- Required for: VRF, ed25519, curve25519, secp256k1

This means:
- Cannot use `CGO_ENABLED=0`
- Cross-compilation requires appropriate C toolchain
- macOS universal builds require building twice and using `lipo`

### Build Targets

Key Makefile targets:
```bash
make build              # Build all binaries
make ci-build           # CI build for current OS/ARCH
make ci-build-universal # macOS universal binary (arm64 + amd64 lipo'd)
make libsodium          # Build libsodium dependency
```

### Package Types

Two package variants:
1. **algorand** - Core node (algod, goal, kmd, etc.)
2. **algorand-devtools** - Developer tools (carpenter, tealdbg, msgpacktool)

### Tarball Types

Three tarball types per platform:
1. **node_*** - Full node package (bin/, data/, genesis/)
2. **install_*** - Bootstrap installer (updater, update.sh only)
3. **tools_*** - Additional tools (carpenter, pingpong, etc.)

## Channel System

| Channel | Network | Default Genesis | Trigger |
|---------|---------|-----------------|---------|
| `nightly` | devnet | devnet | Cron on master |
| `beta` | betanet | betanet | Tag `v*-beta` |
| `stable` | mainnet | mainnet | Tag `v*-stable` |

The channel affects:
- Package naming: `algorand_{channel}_linux-amd64_{version}.deb`
- Default genesis.json copied to `/var/lib/algorand/genesis.json`
- Apt unattended-upgrades configuration

## Version Scheme

**Tagged releases**: Parse from git tag
- `v4.5.0-beta` → version `4.5.0`, channel `beta`
- `v4.5.0-stable` → version `4.5.0`, channel `stable`

**Nightly**: Auto-generated with datestamp
- Format: `{major}.{minor}.{YYYYMMDDHHMM}`
- Example: `4.5.202601301318`

## Artifact Matrix

### Linux (per arch: amd64, arm64)
- `algorand_{channel}_linux-{arch}_{version}.deb`
- `algorand-devtools_{channel}_linux-{arch}_{version}.deb`
- `algorand-{version}-1.{x86_64|aarch64}.rpm`
- `algorand-devtools-{version}-1.{x86_64|aarch64}.rpm`
- `node_{channel}_linux-{arch}_{version}.tar.gz`
- `install_{channel}_linux-{arch}_{version}.tar.gz`
- `tools_{channel}_linux-{arch}_{version}.tar.gz`
- `hashes_{channel}_linux_{arch}_{version}`

### macOS (universal only)
- `node_{channel}_darwin-universal_{version}.tar.gz`
- `install_{channel}_darwin-universal_{version}.tar.gz`
- `tools_{channel}_darwin-universal_{version}.tar.gz`
- `hashes_{channel}_darwin_universal_{version}`

## Key Scripts

| Script | Purpose |
|--------|---------|
| `scripts/configure_dev.sh` | Install build dependencies |
| `scripts/build_package.sh` | Build single platform package |
| `scripts/build_packages.sh` | Build and create tarballs |
| `scripts/release/mule/package/deb/package.sh` | Create .deb packages |
| `scripts/release/mule/package/rpm/package.sh` | Create .rpm packages |
| `scripts/compute_build_number.sh` | Compute version number |
| `scripts/release/mule/common/get_channel.sh` | Map network to channel |
| `scripts/compute_branch_release_network.sh` | Map network to default genesis |

## GitHub Actions Resources

### Runners to Use
- `ubuntu-24.04` - Linux amd64 builds
- `ubuntu-24.04-arm` - Linux arm64 builds (native ARM runner)
- `macos-14` - macOS universal builds (M1/M3 Apple Silicon)

### Key Actions
- `actions/checkout@v4` - Clone repository
- `actions/upload-artifact@v4` / `download-artifact@v4` - Artifact handling
- `actions/attest-build-provenance@v2` - SLSA provenance
- `actions/attest-sbom@v1` - SBOM attestation
- `softprops/action-gh-release@v2` - Create GitHub releases
- `aws-actions/configure-aws-credentials@v4` - AWS OIDC auth for S3

### Existing Actions in Repo
- `.github/actions/setup-go` - Go toolchain setup
- `.github/actions/setup-test` - Test environment setup

## Security Requirements

1. **SBOM** - Generate Software Bill of Materials
2. **Provenance** - SLSA build provenance attestation
3. **Signing** - Sigstore-based via GitHub Attestations
4. **No secrets in workflows** - Use OIDC for AWS, Sigstore for signing

## Files to Modify/Create

### New Files
- `.github/workflows/release.yml` - Tagged release workflow
- `.github/workflows/nightly.yml` - Nightly build workflow
- `.github/actions/setup-build/action.yml` - Reusable build setup

### Files to Reference (not modify initially)
- `scripts/release/mule/package/deb/package.sh`
- `scripts/release/mule/package/rpm/package.sh`
- `scripts/build_packages.sh`
- `Makefile` and `scripts/release/mule/Makefile.mule`

## Environment Variables

Key environment variables used by build scripts:
```
CHANNEL     - Release channel (nightly/beta/stable)
VERSION     - Full version string (e.g., 4.5.0)
NETWORK     - Network name (devnet/betanet/mainnet)
FULLVERSION - Same as VERSION (legacy compatibility)
OS_TYPE     - Operating system (linux/darwin)
ARCH        - Architecture (amd64/arm64)
GOOS        - Go OS target
GOARCH      - Go architecture target
```

## Testing the Migration

### Fork Testing

The workflows are designed to be testable from a fork (`onetechnical/go-algorand`) before merging to upstream (`algorand/go-algorand`).

Key points:
- Use repository variables (`vars.AWS_ACCOUNT_ID`, `vars.S3_BUCKET`) instead of hardcoded values
- S3 publishing can be skipped if AWS isn't configured
- Attestations work but are scoped to the fork owner
- GitHub Releases go to the fork's releases page

See [fork-testing.md](./fork-testing.md) for detailed setup instructions.

### Testing Steps

1. Create workflow on a branch
2. Push to fork and create test tag (e.g., `v0.0.1-test-beta`)
3. Or manually trigger with `workflow_dispatch`
4. Compare artifacts with Jenkins-produced artifacts
5. Run produced packages through installation tests
6. Verify signatures and attestations
