# Specification: Release Workflow

## Overview

The release workflow handles tagged releases (beta and stable channels).

**File**: `.github/workflows/release.yml`

## Triggers

```yaml
on:
  push:
    tags:
      - 'v*-beta'
      - 'v*-stable'
  workflow_dispatch:
    inputs:
      version:
        description: 'Version (e.g., 4.5.0)'
        required: true
        type: string
      channel:
        description: 'Release channel'
        required: true
        type: choice
        options:
          - beta
          - stable
```

## Version/Channel Parsing

**Tag Format**: `v{major}.{minor}.{patch}-{channel}`

Examples:
- `v4.5.0-beta` → version `4.5.0`, channel `beta`
- `v4.5.0-stable` → version `4.5.0`, channel `stable`
- `v4.5.0-nightly` → version `4.5.0`, channel `nightly`
- `v4.5.0-dev` → version `4.5.0`, channel `dev`

Valid channels: `beta`, `stable`, `nightly`, `dev` (the last component after the final hyphen).

For tag triggers, parse from the tag:
```bash
# Tag: v4.5.0-beta
TAG="${GITHUB_REF_NAME}"           # v4.5.0-beta
CHANNEL="${TAG##*-}"                # beta (extract channel first)
VERSION="${TAG#v}"                  # 4.5.0-beta
VERSION="${VERSION%-${CHANNEL}}"    # 4.5.0 (remove known channel suffix)
```

For manual triggers, use inputs directly.

## Channel to Network Mapping

```bash
case "$CHANNEL" in
  beta)    NETWORK="betanet" ;;
  stable)  NETWORK="mainnet" ;;
  nightly) NETWORK="devnet" ;;
  dev)     NETWORK="devnet" ;;
esac
```

## Jobs

### Job: `prepare`

**Purpose**: Parse inputs, compute version/channel, set outputs for downstream jobs.

**Runs on**: `ubuntu-24.04`

**Outputs**:
- `version` - e.g., `4.5.0`
- `channel` - e.g., `beta`
- `network` - e.g., `betanet`

**Steps**:
1. Checkout code
2. Parse version/channel from tag or inputs
3. Validate version format
4. Set outputs

### Job: `build`

**Purpose**: Compile binaries for each platform.

**Needs**: `prepare`

**Strategy Matrix**:
```yaml
matrix:
  include:
    - runner: ubuntu-24.04
      os: linux
      arch: amd64
      make_target: ci-build
    - runner: ubuntu-24.04-arm
      os: linux
      arch: arm64
      make_target: ci-build
    - runner: macos-14
      os: darwin
      arch: universal
      make_target: ci-build-universal
```

**Steps**:
1. Checkout code
2. Setup Go (use existing `.github/actions/setup-go`)
3. Build libsodium: `make libsodium`
4. Build binaries: `make ${{ matrix.make_target }}`
5. Upload artifact: `build-${{ matrix.os }}-${{ matrix.arch }}`

**Environment**:
```yaml
env:
  CHANNEL: ${{ needs.prepare.outputs.channel }}
  VERSION: ${{ needs.prepare.outputs.version }}
  NETWORK: ${{ needs.prepare.outputs.network }}
  FULLVERSION: ${{ needs.prepare.outputs.version }}
```

**Version Override**: When `VERSION` is set (e.g., `VERSION=4.5.0`), the Makefile parses it and overrides the version components via ldflags:
- `VersionMajorOverride` - overrides `config.VersionMajor` constant
- `VersionMinorOverride` - overrides `config.VersionMinor` constant
- `BUILDNUMBER` - set to the patch version

This ensures the binary version matches the tag version (e.g., `v4.5.0-beta` → `4.5.0.beta` in binary output).

**Artifact Contents**:
```
tmp/node_pkgs/
├── {channel}/
│   └── {os}-{arch}/
│       ├── bin/
│       ├── data/
│       ├── genesis/
│       ├── tools/
│       └── test-utils/
```

### Job: `package-linux`

**Purpose**: Create .deb and .rpm packages from Linux builds using nFPM.

**Needs**: `prepare`, `build`

**Strategy Matrix**:
```yaml
matrix:
  arch: [amd64, arm64]
```

**Runs on**: `ubuntu-24.04`

**nFPM Configuration**: `.github/packaging/`
- `algorand.nfpm.yaml` - main package (algod, goal, kmd, etc.)
- `algorand-devtools.nfpm.yaml` - devtools package (carpenter, tealdbg, msgpacktool)
- `scripts/` - unified maintainer scripts (detect deb vs rpm at runtime)

**Steps**:
1. Checkout code
2. Download artifact: `build-linux-${{ matrix.arch }}`
3. Install nFPM
4. Generate unattended-upgrades config (deb only)
5. Build packages with nFPM:
   ```bash
   # Set environment for nFPM
   export VERSION CHANNEL PKG_NAME DEFAULTNETWORK BINDIR TOOLSDIR GOARCH

   # Build .deb
   nfpm package -p deb -f .github/packaging/algorand.nfpm.yaml
   nfpm package -p deb -f .github/packaging/algorand-devtools.nfpm.yaml

   # Build .rpm
   nfpm package -p rpm -f .github/packaging/algorand.nfpm.yaml
   nfpm package -p rpm -f .github/packaging/algorand-devtools.nfpm.yaml
   ```
6. Upload artifact: `packages-linux-${{ matrix.arch }}`

**Package Naming**:
- `algorand` / `algorand-beta` (main package)
- `algorand-devtools` / `algorand-devtools-beta` (devtools)

**Environment Variables for nFPM**:
- `VERSION` - Package version (e.g., 4.5.0)
- `CHANNEL` - Release channel (stable, beta, nightly, dev)
- `PKG_NAME` - "algorand" or "algorand-beta"
- `DEVTOOLS_PKG_NAME` - "algorand-devtools" or "algorand-devtools-beta"
- `DEFAULTNETWORK` - Default genesis (mainnet, betanet, devnet)
- `BINDIR` - Path to built binaries (bin/)
- `TOOLSDIR` - Path to devtools binaries (tools/)
- `GOARCH` - Architecture (amd64, arm64)

**Artifact Contents**:
```
packages/
├── {pkg_name}_{channel}_linux-{arch}_{version}.deb
├── {devtools_pkg_name}_{channel}_linux-{arch}_{version}.deb
├── {pkg_name}-{version}-1.{x86_64|aarch64}.rpm
├── {devtools_pkg_name}-{version}-1.{x86_64|aarch64}.rpm
├── node_{channel}_linux-{arch}_{version}.tar.gz
├── install_{channel}_linux-{arch}_{version}.tar.gz
└── tools_{channel}_linux-{arch}_{version}.tar.gz
```

### Job: `test-packages`

**Purpose**: Verify packages install correctly in clean containers.

**Needs**: `prepare`, `package-linux`

**Strategy Matrix**:
```yaml
matrix:
  include:
    - pkg_type: deb
      image: ubuntu:24.04
      arch: amd64
    - pkg_type: deb
      image: ubuntu:24.04
      arch: arm64
    - pkg_type: rpm
      image: fedora:40
      arch: amd64
    - pkg_type: rpm
      image: fedora:40
      arch: arm64
```

**Tests**:
1. Install package in container
2. Verify binaries are installed (`command -v algod goal kmd`)
3. Verify version output (`algod -v`)
4. Verify systemd service file exists
5. Verify data directory exists

### Job: `package-darwin`

**Purpose**: Ensure darwin tarballs are properly named and organized.

**Needs**: `prepare`, `build`

**Runs on**: `ubuntu-24.04`

**Steps**:
1. Download artifact: `build-darwin-universal`
2. Verify/rename tarballs to final names
3. Upload artifact: `packages-darwin-universal`

**Artifact Contents**:
```
tmp/node_pkgs/darwin/universal/
├── node_{channel}_darwin-universal_{version}.tar.gz
├── install_{channel}_darwin-universal_{version}.tar.gz
└── tools_{channel}_darwin-universal_{version}.tar.gz
```

### Job: `finalize`

**Purpose**: Collect all artifacts, generate checksums, SBOM, and attestations.

**Needs**: `prepare`, `package-linux`, `package-darwin`

**Runs on**: `ubuntu-24.04`

**Permissions**:
```yaml
permissions:
  contents: write
  id-token: write
  attestations: write
```

**Steps**:
1. Download all package artifacts
2. Generate checksums:
   ```bash
   for platform in linux/amd64 linux/arm64 darwin/universal; do
     cd "packages/$platform"
     sha256sum *.tar.gz *.deb *.rpm 2>/dev/null > \
       "hashes_${CHANNEL}_${platform//\//_}_${VERSION}"
   done
   ```
3. Generate SBOM:
   ```yaml
   - uses: anchore/sbom-action@v0
     with:
       format: spdx-json
       output-file: sbom.spdx.json
   ```
4. Attest provenance:
   ```yaml
   - uses: actions/attest-build-provenance@v2
     with:
       subject-path: 'packages/**/*.tar.gz,packages/**/*.deb,packages/**/*.rpm'
   ```
5. Attest SBOM:
   ```yaml
   - uses: actions/attest-sbom@v1
     with:
       subject-path: 'packages/**/*.tar.gz,packages/**/*.deb,packages/**/*.rpm'
       sbom-path: 'sbom.spdx.json'
   ```
6. Upload artifact: `release-artifacts`

### Job: `publish-github`

**Purpose**: Create GitHub Release with all artifacts.

**Needs**: `prepare`, `finalize`

**Runs on**: `ubuntu-24.04`

**Steps**:
1. Download `release-artifacts`
2. Create GitHub Release:
   ```yaml
   - uses: softprops/action-gh-release@v2
     with:
       tag_name: v${{ needs.prepare.outputs.version }}-${{ needs.prepare.outputs.channel }}
       name: v${{ needs.prepare.outputs.version }}-${{ needs.prepare.outputs.channel }}
       body: |
         ## Algorand ${{ needs.prepare.outputs.version }} (${{ needs.prepare.outputs.channel }})

         ### Verification
         ```bash
         gh attestation verify <artifact> --owner algorand
         ```

         ### Checksums
         See `hashes_*` files for SHA256 checksums.
       files: |
         packages/**/*.tar.gz
         packages/**/*.deb
         packages/**/*.rpm
         packages/**/hashes_*
         sbom.spdx.json
   ```

### Job: `publish-s3`

**Purpose**: Upload artifacts to S3 for updater compatibility.

**Needs**: `prepare`, `finalize`

**Runs on**: `ubuntu-24.04`

**Environment**: `release` (requires approval for production)

**Steps**:
1. Configure AWS credentials (OIDC):
   ```yaml
   - uses: aws-actions/configure-aws-credentials@v4
     with:
       role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-release
       aws-region: us-east-1
   ```
2. Download `release-artifacts`
3. Upload to S3:
   ```bash
   aws s3 cp packages/ \
     s3://${{ vars.S3_BUCKET }}/${{ needs.prepare.outputs.channel }}/${{ needs.prepare.outputs.version }}/ \
     --recursive
   ```

## Complete Workflow Structure

```yaml
name: Release

on:
  push:
    tags: ['v*-beta', 'v*-stable']
  workflow_dispatch:
    inputs:
      version:
        required: true
        type: string
      channel:
        required: true
        type: choice
        options: [beta, stable]

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  prepare:
    # ... (see above)

  build:
    needs: prepare
    strategy:
      matrix:
        include:
          - runner: ubuntu-24.04
            os: linux
            arch: amd64
          - runner: ubuntu-24.04-arm
            os: linux
            arch: arm64
          - runner: macos-14
            os: darwin
            arch: universal
    # ... (see above)

  package-linux:
    needs: [prepare, build]
    strategy:
      matrix:
        arch: [amd64, arm64]
    # ... (see above)

  package-darwin:
    needs: [prepare, build]
    # ... (see above)

  finalize:
    needs: [prepare, package-linux, package-darwin]
    # ... (see above)

  publish-github:
    needs: [prepare, finalize]
    # ... (see above)

  publish-s3:
    needs: [prepare, finalize]
    environment: release
    # ... (see above)
```

## Testing

### Manual Testing
1. Create workflow on feature branch
2. Trigger via `workflow_dispatch` with test version
3. Verify artifacts are created correctly
4. Compare with Jenkins-produced artifacts

### Automated Testing
- Artifact naming validation
- Package installation tests (spin up VM, install .deb/.rpm)
- Signature verification tests
- SBOM validation

## Rollout Plan

1. **Week 1-2**: Implement build jobs, verify artifacts match
2. **Week 3**: Add packaging jobs
3. **Week 4**: Add signing/attestation
4. **Week 5**: Add publishing (GitHub Releases only initially)
5. **Week 6**: Add S3 publishing, run parallel with Jenkins
6. **Week 7-8**: Monitor, fix issues, cutover
