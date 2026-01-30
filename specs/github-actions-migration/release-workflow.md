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

For tag triggers, parse from the tag:
```bash
# Tag: v4.5.0-beta
TAG="${GITHUB_REF_NAME}"           # v4.5.0-beta
VERSION="${TAG#v}"                  # 4.5.0-beta
VERSION="${VERSION%-*}"             # 4.5.0
CHANNEL="${TAG##*-}"                # beta
```

For manual triggers, use inputs directly.

## Channel to Network Mapping

```bash
case "$CHANNEL" in
  beta)   NETWORK="betanet" ;;
  stable) NETWORK="mainnet" ;;
  *)      NETWORK="devnet"  ;;
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

**Purpose**: Create .deb and .rpm packages from Linux builds.

**Needs**: `prepare`, `build`

**Strategy Matrix**:
```yaml
matrix:
  arch: [amd64, arm64]
```

**Runs on**: `ubuntu-24.04`

**Steps**:
1. Checkout code
2. Download artifact: `build-linux-${{ matrix.arch }}`
3. Build .deb packages:
   ```bash
   scripts/release/mule/package/deb/package.sh algorand
   scripts/release/mule/package/deb/package.sh algorand-devtools
   ```
4. Build .rpm packages (in container):
   ```bash
   docker run --rm \
     -v $PWD:/work \
     -w /work \
     -e NETWORK=$NETWORK \
     -e VERSION=$VERSION \
     centos:stream10 \
     bash -c "
       dnf install -y rpm-build &&
       scripts/release/mule/package/rpm/package.sh algorand &&
       scripts/release/mule/package/rpm/package.sh algorand-devtools
     "
   ```
5. Upload artifact: `packages-linux-${{ matrix.arch }}`

**Artifact Contents**:
```
tmp/node_pkgs/linux/{arch}/
├── algorand_{channel}_linux-{arch}_{version}.deb
├── algorand-devtools_{channel}_linux-{arch}_{version}.deb
├── algorand-{version}-1.{x86_64|aarch64}.rpm
├── algorand-devtools-{version}-1.{x86_64|aarch64}.rpm
├── node_{channel}_linux-{arch}_{version}.tar.gz
├── install_{channel}_linux-{arch}_{version}.tar.gz
└── tools_{channel}_linux-{arch}_{version}.tar.gz
```

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
