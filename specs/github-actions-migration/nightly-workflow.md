# Specification: Nightly Workflow

## Overview

The nightly workflow runs daily builds from master, producing development packages for testing.

**File**: `.github/workflows/nightly.yml`

## Triggers

```yaml
on:
  schedule:
    # Run at 2:00 AM UTC daily
    - cron: '0 2 * * *'
  workflow_dispatch:
    inputs:
      base_version:
        description: 'Base version (major.minor)'
        required: false
        type: string
        default: ''
```

## Version Generation

Nightly versions use datestamp format: `{major}.{minor}.{YYYYMMDDHHMM}`

Example: `4.5.202601301318`

### Determining Base Version

Priority order:
1. Manual input (if provided via `workflow_dispatch`)
2. Parse from most recent tag on master
3. Fall back to `VERSION` file (if it exists)

```bash
get_base_version() {
  if [ -n "${{ inputs.base_version }}" ]; then
    echo "${{ inputs.base_version }}"
    return
  fi

  # Get most recent version tag
  LATEST_TAG=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo "")
  if [ -n "$LATEST_TAG" ]; then
    # v4.5.0-stable -> 4.5
    VERSION="${LATEST_TAG#v}"
    VERSION="${VERSION%-*}"
    MAJOR="${VERSION%%.*}"
    MINOR="${VERSION#*.}"
    MINOR="${MINOR%%.*}"
    echo "${MAJOR}.${MINOR}"
    return
  fi

  # Fallback
  echo "4.5"
}

BASE_VERSION=$(get_base_version)
DATESTAMP=$(date -u +%Y%m%d%H%M)
VERSION="${BASE_VERSION}.${DATESTAMP}"
```

## Channel Configuration

Nightly builds always use:
- **Channel**: `nightly`
- **Network**: `devnet`
- **Default Genesis**: `devnet/genesis.json`

## Jobs

The nightly workflow uses the same job structure as the release workflow, with these differences:

### Job: `prepare`

**Outputs**:
- `version` - e.g., `4.5.202601301318`
- `channel` - always `nightly`
- `network` - always `devnet`

### Job: `build`

Same as release workflow.

### Job: `package-linux`

Same as release workflow.

### Job: `package-darwin`

Same as release workflow.

### Job: `finalize`

Same as release workflow (SBOM, attestations, checksums).

### Job: `publish-github`

**Differences from release**:
- Creates a pre-release (not a full release)
- Overwrites previous nightly release (only keep latest)

```yaml
- uses: softprops/action-gh-release@v2
  with:
    tag_name: nightly
    name: Nightly Build ${{ needs.prepare.outputs.version }}
    prerelease: true
    body: |
      ## Nightly Build

      **Version**: ${{ needs.prepare.outputs.version }}
      **Built from**: ${{ github.sha }}
      **Date**: ${{ github.event.head_commit.timestamp || github.event.repository.updated_at }}

      This is an automated nightly build from the master branch.
      It is intended for testing purposes only.

      ### Verification
      ```bash
      gh attestation verify <artifact> --owner algorand
      ```
    files: |
      packages/**/*.tar.gz
      packages/**/*.deb
      packages/**/*.rpm
      packages/**/hashes_*
      sbom.spdx.json
```

### Job: `publish-s3`

**Differences from release**:
- Uploads to nightly channel path
- May not require approval (it's not production)

```bash
aws s3 cp packages/ \
  s3://${{ vars.S3_BUCKET }}/nightly/${{ needs.prepare.outputs.version }}/ \
  --recursive

# Also update "latest" symlink/copy
aws s3 sync packages/ \
  s3://${{ vars.S3_BUCKET }}/nightly/latest/ \
  --delete
```

## Complete Workflow Structure

```yaml
name: Nightly Build

on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:
    inputs:
      base_version:
        description: 'Base version (major.minor, e.g., 4.5)'
        required: false
        type: string

permissions:
  contents: write
  id-token: write
  attestations: write

env:
  CHANNEL: nightly
  NETWORK: devnet

jobs:
  prepare:
    runs-on: ubuntu-24.04
    outputs:
      version: ${{ steps.version.outputs.version }}
      channel: nightly
      network: devnet
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Need tags for version detection

      - name: Compute version
        id: version
        run: |
          if [ -n "${{ inputs.base_version }}" ]; then
            BASE="${{ inputs.base_version }}"
          else
            LATEST_TAG=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo "v4.5.0")
            VERSION="${LATEST_TAG#v}"
            VERSION="${VERSION%-*}"
            BASE="${VERSION%.*}"
          fi

          DATESTAMP=$(date -u +%Y%m%d%H%M)
          VERSION="${BASE}.${DATESTAMP}"

          echo "version=${VERSION}" >> "$GITHUB_OUTPUT"
          echo "Generated version: ${VERSION}"

  build:
    needs: prepare
    strategy:
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
    runs-on: ${{ matrix.runner }}
    env:
      CHANNEL: nightly
      VERSION: ${{ needs.prepare.outputs.version }}
      FULLVERSION: ${{ needs.prepare.outputs.version }}
      NETWORK: devnet
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup-go

      - name: Build libsodium
        run: make libsodium

      - name: Build binaries
        run: make ${{ matrix.make_target }}

      - uses: actions/upload-artifact@v4
        with:
          name: build-${{ matrix.os }}-${{ matrix.arch }}
          path: tmp/node_pkgs/
          retention-days: 7

  package-linux:
    needs: [prepare, build]
    strategy:
      matrix:
        arch: [amd64, arm64]
    runs-on: ubuntu-24.04
    env:
      CHANNEL: nightly
      VERSION: ${{ needs.prepare.outputs.version }}
      NETWORK: devnet
    steps:
      - uses: actions/checkout@v4

      - uses: actions/download-artifact@v4
        with:
          name: build-linux-${{ matrix.arch }}
          path: tmp/node_pkgs/

      - name: Build .deb packages
        run: |
          scripts/release/mule/package/deb/package.sh algorand
          scripts/release/mule/package/deb/package.sh algorand-devtools

      - name: Build .rpm packages
        run: |
          docker run --rm \
            -v $PWD:/work \
            -w /work \
            -e NETWORK=devnet \
            -e VERSION=${{ needs.prepare.outputs.version }} \
            -e CHANNEL=nightly \
            centos:stream10 \
            bash -c "
              dnf install -y rpm-build &&
              scripts/release/mule/package/rpm/package.sh algorand &&
              scripts/release/mule/package/rpm/package.sh algorand-devtools
            "

      - uses: actions/upload-artifact@v4
        with:
          name: packages-linux-${{ matrix.arch }}
          path: tmp/node_pkgs/linux/${{ matrix.arch }}/
          retention-days: 7

  package-darwin:
    needs: [prepare, build]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-darwin-universal
          path: tmp/node_pkgs/

      - uses: actions/upload-artifact@v4
        with:
          name: packages-darwin-universal
          path: tmp/node_pkgs/darwin/universal/
          retention-days: 7

  finalize:
    needs: [prepare, package-linux, package-darwin]
    runs-on: ubuntu-24.04
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/download-artifact@v4
        with:
          pattern: packages-*
          path: packages/
          merge-multiple: true

      - name: Generate checksums
        run: |
          cd packages
          for dir in linux/amd64 linux/arm64 darwin/universal; do
            if [ -d "$dir" ]; then
              pushd "$dir"
              sha256sum *.tar.gz *.deb *.rpm 2>/dev/null > \
                "hashes_nightly_${dir//\//_}_${{ needs.prepare.outputs.version }}" || true
              popd
            fi
          done

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: spdx-json
          output-file: packages/sbom.spdx.json

      - name: Attest build provenance
        uses: actions/attest-build-provenance@v2
        with:
          subject-path: 'packages/**/*.tar.gz'

      - uses: actions/upload-artifact@v4
        with:
          name: release-artifacts
          path: packages/
          retention-days: 7

  publish-github:
    needs: [prepare, finalize]
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: release-artifacts
          path: packages/

      - uses: softprops/action-gh-release@v2
        with:
          tag_name: nightly
          name: Nightly Build ${{ needs.prepare.outputs.version }}
          prerelease: true
          make_latest: false
          body: |
            ## Nightly Build

            **Version**: ${{ needs.prepare.outputs.version }}
            **Commit**: ${{ github.sha }}

            Automated nightly build from master. For testing only.
          files: |
            packages/**/*.tar.gz
            packages/**/*.deb
            packages/**/*.rpm
            packages/**/hashes_*
            packages/sbom.spdx.json

  publish-s3:
    needs: [prepare, finalize]
    runs-on: ubuntu-24.04
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-nightly
          aws-region: us-east-1

      - uses: actions/download-artifact@v4
        with:
          name: release-artifacts
          path: packages/

      - name: Upload to S3
        run: |
          # Upload versioned
          aws s3 cp packages/ \
            s3://${{ vars.S3_BUCKET }}/nightly/${{ needs.prepare.outputs.version }}/ \
            --recursive

          # Update latest
          aws s3 sync packages/ \
            s3://${{ vars.S3_BUCKET }}/nightly/latest/ \
            --delete
```

## Retention and Cleanup

Nightly builds should have shorter retention:
- GitHub Artifacts: 7 days
- GitHub Releases: Keep only latest nightly tag
- S3: Keep versioned builds for 30 days, prune with lifecycle rules

## Failure Notifications

Add Slack notification on failure:

```yaml
  notify-failure:
    needs: [build, package-linux, package-darwin, finalize, publish-github]
    if: failure()
    runs-on: ubuntu-24.04
    steps:
      - uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "Nightly build failed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Nightly Build Failed*\n<${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Run>"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```
