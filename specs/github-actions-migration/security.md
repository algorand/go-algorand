# Specification: Security and Supply Chain

## Overview

This document details the security measures for the GitHub Actions release pipeline, including signing, attestation, and dependency management.

## Supply Chain Security Goals

1. **Provenance**: Cryptographic proof that artifacts were built from this repository
2. **Integrity**: Verification that artifacts haven't been tampered with
3. **Transparency**: Public audit log of all releases
4. **Reproducibility**: Ability to verify builds (future goal)
5. **Dependency Awareness**: SBOM for all releases

## GitHub Attestations

### What Are Attestations?

GitHub Attestations provide cryptographic proof about artifacts:
- **Build Provenance**: Which repository, commit, workflow, and runner built the artifact
- **SBOM**: What dependencies are included in the artifact

Attestations are signed using Sigstore and recorded in a transparency log.

### Enabling Attestations

Required permissions in workflow:
```yaml
permissions:
  id-token: write      # Required for Sigstore OIDC
  attestations: write  # Required to create attestations
```

### Creating Provenance Attestation

```yaml
- uses: actions/attest-build-provenance@v2
  with:
    subject-path: 'packages/**/*.tar.gz,packages/**/*.deb,packages/**/*.rpm'
```

This creates a SLSA provenance attestation containing:
- Repository and commit SHA
- Workflow file and job name
- Runner environment
- Build inputs

### Creating SBOM Attestation

```yaml
- uses: anchore/sbom-action@v0
  with:
    format: spdx-json
    output-file: sbom.spdx.json

- uses: actions/attest-sbom@v1
  with:
    subject-path: 'packages/**/*.tar.gz'
    sbom-path: 'sbom.spdx.json'
```

### Verifying Attestations

Users verify artifacts with:
```bash
gh attestation verify algorand_stable_linux-amd64_4.5.0.deb --owner algorand
```

Output:
```
Loaded digest sha256:abc123... for file algorand_stable_linux-amd64_4.5.0.deb
Loaded 2 attestations from GitHub API
✓ Verification succeeded!

Attestation #1:
  - Type: https://slsa.dev/provenance/v1
  - Issuer: https://token.actions.githubusercontent.com
  - Subject: algorand/go-algorand
  - Predicate: Built by GitHub Actions workflow

Attestation #2:
  - Type: https://spdx.dev/Document
  - Issuer: https://token.actions.githubusercontent.com
  - Subject: algorand/go-algorand
  - Predicate: SBOM
```

## SLSA Compliance

### SLSA Levels

| Level | Requirements | Status |
|-------|--------------|--------|
| SLSA 1 | Documentation of build process | ✅ Achieved |
| SLSA 2 | Hosted build service, signed provenance | ✅ Achieved with attestations |
| SLSA 3 | Hardened build environment, non-falsifiable provenance | 🔄 Partial |
| SLSA 4 | Two-party review, hermetic builds | ❌ Future goal |

### SLSA 2 Requirements Met

- **Hosted build platform**: GitHub Actions
- **Build as code**: Workflow defined in repository
- **Signed provenance**: Sigstore-signed attestations
- **Available provenance**: Attestations queryable via GitHub API

## Dependency Management

### Go Module Security

```yaml
- name: Run Govulncheck
  uses: golang/govulncheck-action@v1
  with:
    go-version-input: stable
```

Govulncheck scans for known vulnerabilities in Go dependencies.

### Container Scanning

For any container images used in the build:
```yaml
- name: Scan container
  uses: anchore/scan-action@v4
  with:
    image: centos:stream10
    fail-build: true
    severity-cutoff: critical
```

### SBOM Generation

SBOM generated using Syft:
```yaml
- uses: anchore/sbom-action@v0
  with:
    format: spdx-json
    output-file: sbom.spdx.json
```

The SBOM includes:
- All Go module dependencies
- Go version used
- Build metadata

## Credential Management

### No Static Credentials

The pipeline uses no long-lived credentials:

| Service | Authentication Method |
|---------|----------------------|
| GitHub | Automatic `GITHUB_TOKEN` |
| AWS S3 | OIDC federation |
| Sigstore | OIDC (GitHub identity) |

### AWS OIDC Setup

1. Create OIDC provider in AWS IAM:
   ```
   Provider URL: https://token.actions.githubusercontent.com
   Audience: sts.amazonaws.com
   ```

2. Create IAM role with trust policy:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
           },
           "StringLike": {
             "token.actions.githubusercontent.com:sub": "repo:algorand/go-algorand:*"
           }
         }
       }
     ]
   }
   ```

3. Attach policy for S3 access:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:PutObject",
           "s3:GetObject",
           "s3:ListBucket"
         ],
         "Resource": [
           "arn:aws:s3:::algorand-releases",
           "arn:aws:s3:::algorand-releases/*"
         ]
       }
     ]
   }
   ```

4. Use in workflow:
   ```yaml
   - uses: aws-actions/configure-aws-credentials@v4
     with:
       role-to-assume: arn:aws:iam::ACCOUNT:role/github-actions-release
       aws-region: us-east-1
   ```

## Workflow Security

### Permission Restrictions

Minimum required permissions per job:

```yaml
# Build jobs (no special permissions needed)
permissions:
  contents: read

# Finalize job (needs attestation)
permissions:
  contents: read
  id-token: write
  attestations: write

# Publish job (needs release creation and AWS)
permissions:
  contents: write
  id-token: write
```

### Environment Protection

For production publishing, use GitHub Environments:

```yaml
publish-s3:
  environment: release
  ...
```

Environment `release` configured with:
- Required reviewers for approval
- Deployment branches limited to tags
- Optional: wait timer

### Branch Protection

Recommended branch protection for `master`:
- Require pull request reviews
- Require status checks to pass
- Require signed commits (optional)
- Restrict who can push

### Tag Protection

Create tag protection rule for `v*`:
- Only maintainers can create version tags
- Prevents unauthorized releases

## Artifact Integrity

### Checksums

SHA256 checksums generated for all artifacts:
```bash
sha256sum *.tar.gz *.deb *.rpm > hashes_${CHANNEL}_${PLATFORM}_${VERSION}
```

### Verification Flow

Users should verify artifacts:
1. Download artifact and hash file
2. Verify checksum: `sha256sum -c hashes_*`
3. Verify attestation: `gh attestation verify <file> --owner algorand`

## Future Improvements

### Reproducible Builds

Goal: Same source produces bit-identical binaries.

Challenges:
- Build timestamps embedded in binaries
- Go compiler version differences
- libsodium compilation variations

### Two-Party Review

For SLSA 4 compliance:
- Require two approvers for release tags
- Automated verification that reviews occurred

### Hardware Security

Consider for future:
- HSM-backed signing keys
- AWS KMS for additional signing layer
- Yubikey for manual release approval

## Incident Response

### Compromised Release

If a malicious release is discovered:
1. Delete the GitHub release
2. Remove artifacts from S3
3. Revoke any signing credentials (if applicable)
4. Issue security advisory
5. Publish patched release

### Compromised Workflow

If workflow is compromised:
1. Disable the workflow
2. Revoke OIDC trust (AWS, Sigstore)
3. Audit recent releases
4. Review and fix workflow
5. Re-enable with additional protections
