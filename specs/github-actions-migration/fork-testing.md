# Fork Testing Guide

## Overview

The GitHub Actions workflows are designed to be testable from a fork before merging to the upstream `algorand/go-algorand` repository.

## Repository Configuration

### Fork Setup

Current fork: `onetechnical/go-algorand`
Upstream: `algorand/go-algorand`

### Environment Variables

The workflows use repository variables and secrets that need to be configured per-repository:

| Variable/Secret | Purpose | Fork Value | Upstream Value |
|-----------------|---------|------------|----------------|
| `vars.AWS_ACCOUNT_ID` | AWS account for OIDC | Your AWS account | Algorand AWS account |
| `vars.S3_BUCKET` | Artifact storage bucket | Your test bucket | `algorand-releases` |
| `secrets.SLACK_WEBHOOK` | Failure notifications | Optional | Algorand Slack |

### Configuring Your Fork

1. **GitHub Repository Settings → Variables and Secrets**

   Add repository variables:
   ```
   AWS_ACCOUNT_ID: <your-aws-account-id>
   S3_BUCKET: <your-test-bucket>
   ```

2. **AWS OIDC Setup** (if testing S3 publishing)

   Create OIDC provider in your AWS account:
   ```
   Provider URL: https://token.actions.githubusercontent.com
   Audience: sts.amazonaws.com
   ```

   Create IAM role with trust policy for your fork:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::YOUR_ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
           },
           "StringLike": {
             "token.actions.githubusercontent.com:sub": "repo:onetechnical/go-algorand:*"
           }
         }
       }
     ]
   }
   ```

3. **GitHub Environments** (optional)

   Create a `release` environment for S3 publishing approval:
   - Settings → Environments → New environment
   - Name: `release`
   - Add yourself as required reviewer (optional for testing)

## Testing Workflow

### Phase 1: Build Only (No AWS Required)

Test builds without S3 publishing:

1. Push branch to your fork
2. Create a test tag:
   ```bash
   git tag v0.0.1-test-beta
   git push origin v0.0.1-test-beta
   ```
3. Or use workflow_dispatch from GitHub UI

The build and package jobs will run; S3 publish will be skipped if not configured.

### Phase 2: Full Pipeline (AWS Required)

Test with S3 publishing:

1. Set up AWS OIDC (see above)
2. Create test S3 bucket
3. Configure repository variables
4. Run workflow

### Skipping S3 for Fork Testing

The workflow can conditionally skip S3 based on repository:

```yaml
publish-s3:
  # Only run on upstream repository, or when explicitly enabled
  if: github.repository == 'algorand/go-algorand' || vars.ENABLE_S3_PUBLISH == 'true'
```

Or use a simpler approach - the job will fail gracefully if AWS isn't configured.

## Comparing Artifacts

### Download and Compare

After a successful fork build:

1. Download artifacts from GitHub Actions run
2. Download corresponding artifacts from Jenkins (if available)
3. Compare:
   ```bash
   # Compare file lists
   diff <(tar -tzf fork-node.tar.gz | sort) <(tar -tzf jenkins-node.tar.gz | sort)

   # Compare binary sizes
   ls -la fork/*.deb jenkins/*.deb

   # Compare package contents
   dpkg-deb -c fork/algorand_*.deb > fork-contents.txt
   dpkg-deb -c jenkins/algorand_*.deb > jenkins-contents.txt
   diff fork-contents.txt jenkins-contents.txt
   ```

### Functional Testing

Test packages on a VM:
```bash
# Ubuntu
sudo dpkg -i algorand_*.deb
sudo systemctl start algorand
goal node status

# macOS
tar -xzf node_*.tar.gz
./bin/goal node start -d data
./bin/goal node status -d data
```

## GitHub Release Testing

Fork releases go to your fork's releases page:
```
https://github.com/onetechnical/go-algorand/releases
```

These won't affect the upstream releases.

## Attestation Testing

Attestations work on forks but are scoped to your repository:
```bash
# Verify from fork
gh attestation verify artifact.tar.gz --owner onetechnical

# This won't work until merged upstream
gh attestation verify artifact.tar.gz --owner algorand
```

## Merging to Upstream

When ready to merge:

1. Create PR from fork to upstream
2. Ensure workflow files don't have fork-specific hardcoding
3. After merge, upstream maintainers configure:
   - AWS OIDC role trust policy for `algorand/go-algorand`
   - Repository variables/secrets
   - Environment protection rules

## Workflow Portability Checklist

Before merging, verify workflows are portable:

- [ ] No hardcoded repository names (use `${{ github.repository }}`)
- [ ] No hardcoded AWS account IDs (use `${{ vars.AWS_ACCOUNT_ID }}`)
- [ ] No hardcoded S3 buckets (use `${{ vars.S3_BUCKET }}`)
- [ ] Attestation verification docs reference `--owner algorand`
- [ ] Conditional jobs for optional integrations (S3, Slack)
