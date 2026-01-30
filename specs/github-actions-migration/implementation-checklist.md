# Implementation Checklist

## Phase 1: Build Workflow Foundation

### Setup
- [ ] Create `.github/workflows/release.yml` skeleton
- [ ] Create `.github/actions/setup-build/action.yml` composite action
- [ ] Test workflow triggers (tag push, workflow_dispatch)

### Prepare Job
- [ ] Implement version parsing from tags (`v4.5.0-beta` → `4.5.0`, `beta`)
- [ ] Implement channel-to-network mapping
- [ ] Set up job outputs for downstream jobs
- [ ] Test with manual dispatch inputs

### Build Jobs
- [ ] Linux amd64 build on `ubuntu-24.04`
  - [ ] Setup Go
  - [ ] Build libsodium
  - [ ] Run `make ci-build`
  - [ ] Upload artifacts
- [ ] Linux arm64 build on `ubuntu-24.04-arm`
  - [ ] Verify native ARM runner works
  - [ ] Same steps as amd64
- [ ] macOS universal build on `macos-14`
  - [ ] Verify M1 runner works
  - [ ] Run `make ci-build-universal`
  - [ ] Verify lipo produces universal binary

### Validation
- [ ] Compare build artifacts with Jenkins-produced artifacts
- [ ] Verify binary functionality (basic smoke test)
- [ ] Document any differences found

---

## Phase 2: Packaging

### Linux Packaging
- [ ] Implement `package-linux` job
- [ ] .deb packaging
  - [ ] Run `package/deb/package.sh algorand`
  - [ ] Run `package/deb/package.sh algorand-devtools`
  - [ ] Verify package contents
  - [ ] Test installation on Ubuntu
- [ ] .rpm packaging
  - [ ] Set up CentOS container for rpmbuild
  - [ ] Run `package/rpm/package.sh algorand`
  - [ ] Run `package/rpm/package.sh algorand-devtools`
  - [ ] Verify package contents
  - [ ] Test installation on RHEL/Rocky

### Darwin Packaging
- [ ] Implement `package-darwin` job
- [ ] Verify tarball naming matches expected format
- [ ] Remove separate amd64/arm64 tarballs (only universal)

### Tarball Verification
- [ ] Verify `node_*` tarball contents
- [ ] Verify `install_*` tarball contents
- [ ] Verify `tools_*` tarball contents

---

## Phase 3: Signing and Attestation

### Checksums
- [ ] Implement checksum generation
- [ ] Match format of existing `hashes_*` files

### SBOM
- [ ] Add `anchore/sbom-action`
- [ ] Verify SBOM contains all Go dependencies
- [ ] Test SBOM validation

### Attestations
- [ ] Add `actions/attest-build-provenance`
- [ ] Add `actions/attest-sbom`
- [ ] Test verification with `gh attestation verify`

### Dependency Scanning
- [ ] Add `golang/govulncheck-action`
- [ ] Determine policy for vulnerability findings (fail build vs warn)

---

## Phase 4: Publishing

### GitHub Releases
- [ ] Implement `publish-github` job
- [ ] Create release with all artifacts
- [ ] Generate release notes template
- [ ] Test release creation

### S3 Publishing
- [ ] Set up AWS OIDC provider
- [ ] Create IAM role with S3 permissions
- [ ] Implement `publish-s3` job
- [ ] Test upload to staging bucket first
- [ ] Create `release` environment with approval requirement

---

## Phase 5: Nightly Workflow

### Workflow Setup
- [ ] Create `.github/workflows/nightly.yml`
- [ ] Implement cron trigger
- [ ] Implement datestamp version generation

### Version Management
- [ ] Implement base version detection from tags
- [ ] Test version format `4.5.202601301318`

### Nightly-Specific Behavior
- [ ] Create pre-release (not full release)
- [ ] Update `nightly` tag to latest
- [ ] Upload to `nightly/latest` on S3

### Notifications
- [ ] Add Slack notification on failure
- [ ] Test notification delivery

---

## Phase 6: Migration and Cutover

### Parallel Running
- [ ] Run both Jenkins and GitHub Actions for same releases
- [ ] Compare all artifacts for parity
- [ ] Document any differences
- [ ] Fix any discrepancies

### Documentation
- [ ] Update CLAUDE.md with new build commands
- [ ] Create release process documentation
- [ ] Document verification process for users

### Cutover
- [ ] Disable Jenkins pipeline
- [ ] Monitor first few GHA-only releases
- [ ] Archive mule configuration (keep for reference)

### Cleanup
- [ ] Remove mule.yaml (or move to archive)
- [ ] Update/remove references to Jenkins
- [ ] Clean up any unused scripts

---

## Deferred Items (Future Work)

- [ ] Apt repository updates
- [ ] Yum repository updates
- [ ] Docker image builds
- [ ] releases.algorand.com updates
- [ ] Reproducible builds investigation
- [ ] SLSA Level 3+ compliance

---

## Notes

### Blockers/Issues Discovered
<!-- Document any blockers or issues found during implementation -->

### Decisions Made
<!-- Document any decisions made during implementation -->

### Test Results
<!-- Document test results and comparisons -->
