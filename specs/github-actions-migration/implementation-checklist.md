# Implementation Checklist

## Phase 1: Build Workflow Foundation

### Setup
- [x] Create `.github/workflows/release.yml` skeleton
- [x] Create `.github/actions/setup-build/action.yml` composite action
- [x] Test workflow triggers (tag push, workflow_dispatch)

### Prepare Job
- [x] Implement version parsing from tags (`v4.5.0-beta` → `4.5.0`, `beta`)
- [x] Implement channel-to-network mapping
- [x] Set up job outputs for downstream jobs
- [ ] Test with manual dispatch inputs

### Build Jobs
- [x] Linux amd64 build on `ubuntu-24.04`
  - [x] Setup Go
  - [x] Build libsodium
  - [x] Run `make ci-build`
  - [x] Upload artifacts
- [x] Linux arm64 build on `ubuntu-24.04-arm`
  - [x] Verify native ARM runner works
  - [x] Same steps as amd64
- [x] macOS universal build on `macos-14`
  - [x] Verify M1 runner works
  - [x] Run `make ci-build-universal`
  - [ ] Verify lipo produces universal binary

### Validation
- [ ] Compare build artifacts with Jenkins-produced artifacts
- [ ] Verify binary functionality (basic smoke test)
- [ ] Document any differences found

---

## Phase 2: Packaging

### Linux Packaging (using nFPM)
- [x] Implement `package-linux` job
- [x] Create nFPM configuration files in `.github/packaging/`
  - [x] `algorand.nfpm.yaml` - main package config
  - [x] `algorand-devtools.nfpm.yaml` - devtools package config
- [x] .deb packaging
  - [x] Build with nFPM (single config for deb/rpm)
  - [x] Include unattended-upgrades config (deb only via `packager: deb`)
  - [x] Verify package contents
  - [x] Test installation on Ubuntu (container-based)
- [x] .rpm packaging
  - [x] Build with nFPM (same config as deb)
  - [x] Verify package contents
  - [x] Test installation on Fedora (container-based)
- [x] Create unified maintainer scripts in `.github/packaging/scripts/`
  - [x] `algorand-preinstall.sh` - user/group creation (rpm)
  - [x] `algorand-postinstall.sh` - systemd setup, permissions
  - [x] `algorand-preremove.sh` - service stop
  - [x] `algorand-postremove.sh` - systemd cleanup
- [x] Implement `test-packages` job
  - [x] Test deb on Ubuntu 24.04 container
  - [x] Test rpm on Fedora 40 container
  - [x] Verify binary installation and version output

### Darwin Packaging
- [x] Implement `package-darwin` job
- [x] Verify tarball naming matches expected format
- [x] Universal binary only (no separate amd64/arm64)

### Tarball Verification
- [x] Verify `node_*` tarball contents
- [x] Verify `install_*` tarball contents
- [x] Verify `tools_*` tarball contents

### Version Override Support
- [x] Add `VERSION` env var support in Makefile
- [x] Add `VersionMajorOverride` and `VersionMinorOverride` ldflags
- [x] Binary version now matches tag version (e.g., `v0.0.1-beta` → `0.0.1.beta`)

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
- nFPM `overrides.<packager>.contents` **replaces** the contents section, doesn't extend it
- Fedora minimal images don't include `which` command - use `command -v` instead
- Container tests without systemd require `--no-install-recommends` for apt to avoid systemd-resolved
- `adduser` not available in minimal containers - use `useradd/groupadd` instead

### Decisions Made
1. **nFPM over legacy scripts**: Chose nFPM for packaging instead of legacy shell scripts
   - Single YAML config produces both .deb and .rpm
   - Better maintainability and reproducibility
   - Industry standard tool (used by goreleaser)

2. **Unified maintainer scripts**: Single script detects deb vs rpm at runtime
   - Reduces duplication
   - Easier to maintain
   - Scripts in `.github/packaging/scripts/`

3. **Config location**: `.github/packaging/` instead of top-level `packaging/`
   - Keeps packaging config with CI/CD workflow
   - Doesn't pollute repository root

4. **Package naming**: `algorand` / `algorand-beta` for main, `algorand-devtools` / `algorand-devtools-beta` for devtools
   - Consistent with existing naming conventions

5. **VERSION env var**: Added support to override version at build time
   - `VERSION=x.y.z` sets Major.Minor.Patch via ldflags
   - Binary version now matches tag version
   - Old behavior preserved when VERSION not set

### Test Results
- Successfully tested with tag `v0.0.1-beta`
- deb packages install correctly on Ubuntu 24.04 (amd64, arm64)
- rpm packages install correctly on Fedora 40 (amd64, arm64)
- Binary reports correct version: `0.0.1.beta`
