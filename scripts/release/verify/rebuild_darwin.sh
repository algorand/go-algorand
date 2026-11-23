#!/usr/bin/env bash
# rebuild_darwin.sh - Rebuild a release's macOS universal tarballs on a Mac,
# from the toolchain its build environment attestation records, and check
# them against the released files and their provenance.
#
# Syntax:   rebuild_darwin.sh <tag> <run-id|release-files-dir> [owner/repo]
#
#           <run-id> is the release workflow run that built <tag>; its
#           packages-darwin-universal artifact is downloaded. Otherwise give a
#           directory holding the released darwin-universal tarballs and their
#           build-environment_<channel>_darwin-universal_<version>.json.
#           [owner/repo] defaults to algorand/go-algorand.
#
# Needs the Xcode and SDK the release recorded (set XCODE_APP if it is not at
# /Applications/Xcode_<version>.app), Homebrew autoconf, automake, libtool and
# gnu-tar, plus gh (logged in), git, jq and curl. Works in
# ./rebuild-<tag>-darwin-universal, which it creates; the module cache goes to
# the recorded GOMODCACHE path. Exits non-zero if any file differs or fails
# provenance verification.

set -euo pipefail

TAG=${1:?tag}; SOURCE=${2:?run id or release files directory}; REPO=${3:-algorand/go-algorand}

VERSION=${TAG#v}; CHANNEL=${VERSION##*-}; VERSION=${VERSION%-*}
case "${CHANNEL}" in beta) NETWORK=betanet ;; stable) NETWORK=mainnet ;; nightly|dev) NETWORK=devnet ;; *) echo "unexpected tag ${TAG}" >&2; exit 1 ;; esac
W=$(pwd)/rebuild-${TAG}-darwin-universal
mkdir -p "${W}"
echo "Rebuilding ${TAG} (${VERSION}, ${CHANNEL}) for darwin-universal in ${W}"

# The release files and attested build record: either downloaded from a
# workflow run (whose artifacts expire after a few days) or already on disk.
if [[ "${SOURCE}" =~ ^[0-9]+$ ]]; then
    run_tag=$(gh run view "${SOURCE}" -R "${REPO}" --json headBranch -q .headBranch)
    [ "${run_tag}" = "${TAG}" ] || { echo "run ${SOURCE} built ${run_tag}, not ${TAG}" >&2; exit 1; }
    CI=${W}/ci
    [ -n "$(ls "${CI}" 2>/dev/null)" ] || gh run download "${SOURCE}" -R "${REPO}" -n "packages-darwin-universal" -D "${CI}"
else
    CI=$(cd "${SOURCE}" && pwd)
fi
REC=$(ls "${CI}"/build-environment_*_darwin-universal_*.json)
rec() { jq -r ".build.$1" "${REC}"; }

# 2. Xcode and its SDK produce the compiler, linker and lipo output, so they
# must match the record exactly.
XCODE_VERSION=$(rec xcode | awk '{print $2}')
XCODE_APP=${XCODE_APP:-/Applications/Xcode_${XCODE_VERSION}.app}
export DEVELOPER_DIR=${XCODE_APP}/Contents/Developer
check() {
    if [ "$2" = "$3" ]; then echo "ok   $1: $2"; else echo "FAIL $1: have '$2', record says '$3'" >&2; return 1; fi
}
check Xcode "$(xcodebuild -version | tr '\n' ' ' | sed 's/ *$//')" "$(rec xcode)"
check "SDK version" "$(xcrun --show-sdk-version)" "$(rec sdk_version)"
check "SDK build" "$(xcrun --show-sdk-build-version)" "$(rec sdk_build)"
check compiler "$(clang --version | head -1)" "$(rec compiler)"

# Homebrew installs whatever is current, so these may not be matchable; a
# mismatch is reported but the build goes ahead.
have_brew=$(brew list --versions autoconf automake libtool gnu-tar 2>/dev/null | sort)
want_brew=$(jq -r '.build.homebrew[]' "${REC}" | sort)
if [ "${have_brew}" = "${want_brew}" ]; then
    echo "ok   Homebrew tools: $(echo "${have_brew}" | tr '\n' ',' | sed 's/,$//')"
else
    echo "WARN Homebrew tools differ from the record (libsodium's autogen.sh uses them):"
    diff <(echo "${want_brew}") <(echo "${have_brew}") | sed 's/^/     /' || true
fi
BREW_PREFIX=$(brew --prefix)
export PATH="${BREW_PREFIX}/bin:${PATH}"

# 3. Go, checked against go.dev's published hash.
GOVERSION=$(rec go.GOVERSION)
case "$(uname -m)" in arm64) GOHOST=arm64 ;; *) GOHOST=amd64 ;; esac
GO_TGZ=${GOVERSION}.darwin-${GOHOST}.tar.gz
if [ ! -d "${W}/go" ]; then
    curl -sfL -o "${W}/${GO_TGZ}" "https://go.dev/dl/${GO_TGZ}"
    want=$(curl -sfL 'https://go.dev/dl/?mode=json&include=all' | jq -r --arg f "${GO_TGZ}" '.[].files[] | select(.filename == $f) | .sha256')
    [ "$(shasum -a 256 "${W}/${GO_TGZ}" | cut -d' ' -f1)" = "${want}" ] || { echo "Go tarball hash mismatch" >&2; exit 1; }
    tar -C "${W}" -xzf "${W}/${GO_TGZ}"
fi
export PATH="${W}/go/bin:${PATH}" GOTOOLCHAIN=local
check Go "$(go env GOVERSION)" "${GOVERSION}"

# 4. Build as the release workflow's darwin job does. GOBIN and GOCACHE are
# private to this rebuild: the Makefile's clean step runs `go clean -i`, which
# would otherwise remove binaries from the usual GOBIN.
[ -d "${W}/src" ] || git clone -q "https://github.com/${REPO}.git" "${W}/src"
cd "${W}/src"
git checkout -q "${TAG}"
GOMODCACHE=$(rec go.GOMODCACHE)
export CHANNEL NETWORK VERSION FULLVERSION=${VERSION} TRAVIS_BRANCH='' BRANCH='' \
    ALGORAND_DEADLOCK=disable KMD_NOUSB=true BUILD_CONTAINER_IMAGE='' \
    GOMODCACHE GOBIN=${W}/gobin GOCACHE=${W}/gocache
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct); export SOURCE_DATE_EPOCH
echo "Building; log in ${W}/build.log"
make ci-build-universal > "${W}/build.log" 2>&1

# 5. Compare with the released files for this platform, then check the local
# files against the release's signed provenance.
echo "--- local rebuild vs ${CI}:"
fail=0
for f in $(cd "${CI}" && ls ./*_darwin-universal_*.tar.gz | sed 's|^\./||'); do
    local_f=$(find tmp/node_pkgs -name "$f" | head -1)
    if [ -n "${local_f}" ] && [ "$(shasum -a 256 "${CI}/$f" | cut -d' ' -f1)" = "$(shasum -a 256 "${local_f}" | cut -d' ' -f1)" ]; then
        echo "SAME $f"
    else
        echo "DIFF $f"; fail=1
    fi
    if [ -n "${local_f}" ] && gh attestation verify "${local_f}" -R "${REPO}" --signer-workflow "${REPO}/.github/workflows/release.yml" >/dev/null 2>&1; then
        echo "provenance verifies: $f"
    else
        echo "provenance FAILS: $f"; fail=1
    fi
done
exit "${fail}"
