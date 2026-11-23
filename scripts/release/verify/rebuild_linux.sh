#!/usr/bin/env bash
# rebuild_linux.sh - Rebuild a release's Linux packages in Docker, from the
# toolchain its build environment attestation records, and check them against
# the released files and their provenance.
#
# Syntax:   rebuild_linux.sh <amd64|arm64> <tag> <run-id|release-files-dir> [owner/repo]
#
#           <run-id> is the release workflow run that built <tag>; its
#           packages-linux-<arch> artifact is downloaded. Otherwise give a
#           directory holding the released files for this platform and their
#           build-environment_<channel>_linux-<arch>_<version>.json.
#           [owner/repo] defaults to algorand/go-algorand.
#
# Needs docker (able to run linux/<arch> images, natively or emulated), gh
# (logged in), git, jq, curl and sha256sum or shasum. Works in
# ./rebuild-<tag>-linux-<arch>, which it creates. Exits non-zero if any file
# differs or fails provenance verification.

set -euo pipefail

ARCH=${1:?amd64 or arm64}; TAG=${2:?tag}; SOURCE=${3:?run id or release files directory}; REPO=${4:-algorand/go-algorand}
case "${ARCH}" in amd64) RPM_ARCH=x86_64 ;; arm64) RPM_ARCH=aarch64 ;; *) echo "arch must be amd64 or arm64" >&2; exit 1 ;; esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

VERSION=${TAG#v}; CHANNEL=${VERSION##*-}; VERSION=${VERSION%-*}
case "${CHANNEL}" in beta) NETWORK=betanet ;; stable) NETWORK=mainnet ;; nightly|dev) NETWORK=devnet ;; *) echo "unexpected tag ${TAG}" >&2; exit 1 ;; esac
W=$(pwd)/rebuild-${TAG}-linux-${ARCH}
mkdir -p "${W}/out" "${W}/steps"
echo "Rebuilding ${TAG} (${VERSION}, ${CHANNEL}) for linux-${ARCH} in ${W}"

# The release files and attested build record: either downloaded from a
# workflow run (whose artifacts expire after a few days) or already on disk.
if [[ "${SOURCE}" =~ ^[0-9]+$ ]]; then
    run_tag=$(gh run view "${SOURCE}" -R "${REPO}" --json headBranch -q .headBranch)
    [ "${run_tag}" = "${TAG}" ] || { echo "run ${SOURCE} built ${run_tag}, not ${TAG}" >&2; exit 1; }
    CI=${W}/ci
    [ -n "$(ls "${CI}" 2>/dev/null)" ] || gh run download "${SOURCE}" -R "${REPO}" -n "packages-linux-${ARCH}" -D "${CI}"
else
    CI=$(cd "${SOURCE}" && pwd)
fi
REC=$(ls "${CI}"/build-environment_*_linux-"${ARCH}"_*.json)
IMAGE=$(jq -r .build.runner.container_image "${REC}")
GOVERSION=$(jq -r .build.go.GOVERSION "${REC}")
GOMODCACHE=$(jq -r .build.go.GOMODCACHE "${REC}")
NFPM_VERSION=$(jq -r '.packaging.nfpm.buildinfo' "${REC}" | awk '$1=="mod" && $2=="github.com/goreleaser/nfpm/v2" {print $3}')
echo "Recorded: image ${IMAGE}, ${GOVERSION}, GOMODCACHE ${GOMODCACHE}, nfpm ${NFPM_VERSION}"
echo "Recorded apt sources: $(jq -r '.build.runner.apt_sources | join(" ")' "${REC}")"

# 2. The source at the tag, and the workflow steps that matter, taken from
# release.yml at that tag rather than retyped.
[ -d "${W}/repo.git" ] || git clone -q --bare "https://github.com/${REPO}.git" "${W}/repo.git"
git -C "${W}/repo.git" show "${TAG}:.github/workflows/release.yml" > "${W}/release.yml"
UBUNTU_SNAPSHOT=$(awk '/^  UBUNTU_SNAPSHOT:/ {print $2}' "${W}/release.yml")
# Prints a step's `run: |` block with its YAML indentation removed.
extract_step() {
    awk -v name="- name: $1" '
        index($0, name) { found = 1; next }
        found && /^ *run: \|/ { inrun = 1; next }
        inrun { if ($0 !~ /^          / && $0 !~ /^$/) exit; sub(/^          /, ""); print }' "${W}/release.yml"
}
for s in "Install pinned Linux toolchain" "Generate Debian copyright file" "Generate unattended-upgrades config"; do
    f="${W}/steps/$(echo "$s" | tr ' A-Z-' '_a-z_').sh"
    { echo "set -eo pipefail"; extract_step "$s"; } > "$f"
    [ "$(wc -l < "$f")" -gt 2 ] || { echo "could not extract step: $s" >&2; exit 1; }
done
grep -q "snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/" <(jq -r '.build.runner.apt_sources[]' "${REC}") ||
    { echo "release.yml snapshot ${UBUNTU_SNAPSHOT} does not match the record" >&2; exit 1; }

# 3. Go, checked against go.dev's published hash.
GO_TGZ=${GOVERSION}.linux-${ARCH}.tar.gz
if [ ! -f "${W}/${GO_TGZ}" ]; then
    curl -sfL -o "${W}/${GO_TGZ}" "https://go.dev/dl/${GO_TGZ}"
fi
want=$(curl -sfL 'https://go.dev/dl/?mode=json&include=all' | jq -r --arg f "${GO_TGZ}" '.[].files[] | select(.filename == $f) | .sha256')
[ "$(sha256 "${W}/${GO_TGZ}" | cut -d' ' -f1)" = "${want}" ] || { echo "Go tarball hash mismatch" >&2; exit 1; }

# The base image has no CA certificates; lend it the host's bundle.
for c in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do [ -f "$c" ] && { cp "$c" "${W}/ca.crt"; break; }; done

cat > "${W}/inside.sh" <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive UBUNTU_SNAPSHOT=${UBUNTU_SNAPSHOT} GITHUB_WORKSPACE=/rebuild/src
bash /w/steps/install_pinned_linux_toolchain.sh > /w/out/apt.log 2>&1
tar -C /usr/local -xzf /w/${GO_TGZ}
export PATH=/usr/local/go/bin:/root/go/bin:\$PATH
git config --global --add safe.directory /w/repo.git
git clone -q /w/repo.git /rebuild/src && cd /rebuild/src && git checkout -q ${TAG}
export CHANNEL=${CHANNEL} NETWORK=${NETWORK} VERSION=${VERSION} FULLVERSION=${VERSION} TRAVIS_BRANCH= BRANCH= \\
    ALGORAND_DEADLOCK=disable KMD_NOUSB=true BUILD_CONTAINER_IMAGE=${IMAGE} GOMODCACHE=${GOMODCACHE}
export SOURCE_DATE_EPOCH=\$(git log -1 --format=%ct)
make libsodium > /w/out/build.log 2>&1
make ci-build >> /w/out/build.log 2>&1
GOTOOLCHAIN=local go install github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION} >> /w/out/build.log 2>&1
export DEFAULTNETWORK=${NETWORK} GOARCH=${ARCH}
if [ "${CHANNEL}" = beta ]; then
    export PKG_NAME=algorand-beta DEVTOOLS_PKG_NAME=algorand-devtools-beta CONFLICTS_PKG_NAME=algorand CONFLICTS_DEVTOOLS_PKG_NAME=algorand-devtools
else
    export PKG_NAME=algorand DEVTOOLS_PKG_NAME=algorand-devtools CONFLICTS_PKG_NAME=algorand-beta CONFLICTS_DEVTOOLS_PKG_NAME=algorand-devtools-beta
fi
export BINDIR=\$(cd "\$(find tmp/node_pkgs -type d -name bin | head -1)" && pwd)
export TOOLSDIR=\$(cd "\$(find tmp/node_pkgs -type d -name tools | head -1)" && pwd)
bash /w/steps/generate_debian_copyright_file.sh
bash /w/steps/generate_unattended_upgrades_config.sh
mkdir -p dist
nfpm pkg -f .github/packaging/algorand.nfpm.yaml -p deb -t "dist/algorand_${CHANNEL}_linux-${ARCH}_${VERSION}.deb" >/dev/null
nfpm pkg -f .github/packaging/algorand-devtools.nfpm.yaml -p deb -t "dist/algorand-devtools_${CHANNEL}_linux-${ARCH}_${VERSION}.deb" >/dev/null
nfpm pkg -f .github/packaging/algorand.nfpm.yaml -p rpm -t "dist/\${PKG_NAME}-${VERSION}-1.${RPM_ARCH}.rpm" >/dev/null
nfpm pkg -f .github/packaging/algorand-devtools.nfpm.yaml -p rpm -t "dist/\${DEVTOOLS_PKG_NAME}-${VERSION}-1.${RPM_ARCH}.rpm" >/dev/null
find tmp/node_pkgs -name "*.tar.gz" -exec cp {} dist/ \\;
cp dist/* /w/out/
EOF

# 4. Build in the recorded image, for the target architecture. The record
# pins a multi-arch index; Docker Engine's image store holds only one platform
# per digest, so run the architecture's own manifest, which the index lists.
ARCH_DIGEST=$(docker manifest inspect "${IMAGE}" |
    jq -r --arg a "${ARCH}" '.manifests[] | select(.platform.os == "linux" and .platform.architecture == $a) | .digest' | head -1)
[ -n "${ARCH_DIGEST}" ] || { echo "no linux/${ARCH} manifest in ${IMAGE}" >&2; exit 1; }
RUN_IMAGE=${IMAGE%@*}@${ARCH_DIGEST}
echo "Building in ${RUN_IMAGE} (linux/${ARCH}, from ${IMAGE}); logs in ${W}/out"
docker run --rm --platform "linux/${ARCH}" \
    -v "${W}:/w" -v "${W}/ca.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
    "${RUN_IMAGE}" bash /w/inside.sh

# 5. Compare with the released files for this platform, then check the local
# files against the release's signed provenance.
echo "--- local rebuild vs ${CI}:"
fail=0
for f in $(cd "${CI}" && ls ./*_linux-"${ARCH}"_*.tar.gz ./*_linux-"${ARCH}"_*.deb ./*."${RPM_ARCH}".rpm | sed 's|^\./||'); do
    if [ "$(sha256 "${CI}/$f" | cut -d' ' -f1)" = "$(sha256 "${W}/out/$f" 2>/dev/null | cut -d' ' -f1)" ]; then
        echo "SAME $f"
    else
        echo "DIFF $f"; fail=1
    fi
done
for f in $(cd "${W}/out" && ls *.tar.gz *.deb *.rpm); do
    if gh attestation verify "${W}/out/$f" -R "${REPO}" --signer-workflow "${REPO}/.github/workflows/release.yml" >/dev/null 2>&1; then
        echo "provenance verifies: $f"
    else
        echo "provenance FAILS: $f"; fail=1
    fi
done
exit "${fail}"
