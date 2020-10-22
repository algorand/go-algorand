#!/usr/bin/env bash
# shellcheck disable=2038,2064

# build_deb.sh - Build a .deb package for one platform.
#
# Syntax:   build_deb.sh <arch> <output directory> <channel>
#
# Examples: scripts/build_deb.sh amd64

set -e
if [ "$#" -lt 2 ]; then
    echo "Syntax: build_deb.sh <arch> <output directory> <channel>"
    exit 1
fi

## Need to run inside fakeroot to make sure the files in
## the Debian package are owned by root.
if [ "$EUID" != "0" ]; then
    exec fakeroot "$0" "$@"
fi

OS=linux
ARCH="$1"
OUTDIR="$2"
CHANNEL=${CHANNEL:-$3}
PKG_NAME=$(./scripts/compute_package_name.sh "${CHANNEL:-stable}")

GOPATH=$(go env GOPATH)
export GOPATH
REPO_DIR=$(pwd)

echo "Building debian package for '${OS} - ${ARCH}'"

if [ -z "${NO_BUILD}" ]; then
    env GOOS="${OS}" GOARCH="${ARCH}" scripts/build_prod.sh
else
    echo "already built"
    true
fi

VER=$(./scripts/compute_build_number.sh -f)

if [ "${DEFAULTNETWORK}" = "" ]; then
    DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
fi
DEFAULT_RELEASE_NETWORK=$(./scripts/compute_branch_release_network.sh "${DEFAULTNETWORK}")

PKG_ROOT=$(mktemp -d)
trap "rm -rf $PKG_ROOT" 0

mkdir -p "${PKG_ROOT}/usr/bin"

if [ "${VARIATION}" = "" ]; then
    # NOTE: keep in sync with installer/rpm/algorand.spec
    bin_files=("algocfg" "algod" "algoh" "algokey" "carpenter" "catchupsrv" "ddconfig.sh" "diagcfg" "goal" "kmd" "msgpacktool" "node_exporter" "tealcut" "tealdbg")
fi

for bin in "${bin_files[@]}"; do
    cp "${GOPATH}/bin/${bin}" "${PKG_ROOT}"/usr/bin
    chmod 755 "${PKG_ROOT}/usr/bin/${bin}"
done

mkdir -p "${PKG_ROOT}/usr/lib/algorand"
lib_files=("updater" "find-nodes.sh")
for lib in "${lib_files[@]}"; do
    cp "${GOPATH}/bin/${lib}" "${PKG_ROOT}/usr/lib/algorand"
    chmod g-w "${PKG_ROOT}/usr/lib/algorand/${lib}"
done

data_files=("config.json.example" "system.json")
mkdir -p "${PKG_ROOT}/var/lib/algorand"
for data in "${data_files[@]}"; do
    cp "installer/${data}" "${PKG_ROOT}/var/lib/algorand"
done

if [ ! -z "${RELEASE_GENESIS_PROCESS}" ]; then
    genesis_dirs=("devnet" "testnet" "mainnet" "betanet")
    for dir in "${genesis_dirs[@]}"; do
        mkdir -p "${PKG_ROOT}/var/lib/algorand/genesis/${dir}"
        cp "${REPO_DIR}/installer/genesis/${dir}/genesis.json" "${PKG_ROOT}/var/lib/algorand/genesis/${dir}/genesis.json"
        #${GOPATH}/bin/buildtools genesis ensure -n ${dir} --source ${REPO_DIR}/gen/${dir}/genesis.json --target ${PKG_ROOT}/var/lib/algorand/genesis/${dir}/genesis.json --releasedir ${REPO_DIR}/installer/genesis
    done
    # Copy the appropriate network genesis.json for our default (in root ./genesis folder)
    cp "${PKG_ROOT}/var/lib/algorand/genesis/${DEFAULT_RELEASE_NETWORK}/genesis.json" "${PKG_ROOT}/var/lib/algorand"
elif [[ "${CHANNEL}" == "dev" || "${CHANNEL}" == "stable" || "${CHANNEL}" == "nightly" || "${CHANNEL}" == "beta" ]]; then
    cp "${REPO_DIR}/installer/genesis/${DEFAULTNETWORK}/genesis.json" "${PKG_ROOT}/var/lib/algorand/genesis.json"
    #${GOPATH}/bin/buildtools genesis ensure -n ${DEFAULTNETWORK} --source ${REPO_DIR}/gen/${DEFAULTNETWORK}/genesis.json --target ${PKG_ROOT}/var/lib/algorand/genesis.json --releasedir ${REPO_DIR}/installer/genesis
else
    cp "${REPO_DIR}/installer/genesis/${DEFAULTNETWORK}/genesis.json" "${PKG_ROOT}/var/lib/algorand"
    # Disabled because we have static genesis files now
    #cp gen/${DEFAULTNETWORK}/genesis.json ${PKG_ROOT}/var/lib/algorand
    #if [ -z "${TIMESTAMP}" ]; then
    #  TIMESTAMP=$(date +%s)
    #fi
    #${GOPATH}/bin/buildtools genesis timestamp -f ${PKG_ROOT}/var/lib/algorand/genesis.json -t ${TIMESTAMP}
fi

systemd_files=("algorand.service" "algorand@.service")
mkdir -p "${PKG_ROOT}/lib/systemd/system"
for svc in "${systemd_files[@]}"; do
    cp "installer/${svc}" "${PKG_ROOT}/lib/systemd/system"
    chmod 644 "${PKG_ROOT}/lib/systemd/system/${svc}"
done

unattended_upgrades_files=("51algorand-upgrades")
mkdir -p "${PKG_ROOT}/etc/apt/apt.conf.d"
for f in "${unattended_upgrades_files[@]}"; do
    < "installer/${f}" \
      sed -e "s,@CHANNEL@,${CHANNEL}," \
      > "${PKG_ROOT}/etc/apt/apt.conf.d/${f}"
done

# files should not be group writable but directories should be
chmod -R g-w "${PKG_ROOT}/var/lib/algorand"
find "${PKG_ROOT}/var/lib/algorand" -type d | xargs chmod g+w

mkdir -p "${PKG_ROOT}/DEBIAN"
debian_files=("control" "preinst" "postinst" "prerm" "postrm" "conffiles")
for ctl in "${debian_files[@]}"; do
    # Copy first, to preserve permissions, then overwrite to fill in template.
    cp -a "installer/debian/algorand/${ctl}" "${PKG_ROOT}/DEBIAN/${ctl}"
    < "installer/debian/algorand/${ctl}" \
      sed -e "s,@ARCH@,${ARCH}," \
          -e "s,@VER@,${VER}," \
          -e "s,@PKG_NAME@,${PKG_NAME}," \
      > "${PKG_ROOT}/DEBIAN/${ctl}"
done
# TODO: make `Files:` segments for vendor/... and crypto/libsodium-fork, but reasonably this should be understood to cover all _our_ files and copied in packages continue to be licenced under their own terms
cat <<EOF> "${PKG_ROOT}/DEBIAN/copyright"
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Algorand
Upstream-Contact: Algorand developers <dev@algorand.com>
Source: https://github.com/algorand/go-algorand

Files: *
Copyright: Algorand developers <dev@algorand.com>
License: AGPL-3+
EOF
sed 's/^$/./g' < COPYING | sed 's/^/ /g' >> "${PKG_ROOT}/DEBIAN/copyright"
mkdir -p "${PKG_ROOT}/usr/share/doc/algorand"
cp -p "${PKG_ROOT}/DEBIAN/copyright" "${PKG_ROOT}/usr/share/doc/algorand/copyright"

OUTPUT="$OUTDIR/algorand_${VER}_${ARCH}.deb"
dpkg-deb --build "${PKG_ROOT}" "${OUTPUT}"

