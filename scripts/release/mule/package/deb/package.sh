#!/usr/bin/env bash
# shellcheck disable=2038,2064

set -ex

echo
date "+build_release begin PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

OS_TYPE="$1"
ARCH="$2"
WORKDIR="$3"

if [ -z "$OS_TYPE" ] || [ -z "$ARCH" ] || [ -z "$WORKDIR" ]; then
    echo OS, ARCH and WORKDIR variables must be defined.
    exit 1
fi

BRANCH=${BRANCH:-$("$WORKDIR/scripts/compute_branch.sh" "$BRANCH")}
CHANNEL=${CHANNEL:-$("$WORKDIR/scripts/compute_branch_channel.sh" "$BRANCH")}
BASE="$WORKDIR/tmp/node_pkgs/$OS_TYPE/$ARCH"
mkdir -p "$BASE/$CHANNEL/$OS_TYPE-$ARCH/bin"
ALGO_BIN="$BASE/$CHANNEL/$OS_TYPE-$ARCH/bin"
OUTDIR="$BASE"
PKG_NAME=$("$WORKDIR/scripts/compute_package_name.sh" "${CHANNEL:-stable}")
VER=${VERSION:-$("$WORKDIR/scripts/compute_build_number.sh" -f)}

echo "Building debian package for '${OS} - ${ARCH}'"

if [ "${DEFAULTNETWORK}" = "" ]; then
    DEFAULTNETWORK=$("$WORKDIR/scripts/compute_branch_network.sh")
fi
DEFAULT_RELEASE_NETWORK=$("$WORKDIR/scripts/compute_branch_release_network.sh" "${DEFAULTNETWORK}")

PKG_ROOT=$(mktemp -d)
trap "rm -rf $PKG_ROOT" 0

mkdir -p "${PKG_ROOT}/usr/bin"

# NOTE: keep in sync with installer/rpm/algorand.spec
bin_files=("algocfg" "algod" "algoh" "algokey" "carpenter" "catchupsrv" "ddconfig.sh" "diagcfg" "goal" "kmd" "msgpacktool" "node_exporter")

for binary in "${bin_files[@]}"; do
    cp "${ALGO_BIN}/${binary}" "${PKG_ROOT}"/usr/bin
    chmod 755 "${PKG_ROOT}/usr/bin/${binary}"
done

mkdir -p "${PKG_ROOT}/usr/lib/algorand"
lib_files=("updater" "find-nodes.sh")
for lib in "${lib_files[@]}"; do
    cp "${ALGO_BIN}/${lib}" "${PKG_ROOT}/usr/lib/algorand"
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
        cp "${WORKDIR}/installer/genesis/${dir}/genesis.json" "${PKG_ROOT}/var/lib/algorand/genesis/${dir}/genesis.json"
    done
    # Copy the appropriate network genesis.json for our default (in root ./genesis folder)
    cp "${PKG_ROOT}/var/lib/algorand/genesis/${DEFAULT_RELEASE_NETWORK}/genesis.json" "${PKG_ROOT}/var/lib/algorand"
elif [[ "${CHANNEL}" == "dev" || "${CHANNEL}" == "stable" || "${CHANNEL}" == "nightly" || "${CHANNEL}" == "beta" ]]; then
    cp "${WORKDIR}/installer/genesis/${DEFAULTNETWORK}/genesis.json" "${PKG_ROOT}/var/lib/algorand/genesis.json"
else
    cp "${WORKDIR}/installer/genesis/${DEFAULTNETWORK}/genesis.json" "${PKG_ROOT}/var/lib/algorand"
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
    cp -a "installer/debian/${ctl}" "${PKG_ROOT}/DEBIAN/${ctl}"
    < "installer/debian/${ctl}" \
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

echo
date "+build_release end PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

