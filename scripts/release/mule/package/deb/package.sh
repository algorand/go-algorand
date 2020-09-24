#!/usr/bin/env bash
# shellcheck disable=2038,2045,2064

set -ex

echo
date "+build_release begin PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

ARCH=$(./scripts/archtype.sh)
OS_TYPE=$(./scripts/ostype.sh)
BRANCH=${BRANCH:-$(./scripts/compute_branch.sh "$BRANCH")}
CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
OUTDIR="./tmp/node_pkgs/$OS_TYPE/$ARCH"
mkdir -p "$OUTDIR/bin"
ALGO_BIN="./tmp/node_pkgs/$OS_TYPE/$ARCH/$CHANNEL/$OS_TYPE-$ARCH/bin"
VER=${VERSION:-$(./scripts/compute_build_number.sh -f)}
# A make target in Makefile.mule may pass the name as an argument.
ALGORAND_PACKAGE_NAME=${1:-$(./scripts/compute_package_name.sh "$CHANNEL")}

echo "Building debian package for '${OS} - ${ARCH}'"

DEFAULTNETWORK=$("./scripts/compute_branch_network.sh")
DEFAULT_RELEASE_NETWORK=$("./scripts/compute_branch_release_network.sh" "${DEFAULTNETWORK}")
export DEFAULT_RELEASE_NETWORK

PKG_ROOT=$(mktemp -d)
trap "rm -rf $PKG_ROOT" 0

mkdir -p "${PKG_ROOT}/usr/bin"

# NOTE: keep in sync with `./installer/rpm/algorand.spec`.
if [[ "$ALGORAND_PACKAGE_NAME" =~ devtools ]]; then
    BIN_FILES=("carpenter" "catchupsrv" "msgpacktool" "tealcut" "tealdbg")
    UNATTENDED_UPGRADES_FILE="53algorand-devtools-upgrades"
    OUTPUT_DEB="$OUTDIR/algorand-devtools_${CHANNEL}_${OS_TYPE}-${ARCH}_${VER}.deb"
    REQUIRED_ALGORAND_PKG=$("./scripts/compute_package_name.sh" "$CHANNEL")
else
    BIN_FILES=("algocfg" "algod" "algoh" "algokey" "ddconfig.sh" "diagcfg" "goal" "kmd" "node_exporter")
    UNATTENDED_UPGRADES_FILE="51algorand-upgrades"
    OUTPUT_DEB="$OUTDIR/algorand_${CHANNEL}_${OS_TYPE}-${ARCH}_${VER}.deb"
fi

for binary in "${BIN_FILES[@]}"; do
    cp "${ALGO_BIN}/${binary}" "${PKG_ROOT}"/usr/bin
    chmod 755 "${PKG_ROOT}/usr/bin/${binary}"
done

if [[ ! "$ALGORAND_PACKAGE_NAME" =~ devtools ]]; then
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

    genesis_dirs=("devnet" "testnet" "mainnet" "betanet")
    for dir in "${genesis_dirs[@]}"; do
        mkdir -p "${PKG_ROOT}/var/lib/algorand/genesis/${dir}"
        cp "./installer/genesis/${dir}/genesis.json" "${PKG_ROOT}/var/lib/algorand/genesis/${dir}/genesis.json"
    done
    cp "./installer/genesis/${DEFAULT_RELEASE_NETWORK}/genesis.json" "${PKG_ROOT}/var/lib/algorand/genesis.json"

    # files should not be group writable but directories should be
    chmod -R g-w "${PKG_ROOT}/var/lib/algorand"
    find "${PKG_ROOT}/var/lib/algorand" -type d | xargs chmod g+w

    SYSTEMD_FILES=("algorand.service" "algorand@.service")
    mkdir -p "${PKG_ROOT}/lib/systemd/system"
    for svc in "${SYSTEMD_FILES[@]}"; do
        cp "installer/${svc}" "${PKG_ROOT}/lib/systemd/system"
        chmod 644 "${PKG_ROOT}/lib/systemd/system/${svc}"
    done
fi

mkdir -p "${PKG_ROOT}/etc/apt/apt.conf.d"
cat <<EOF> "${PKG_ROOT}/etc/apt/apt.conf.d/${UNATTENDED_UPGRADES_FILE}"
## This file is provided by the Algorand package to configure
## unattended upgrades for the Algorand node software.

Unattended-Upgrade::Allowed-Origins {
  "Algorand:${CHANNEL}";
};

Dpkg::Options {
   "--force-confdef";
   "--force-confold";
};
EOF

mkdir -p "${PKG_ROOT}/DEBIAN"
if [[ "$ALGORAND_PACKAGE_NAME" =~ devtools ]]; then
    INSTALLER_DIR="algorand-devtools"
else
    INSTALLER_DIR=algorand
fi
# Can contain `control`, `preinst`, `postinst`, `prerm`, `postrm`, `conffiles`.
CTL_FILES_DIR="installer/debian/${INSTALLER_DIR}"
for ctl_file in $(ls "${CTL_FILES_DIR}"); do
    # Copy first, to preserve permissions, then overwrite to fill in template.
    cp -a "${CTL_FILES_DIR}/${ctl_file}" "${PKG_ROOT}/DEBIAN/${ctl_file}"
    < "${CTL_FILES_DIR}/${ctl_file}" \
      sed -e "s,@ARCH@,${ARCH}," \
          -e "s,@VER@,${VER}," \
          -e "s,@PKG_NAME@,$ALGORAND_PACKAGE_NAME," \
          -e "s,@REQUIRED_ALGORAND_PKG@,$REQUIRED_ALGORAND_PKG," \
      > "${PKG_ROOT}/DEBIAN/${ctl_file}"
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
mkdir -p "${PKG_ROOT}/usr/share/doc/${ALGORAND_PACKAGE_NAME}"
cp -p "${PKG_ROOT}/DEBIAN/copyright" "${PKG_ROOT}/usr/share/doc/${ALGORAND_PACKAGE_NAME}/copyright"

dpkg-deb --build "${PKG_ROOT}" "${OUTPUT_DEB}"

echo
date "+build_release end PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

