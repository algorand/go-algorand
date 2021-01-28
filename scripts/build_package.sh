#!/usr/bin/env bash

# build_package.sh - Builds packages for one or more platforms and creates .tar.gz archive to be used for auto-update.
#           Packages are assembled under $HOME/node_pkg.  This directory is deleted before starting.
#
# Syntax:   build_package.sh <os> <arch> <package_root_folder>
#
# Outputs:  'Building package for os-arch' and any errors
#
# ExitCode: 0 = Package built and deployment layout created under $HOME/node_pkg/<platform>
#
# Usage:    Generate production version of layout for deployment.
#           Currently used by build_packages.sh for each requested platform
#
# Examples: scripts/build_package.sh darwin amd64 $HOME/some_folder/for-mac
#
# Notes:    The specified package_root_folder must exist.

if [ ! "$#" -eq 3 ]; then
    echo "Syntax: build_package.sh <os> <arch> <package_root_folder - must exist>"
    exit 1
fi

set -x

OS=$1
ARCH=$2
PKG_ROOT=$3

if [ ! -d "${PKG_ROOT}" ]; then
    echo "Package Root Folder '${PKG_ROOT}' must exist"
    exit 1
fi

UNAME=$(uname)
if [[ "${UNAME}" == *"MINGW"* ]]; then
	GOPATH1=$HOME/go
else
	export GOPATH=$(go env GOPATH)
fi
export GOPATHBIN=${GOPATH%%:*}/bin
REPO_DIR=$(pwd)

echo "Building package for '${OS} - ${ARCH}'"

if [ -z "${NO_BUILD}" ]; then
    env GOOS=${OS} GOARCH=${ARCH} scripts/build_prod.sh
else
    echo "already built"
    true
fi

if [ $? -ne 0 ]; then
    echo 'Error building! Aborting...'
    exit 1
fi

if [ "${DEFAULTNETWORK}" = "" ]; then
    DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
fi
DEFAULT_RELEASE_NETWORK=$(./scripts/compute_branch_release_network.sh "${DEFAULTNETWORK}")

mkdir ${PKG_ROOT}/bin

# If you modify this list, also update this list in ./cmd/updater/update.sh backup_binaries()
bin_files=("algocfg" "algod" "algoh" "algokey" "carpenter" "catchupsrv" "ddconfig.sh" "diagcfg" "find-nodes.sh" "goal" "kmd" "msgpacktool" "node_exporter" "tealcut" "tealdbg" "update.sh" "updater" "COPYING")
for bin in "${bin_files[@]}"; do
    cp ${GOPATHBIN}/${bin} ${PKG_ROOT}/bin
    if [ $? -ne 0 ]; then exit 1; fi
done

# Copy systemd setup script and templates
cp "cmd/updater/systemd-setup.sh" ${PKG_ROOT}/bin
if [ $? -ne 0 ]; then exit 1; fi

cp "installer/algorand@.service.template" ${PKG_ROOT}/bin
if [ $? -ne 0 ]; then exit 1; fi

cp "installer/sudoers.template" ${PKG_ROOT}/bin
if [ $? -ne 0 ]; then exit 1; fi

data_files=("config.json.example")
mkdir ${PKG_ROOT}/data
for data in "${data_files[@]}"; do
    cp installer/${data} ${PKG_ROOT}/data
    if [ $? -ne 0 ]; then exit 1; fi
done

mkdir ${PKG_ROOT}/genesis

genesis_dirs=("devnet" "testnet" "mainnet" "betanet")
for dir in "${genesis_dirs[@]}"; do
    mkdir -p ${PKG_ROOT}/genesis/${dir}
    cp ${REPO_DIR}/installer/genesis/${dir}/genesis.json ${PKG_ROOT}/genesis/${dir}/
    if [ $? -ne 0 ]; then exit 1; fi
done
# Copy the appropriate network genesis.json for our default (in root ./genesis folder)
cp ${PKG_ROOT}/genesis/${DEFAULT_RELEASE_NETWORK}/genesis.json ${PKG_ROOT}/genesis
if [ $? -ne 0 ]; then exit 1; fi

TOOLS_ROOT=${PKG_ROOT}/tools

echo "Staging tools package files"

bin_files=("algons" "auctionconsole" "auctionmaster" "auctionminion" "coroner" "dispenser" "netgoal" "nodecfg" "pingpong" "cc_service" "cc_agent" "cc_client" "loadgenerator" "COPYING" "dsign")
mkdir -p ${TOOLS_ROOT}
for bin in "${bin_files[@]}"; do
    cp ${GOPATHBIN}/${bin} ${TOOLS_ROOT}
    if [ $? -ne 0 ]; then exit 1; fi
done

echo "Staging test util package files"
TEST_UTILS_ROOT=${PKG_ROOT}/test-utils
bin_files=("auctionbank" "algotmpl" "COPYING")
mkdir -p ${TEST_UTILS_ROOT}
for bin in "${bin_files[@]}"; do
    cp ${GOPATHBIN}/${bin} ${TEST_UTILS_ROOT}
    if [ $? -ne 0 ]; then exit 1; fi
done

cp "scripts/sysctl.sh" ${TOOLS_ROOT}
if [ $? -ne 0 ]; then exit 1; fi

cp "scripts/sysctl-all.sh" ${TOOLS_ROOT}
if [ $? -ne 0 ]; then exit 1; fi
