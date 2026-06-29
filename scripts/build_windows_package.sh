#!/usr/bin/env bash

# build_windows_package.sh - Stage Windows binaries and produce a release .zip.
#
# This is intentionally separate from build_package.sh (the Unix packaging path).
# That layout is Unix-shaped: it bundles a systemd service template, sudoers,
# sysctl tuning and the shell-based auto-updater, none of which function on
# Windows, and it copies Go binaries without the .exe suffix Windows produces.
# Here we ship just what is useful on Windows: the Go binaries (.exe),
# node_exporter, the genesis files and the config example.
#
# Syntax:   build_windows_package.sh <output_dir>
#
# Inputs (env):
#   VERSION or FULLVERSION  Version string, e.g. 4.5.0 (falls back to
#                           compute_build_number.sh -f when unset).
#   GOBIN                   Location of the built binaries (otherwise derived
#                           the same way build_package.sh does).
#
# Output:   <output_dir>/algorand-node-windows-amd64-<version>.zip
#
# Examples: scripts/build_windows_package.sh dist

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Syntax: build_windows_package.sh <output_dir>"
    exit 1
fi

OUTDIR=$1
mkdir -p "${OUTDIR}"
OUTDIR=$(cd "${OUTDIR}" && pwd)

REPO_DIR=$(pwd)

VERSION=${VERSION:-${FULLVERSION:-}}
if [ -z "${VERSION}" ]; then
    VERSION=$(./scripts/compute_build_number.sh -f)
fi

# Resolve GOBIN the same way build_package.sh does.
UNAME=$(uname)
if [[ "${UNAME}" == *"MINGW"* ]] || [[ "${UNAME}" == *"MSYS"* ]]; then
    GOPATH1=$HOME/go
else
    GOPATH1=$(go env GOPATH)
    GOPATH1=${GOPATH1%%:*}
fi
if [[ -n "${GOBIN:-}" ]]; then
    : # use the GOBIN provided by the environment
elif [[ -n "$(go env GOBIN)" ]]; then
    GOBIN=$(go env GOBIN)
else
    GOBIN=${GOPATH1}/bin
fi

STAGE=$(mktemp -d)
trap 'rm -rf "${STAGE}"' EXIT

PKG_NAME="algorand-node-windows-amd64-${VERSION}"
PKG_ROOT="${STAGE}/${PKG_NAME}"
mkdir -p "${PKG_ROOT}"

echo "Staging Windows package ${PKG_NAME} from ${GOBIN}"

# Go binaries get a .exe suffix on Windows.
node_bins=(algod algocfg algoh algokey algotmpl diagcfg goal kmd)
devtools_bins=(algons carpenter coroner dispenser msgpacktool netgoal nodecfg pingpong loadgenerator dsign catchpointdump block-generator tealdbg)

for bin in "${node_bins[@]}" "${devtools_bins[@]}"; do
    src="${GOBIN}/${bin}.exe"
    if [ ! -f "${src}" ]; then
        echo "Error: expected binary not found: ${src}"
        exit 1
    fi
    cp "${src}" "${PKG_ROOT}/"
done

# node_exporter is intentionally omitted: the upstream Windows build is an empty
# stub, so it is not built (see Makefile) or shipped on Windows.

# License and config example.
cp "${REPO_DIR}/COPYING" "${PKG_ROOT}/"
mkdir -p "${PKG_ROOT}/data"
cp "${REPO_DIR}/installer/config.json.example" "${PKG_ROOT}/data/"

# Genesis files (committed copies under installer/genesis).
mkdir -p "${PKG_ROOT}/genesis"
genesis_dirs=(devnet testnet mainnet betanet alphanet)
for dir in "${genesis_dirs[@]}"; do
    mkdir -p "${PKG_ROOT}/genesis/${dir}"
    cp "${REPO_DIR}/installer/genesis/${dir}/genesis.json" "${PKG_ROOT}/genesis/${dir}/"
done

ZIP_PATH="${OUTDIR}/${PKG_NAME}.zip"
rm -f "${ZIP_PATH}"
( cd "${STAGE}" && zip -r -q "${ZIP_PATH}" "${PKG_NAME}" )

echo "Created ${ZIP_PATH}"
