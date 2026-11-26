#!/usr/bin/env bash

# build_packages.sh - Builds packages for one or more platforms and creates .tar.gz archive to be used for auto-update.
#           Packages are assembled under $HOME/node_pkg.  This directory is deleted before starting.
#
# Syntax:   build_packages.sh <os>/<arch> [<os>/<arch> ...]
#
# Outputs:  <output from build_package.sh, and errors>
#
# ExitCode: 0 = All target packages built successfully and .tar.gz files created in $HOME/node_pkg
#
# Usage:    Generate usable production update packages for one or more platforms.
#           Currently used by deploy_version.sh for the core build/package step.
#
# Examples: scripts/build_packages.sh

if [ "$#" -eq 0 ]; then
    echo "Syntax: build_packages.sh <os>/<arch> <os>/<arch> ..."
    exit 1
fi

set -x

if [ "${FULLVERSION}" = "" ]; then
    export FULLVERSION=$(./scripts/compute_build_number.sh -f)
fi

if [ "${CHANNEL}" = "" ]; then
    if [ "${BRANCH}" = "" ]; then
        export BRANCH=$(./scripts/compute_branch.sh)
    fi
    export CHANNEL=$(./scripts/compute_branch_channel.sh ${BRANCH})
fi

VARIATION_ARRAY=(${VARIATIONS})
echo "Variation Array: ${VARIATION_ARRAY}"

# Set the TIMESTAMP to use for the genesis.json file - set here so all packages use the same number
TIMESTAMP=
if [ -e ./genesistimestamp.dat ]; then
    TIMESTAMP=$(cat ./genesistimestamp.dat)
else
    TIMESTAMP=$(date +%s)
fi
export TIMESTAMP=${TIMESTAMP}

# Normalize tar metadata so the archives depend only on their contents: file
# order, mtimes, ownership and permission bits otherwise vary with the
# filesystem, build time, build user and umask. --mode sets every permission
# bit, keeping only whether an entry is a directory or executable (X). These
# options need GNU tar, which macOS provides as gtar (brew install gnu-tar).
if [ "${SOURCE_DATE_EPOCH}" = "" ]; then
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
fi
TAR=tar
if command -v gtar >/dev/null 2>&1; then
    TAR=gtar
fi
# gzip -n keeps the compression time out of the gzip header. GNU gzip already
# omits it when compressing a pipe, but the gzip macOS ships does not.
if ${TAR} --version 2>/dev/null | grep -q "GNU tar"; then
    TAR_OPTS=(--sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner --mode=u=rwX,go=rX --use-compress-program="gzip -n")
else
    echo "Warning: GNU tar not found; package archives will not be reproducible"
    TAR_OPTS=(-z)
fi
# The shell glob passed to tar below is expanded in locale collation order.
export LC_ALL=C

VERSION_COMPONENTS=(${FULLVERSION//\./ })
export BUILDNUMBER=${VERSION_COMPONENTS[2]}

if [ "${BUILDNUMBER}" = "" ]; then
    echo "FULLVERSION does not appear to be valid: ${FULLVERSION}"
    exit 1
fi

if [ "${PKG_ROOT}" = "" ]; then
    PKG_ROOT=${HOME}/node_pkg
fi

BASECHANNEL=${CHANNEL}

echo Building ${#VARIATION_ARRAY[@]} variations
for var in "${VARIATION_ARRAY[@]}"; do
    echo "'${var}'"
done

for var in "${VARIATION_ARRAY[@]}"; do
    echo " building '${var}'"
    if [ "${var}" = "base" ]; then
        var=""
    fi

    # If building just a single target, don't qualify the channel/package names at all
    if [ ${#VARIATION_ARRAY[@]} -eq 1 ]; then
        export CHANNEL=${BASECHANNEL}
    else
        export CHANNEL=${BASECHANNEL}${var}
    fi
    export VARIATION=${var}

    for PLATFORM in $@; do
        PLATFORM_SPLIT=(${PLATFORM//\// })
        OS=${PLATFORM_SPLIT[0]}
        ARCH=${PLATFORM_SPLIT[1]}
        PKG_NAME=${OS}-${ARCH}

        PLATFORM_ROOT=${PKG_ROOT}/${CHANNEL}/${PKG_NAME}
        rm -rf ${PLATFORM_ROOT}
        mkdir -p ${PLATFORM_ROOT}
        scripts/build_package.sh ${OS} ${ARCH} ${PLATFORM_ROOT}

        if [ $? -ne 0 ]; then
            echo "Error building package for ${PLATFORM}.  Aborting..."
            exit 1
        fi

        echo Building package for channel ${CHANNEL} to ${PLATFORM_ROOT}

        pushd ${PLATFORM_ROOT}
        ${TAR} "${TAR_OPTS[@]}" --exclude=tools -cf ${PKG_ROOT}/node_${CHANNEL}_${PKG_NAME}_${FULLVERSION}.tar.gz * >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "Error creating node tar file for package ${PLATFORM}.  Aborting..."
            exit 1
        fi
        cd bin
        ${TAR} "${TAR_OPTS[@]}" -cf ${PKG_ROOT}/install_${CHANNEL}_${PKG_NAME}_${FULLVERSION}.tar.gz updater update.sh >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "Error creating install tar file for package ${PLATFORM}.  Aborting..."
            exit 1
        fi

        cd ${PLATFORM_ROOT}/tools
        ${TAR} "${TAR_OPTS[@]}" -cf ${PKG_ROOT}/tools_${CHANNEL}_${PKG_NAME}_${FULLVERSION}.tar.gz * >/dev/null 2>&1
        popd
    done
done
