#!/usr/bin/env bash

set -e

export CHANNEL="dev"

TARGETBINDIR=""
DATADIRSPEC=""
NOINSTALL=0
ADDITIONALFLAGS=""

while [ "$1" != "" ]; do
    case "$1" in
        -p)
            shift
            TARGETBINDIR="$1"
            ;;
        -c)
            shift
            export CHANNEL="$1"
            ;;
        -d)
            shift
            DATADIRSPEC+="-d $1 "
            ;;
        -n)
            NOINSTALL=1
            ;;
        -f)
            shift
            ADDITIONALFLAGS="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [ ${NOINSTALL} -eq 0 ]; then
    if [ "${TARGETBINDIR}" = "" ]; then
        echo "Target path not specified.  Please specify the target path for binaries with -p <path>"
        exit 1
    fi

    if [ "${DATADIRSPEC}" = "" ]; then
        if [ "${CHANNEL}" = "dev" ]; then
            DATADIRSPEC="-d ${HOME}/.algorand"
        else
            DATADIRSPEC="-d ${HOME}/.algorand-testnet"
        fi
    fi
fi

# Build install package into ~/dev_pkg
export PKG_ROOT=$(pwd)/tmp/dev_pkg
rm -rf ${PKG_ROOT}
mkdir -p ${PKG_ROOT}

# Generate the install package
echo "Generating update package..."
./scripts/build_package.sh $(./scripts/ostype.sh) $(./scripts/archtype.sh) ${PKG_ROOT}

if [ ${NOINSTALL} -eq 0 ]; then
    echo "Running update script from install package..."
    ${PKG_ROOT}/bin/update.sh -i -r -p ${TARGETBINDIR} -c ${CHANNEL} -n ${DATADIRSPEC} ${ADDITIONALFLAGS}
fi
