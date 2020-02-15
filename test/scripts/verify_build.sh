#!/bin/bash

BINDIR=""
DATADIR=""
CHANNEL="dev"

while [ "$1" != "" ]; do
    case "$1" in
        -p)
            shift
            BINDIR="$1"
            ;;
        -d)
            shift
            DATADIR="$1"
            ;;
        -c)
            shift
            CHANNEL="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

# Verify version is non-zero
CURRENTVER="$(( ${BINDIR}/algod -v || echo 0 ) | head -n 1)"
if [ $? -ne 0 ]; then
    echo Error checking version
    exit 1
fi

if [ "${CURRENTVER}" -eq 0 ]; then
    echo Error verifying version
    exit 1
fi

# Verify channel matches expectation
CURRENTCHANNEL="$(${BINDIR}/algod -c || echo "" )"
if [ $? -ne 0 ]; then
    echo Error checking channel
    exit 1
fi

if [ "${CURRENTCHANNEL}" != "${CHANNEL}" ]; then
    # For now, treat X == X-telem
    if [ "${CURRENTCHANNEL}" != "${CHANNEL}-telem" ]; then
        echo Error verifying channel: got ${CURRENTCHANNEL} instead of ${CHANNEL}
        exit 1
    fi
fi

# Verify Genesis ID is valid / non-empty
CURRENTGENESIS="$(${BINDIR}/algod -G -d ${DATADIR} || echo "" )"
if [ $? -ne 0 ]; then
    echo Error checking genesis ID
    exit 1
fi

if [ "${CURRENTGENESIS}" = "" ]; then
    echo Error verifying genesis ID
    exit 1
fi
