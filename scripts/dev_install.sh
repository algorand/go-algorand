#!/usr/bin/env bash

TARGETBINDIR=""
DATADIRSPEC=""

while [ "$1" != "" ]; do
    case "$1" in
        -p)
            shift
            TARGETBINDIR="$1"
            ;;
        -d)
            shift
            DATADIRSPEC+="-d $1 "
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [ "${TARGETBINDIR}" = "" ]; then
    echo "Target path not specified.  Please specify the target path for binaries with -p <path>"
    exit 1
fi

# dev_install.sh should explicitly generate 'dev' builds
scripts/local_install.sh -c dev -p ${TARGETBINDIR} ${DATADIRSPEC} -f -s
