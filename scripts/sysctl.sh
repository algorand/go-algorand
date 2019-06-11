#!/bin/bash

set -e

DATADIRS=()
ACTION=""

while [ "$1" != "" ]; do
    NEWACTION=""
    case "$1" in
        -d)
            shift
            THISDIR=$1
            mkdir -p ${THISDIR} >/dev/null
            pushd ${THISDIR} >/dev/null
            THISDIR=$(pwd -P)
            popd >/dev/null
            DATADIRS+=(${THISDIR})
            ;;
	-enable)
            NEWACTION=enable
            ;;
        -disable)
            NEWACTION=disable
            ;;
        -start)
            NEWACTION=start
            ;;
        -stop)
            NEWACTION=stop
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
    if [ -n "${NEWACTION}" ]; then
        if [ -n "${ACTION}" ]; then
            echo "Only one systemctl action can be specified (${ACTION} and ${NEWACTION} found)"
            exit 1
        fi
        ACTION="${NEWACTION}"
    fi
done

if [ -z "${ACTION}" ]; then
    echo "Please specify a systemctl action (-enable, -disable, -start, or -stop)"
    exit 1
fi

if [ ${#DATADIRS[@]} -eq 0 ]; then
    echo "Please specify at least one data directory using -d"
    exit 1
fi

for DD in ${DATADIRS[@]}; do
    echo systemctl ${ACTION} algorand@$(systemd-escape ${DD})
    systemctl ${ACTION} algorand@$(systemd-escape ${DD})
done
