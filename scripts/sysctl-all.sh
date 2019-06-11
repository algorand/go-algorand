#!/bin/bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

ACTION=""

while [ "$1" != "" ]; do
    NEWACTION=""
    case "$1" in
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

${SCRIPTPATH}/sysctl.sh -${ACTION} $(${SCRIPTPATH}/find-nodes.sh ${SCRIPTPATH}/data)
