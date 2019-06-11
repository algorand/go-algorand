#!/bin/bash

# compute_build_number.sh - Calculates the build number to use based on the current date/time.
#           Optionally computes the complete version string from scanning config/version.go for the
#           current major/minor version numbers.
#
# Syntax:   compute_build_number.sh [-f]
#               -f     Compute full version string (e.g. 1.0.1234)
#
# Outputs:  <buildnumber>, or <major>.<minor>.<buildnumber>
#
# Usage:    Calculate build number or full version string.
#
# Examples: scripts/compute_build_number.sh
#           >$ 1234
#           scripts/compute_build_number.sh -f
#           >$ 1.10.1234
export GOPATH=$(go env GOPATH)
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
cd ${SCRIPTPATH}/..

BUILD_NUMBER=${BUILD_NUMBER}
if [ "${BUILD_NUMBER}" = "" ]; then
    if [ -e buildnumber.dat ]; then
        BUILD_NUMBER=$(cat ./buildnumber.dat)
    else
        BUILD_NUMBER=$(./scripts/buildnumber.py)
    fi
fi

VERSION_FILE=config/version.go

# -f means 'Full Version' - we also extract Major/Minor version numbers from
# config/version.go and generate the full version number (MM.mm.BuildNumber)
# Otherwise we just calculate the date/time-based BuildNumber

if [ ! "$1" == "-f" ]; then
    echo ${BUILD_NUMBER}
else
    MAJOR_REGEX="VersionMajor = ([[:digit:]]*)"
    MINOR_REGEX="VersionMinor = ([[:digit:]]*)"

    while read -r line || [[ -n "$line" ]]; do
        if [[ ${line} =~ ${MAJOR_REGEX} ]]; then
            MAJOR=${BASH_REMATCH[1]}
        elif [[ $line =~ $MINOR_REGEX ]]; then
            MINOR=${BASH_REMATCH[1]}
        fi
        if [[ ${MAJOR} && ${MINOR} ]]; then
            break
        fi
    done < "${VERSION_FILE}"

    if [[ ! ${MAJOR} && ${MINOR} ]]; then
        exit 1
    fi

    echo ${MAJOR}.${MINOR}.${BUILD_NUMBER}
fi
