#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$(${SCRIPTPATH}/ostype.sh)
ARCH=$(${SCRIPTPATH}/archtype.sh)

echo ${OS}/${ARCH}
