#!/usr/bin/env bash

# ./compute_package_name <CHANNEL> <NAME>
#
# Examples:
# ./compute_package_name stable                     -> algorand
# ./compute_package_name beta                       -> algorand-beta
# ./compute_package_name nightly algorand-devtools  -> algorand-devtools-nightly

CHANNEL=${1:-stable}
NAME=${2:-algorand}

if [ -n "${PACKAGE_NAME_EXTENSION}" ]; then
  NAME="${NAME}-${PACKAGE_NAME_EXTENSION}"
fi

if [ "$CHANNEL" = stable ]; then
    echo "$NAME"
else
    echo "$NAME-$CHANNEL"
fi
