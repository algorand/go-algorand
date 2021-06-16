#!/usr/bin/env bash

# ./compute_package_name <CHANNEL> <NAME>
#
# Examples:
# ./compute_package_name stable                     -> algorand
# ./compute_package_name beta                       -> algorand-beta
# ./compute_package_name nightly algorand-devtools  -> algorand-devtools-nightly

CHANNEL=${1:-stable}
NAME=${2:-algorand}

if [ -z ${PACKAGE_NAME_EXTENSION} ]; then
  NAME = ${NAME}-${PACKAGE_NAME_EXTENSION}
fi

if [ "$CHANNEL" = beta ]; then
    echo "$NAME-beta"
elif [ "$CHANNEL" = nightly ]; then
    echo "$NAME-nightly"
else
    echo "$NAME"
fi

