#!/usr/bin/env bash

# Download codecov bash script, verify checksum from github, run script

# fail if shasum detects a problem
set -eo pipefail

FILE_ARG=""
if [[ -f "$1" ]]; then
  FILE_ARG="-f $1"
fi

curl -fLso codecov https://codecov.io/bash
VERSION=$(grep -o 'VERSION=\"[0-9\.]*\"' codecov | cut -d'"' -f2)
for i in 1 256 512
do
  curl -s "https://raw.githubusercontent.com/codecov/codecov-bash/${VERSION}/SHA${i}SUM" | grep codecov > sum
  if [[ $(cat sum) != *"codecov" ]]; then
    echo "sum not found."
    exit 1
  fi
  shasum -a $i -c sum
done
rm sum

# Unset everything except "TRAVIS*" variables.
unset $(compgen -e | grep -v "^TRAVIS")
/usr/bin/env bash codecov -t "${CODECOV_TOKEN}" "${FILE_ARG}"
