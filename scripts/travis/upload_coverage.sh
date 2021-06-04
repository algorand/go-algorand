#!/usr/bin/env bash

# Download codecov bash script, verify checksum from github, run script

# fail if shasum detects a problem
set -e

FILE_ARG=""
if [[ -f "$1" ]]; then
  FILE_ARG="-f $1"
fi

curl -fLso codecov https://codecov.io/bash;
VERSION=$(grep -o 'VERSION=\"[0-9\.]*\"' codecov | cut -d'"' -f2);
for i in 1 256 512
do
  shasum -a $i -c --ignore-missing <(curl -s "https://raw.githubusercontent.com/codecov/codecov-bash/${VERSION}/SHA${i}SUM")
done

# Unset everything except "TRAVIS*" variables.
unset $(compgen -e | grep -v "^TRAVIS")
bash codecov -t "${CODECOV_TOKEN}" "${FILE_ARG}"
