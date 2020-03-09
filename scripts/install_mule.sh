#!/usr/bin/env bash

set -e

MULE_VERSION='0.0.0'

while getopts ":v:u" opt; do
  case ${opt} in
    v ) MULE_VERSION=$OPTARG
      ;;
    u ) USER_AUTH="True"
      ;;
    \? ) echo """
Usage: cmd [-v] [-u]

Options:
    -v        Version of mule cli
    -u        Authenticate to github (algorand/go-algorand-ci repository) with user credentials (Default is over ssh)
"""
        exit 1
      ;;
  esac
done



if mule -v &> /dev/null; then
    echo "Mule version $(mule -v) is already installed"
    exit 0
fi

if VERSION=$(pip3 --version 2> /dev/null); then
    PIP="pip3"
elif VERSION=$(pip --version 2> /dev/null); then
    PIP="pip"
else
    echo "You must have pip installed to set up Mule"
    exit 1
fi

if [[ ! "${VERSION}" =~ .*'python 3'.* ]]; then
    echo "Your pip installation must be using python 3"
    exit 1
fi

TIME=$(date +%s)
INSTALL_DIR="/tmp/mule-install-${TIME}"
mkdir -p ${INSTALL_DIR}
if [[ ${USER_AUTH} == "True" ]]; then
    git clone https://github.com/algorand/go-algorand-ci.git ${INSTALL_DIR}/go-algorand-ci
else
    git clone git@github.com:algorand/go-algorand-ci.git ${INSTALL_DIR}/go-algorand-ci
fi
pip3 install ${INSTALL_DIR}/go-algorand-ci/cli/dist/mule-${MULE_VERSION}-py3-none-any.whl --upgrade
rm -rf ${INSTALL_DIR}
