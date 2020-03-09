#!/usr/bin/env bash

set -e

MULE_VERSION='0.0.0'

HELP="Usage: $0 [-v] [-u]

Script for installing the mule cli.

Requires:
    * pip
    * python 3
    * git (And access to algorand/go-algorand-ci repository on github)

Options:
    -v        Version of mule cli (default is '${MULE_VERSION}')
    -u        Authenticate to github (algorand/go-algorand-ci repository) with user credentials (default is over ssh)
"

while getopts ":v:uh" opt; do
  case ${opt} in
    v ) MULE_VERSION=$OPTARG
      ;;
    u ) USER_AUTH="True"
      ;;
    h ) echo "${HELP}"
        exit 0
      ;;
    \? ) echo "${HELP}"
        exit 2
      ;;
  esac
done

if CURRENT_MULE_VERSION=$(mule -v 2> /dev/null); then
    if [[ ${CURRENT_MULE_VERSION} == ${MULE_VERSION} ]]; then
        echo "Mule version $(mule -v) is already installed"
        exit 0
    fi
    echo "Mule version ${CURRENT_MULE_VERSION} currently installed, installing ${MULE_VERSION}..."
fi

if PIP_VERSION=$(pip3 --version 2> /dev/null); then
    PIP="pip3"
elif PIP_VERSION=$(pip --version 2> /dev/null); then
    PIP="pip"
else
    echo "You must have pip installed to set up Mule"
    exit 1
fi

if [[ ! "${PIP_VERSION}" =~ .*'python 3'.* ]]; then
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
${PIP} install ${INSTALL_DIR}/go-algorand-ci/cli/dist/mule-${MULE_VERSION}-py3-none-any.whl --upgrade
rm -rf ${INSTALL_DIR}
