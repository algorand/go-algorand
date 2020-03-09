#!/usr/bin/env bash

set -e

if mule -v &> /dev/null; then
    echo "Mule version $(mule -v) is already installed"
    exit 0
fi

if VERSION=$(pip3 --version) &> /dev/null; then
    PIP="pip3"
elif VERSION=$(pip --version) &> /dev/null; then
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
git clone git@github.com:algorand/go-algorand-ci.git ${INSTALL_DIR}/go-algorand-ci
pip3 install ${INSTALL_DIR}/go-algorand-ci/cli/dist/mule-0.0.0-py3-none-any.whl
rm -rf ${INSTALL_DIR}
