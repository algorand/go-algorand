#!/usr/bin/env bash

set -e
set -x

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

# Get the go build version.
GOLANG_VERSION=$(./scripts/get_golang_version.sh)

curl -sL -o ~/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/gimme
eval "$(~/gimme "${GOLANG_VERSION}")"

# If this command fails the Makefile will select 'go test' instead.
"${SCRIPTPATH}/../buildtools/install_buildtools.sh" -o "gotest.tools/gotestsum" || true

if [ "${OS}-${ARCH}" = "linux-arm" ] || [ "${OS}-${ARCH}" = "windows-amd64" ]; then
     # for arm, no tests need to be invoked.
     # for now, disable tests on windows.
     exit 0
 fi

if $CIRCLECI; then
  GOPATHBIN=/home/circleci/.go_workspace/bin;
else
  GOPATHBIN=$(go env GOPATH)/bin
fi
export PATH=$PATH:$GOPATHBIN

scripts/travis/run_tests.sh;
scripts/travis/after_build.sh;
