#!/usr/bin/env bash
# shellcheck disable=2181

set -exo pipefail

BUILDTOOLS_INSTALL=ALL

function usage {
  echo "$0 is used to install go build tools."
  echo "By default all packages are installed."
  echo "usage: $0 [-o packagename]"
  echo "  -o packagename    when used only packagename is installed."
  echo "  -h                print this usage information."
  exit 1
}

while getopts ":o:h" opt; do
  case $opt in
    o)
      BUILDTOOLS_INSTALL="$OPTARG"
      ;;
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
pushd "${SCRIPTPATH}/../.."

function get_go_version {
    cd "${SCRIPTPATH}"
    VERSION=$( grep "$1" 2>/dev/null < ./go.mod | awk -F " " '{print $2}')
    echo "$VERSION"
    return
}

function install_go_module {
    local OUTPUT
    local MODULE
    if [[ "$2" != "" ]]; then
        MODULE=$2
    else
        MODULE=$1
    fi
    # Check for version to go.mod version
    VERSION=$(get_go_version "$1")

    # TODO: When we switch to 1.16 this should be changed to use 'go install'
    #       instead of 'go get': https://tip.golang.org/doc/go1.16#modules
    if [ -z "$VERSION" ]; then
        OUTPUT=$(GO111MODULE=off go get -u "${MODULE}" 2>&1)
    else
        OUTPUT=$(GO111MODULE=on go get "${MODULE}@${VERSION}" 2>&1)
    fi
    if [ $? != 0 ]; then
        echo "error: executing \"go get ${MODULE}\" failed : ${OUTPUT}"
        exit 1
    fi
}

if [[ "${BUILDTOOLS_INSTALL}" == "ALL" ]]; then
  install_go_module golang.org/x/lint golang.org/x/lint/golint
  install_go_module golang.org/x/tools golang.org/x/tools/cmd/stringer
  install_go_module github.com/go-swagger/go-swagger github.com/go-swagger/go-swagger/cmd/swagger
  install_go_module github.com/algorand/msgp
  install_go_module gotest.tools/gotestsum
else
  install_go_module "${BUILDTOOLS_INSTALL}"
fi

popd
