#!/usr/bin/env bash

# Script to install algod in all sorts of different ways.
#
# Parameters:
#    -d    : Location where binaries will be installed.
#    -c    : Channel to install. Mutually exclusive with source options.
#    -u    : Git repository URL. Mutually exclusive with -c.
#    -b    : Git branch. Mutually exclusive with -c.
#    -s    : (optional) Git Commit SHA hash. Mutually exclusive with -c.

set -e

rootdir=$(dirname "$0")
pushd "$rootdir"

BINDIR=""
CHANNEL=""
URL=""
BRANCH=""
SHA=""

while getopts "p:d:c:u:b:s:" opt; do
  case "$opt" in
    p) BINDIR=$OPTARG; ;;
    d) ALGORAND_DATA=$OPTARG; ;;
    c) CHANNEL=$OPTARG; ;;
    u) URL=$OPTARG; ;;
    b) BRANCH=$OPTARG; ;;
    s) SHA=$OPTARG; ;;
    *) echo "unknown flag"; exit 1;;
  esac
done

if [ -z "$BINDIR" ]; then
  echo "-d <bindir> is required."
  exit 1
fi

if [ -n "$CHANNEL" ] && [ -n "$BRANCH" ]; then
  echo "Set only one of -c <channel> or -b <branch>"
  exit 1
fi

if [ -n "$BRANCH" ] && [ -z "$URL" ]; then
  echo "If using -b <branch>, must also set -u <git url>"
  exit 1
fi

echo "Installing algod with options:"
echo "  BINDIR = ${BINDIR}"
echo "  DATADIR = ${ALGORAND_DATA}"
echo "  CHANNEL = ${CHANNEL}"
echo "  URL = ${URL}"
echo "  BRANCH = ${BRANCH}"
echo "  SHA = ${SHA}"

if [ -n "$CHANNEL" ] && [ -n "$BRANCH" ]; then
  echo "Do not provide CHANNEL and BRANCH."
  exit 1
fi

# Deploy from release channel.
if [ -n "$CHANNEL" ]; then
  ./update.sh -i -c "$CHANNEL" -p "$BINDIR" -d "${ALGORAND_DATA}" -n
  exit 0
fi

# Build from source.
if [ -n "$BRANCH" ]; then
  git clone --single-branch --branch "${BRANCH}" "${URL}"
else
  git clone "${URL}"
fi

cd go-algorand
if [ "${SHA}" != "" ]; then
  echo "Checking out ${SHA}"
  git checkout "${SHA}"
fi

git log -n 5

./scripts/configure_dev.sh
# make sure the makefile uses specific values for BUILD_NUMBER and BRANCH
BUILD_NUMBER="" BRANCH="$BRANCH" make build

shopt -s extglob

cd "$BINDIR" && rm -vrf !(algocfg|algod|algokey|diagcfg|goal|kmd|msgpacktool|node_exporter|tealdbg|update.sh|updater|COPYING)

"$BINDIR"/algod -v
