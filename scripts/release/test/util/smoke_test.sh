#!/usr/bin/env bash

set -ex

# This is currently used by `test_package.sh`.
# It is copied into a docker image at build time and then invoked at run time.

BRANCH=
CHANNEL=
COMMIT_HASH=
FULLVERSION=

while [ "$1" != "" ]; do
    case "$1" in
        -b)
            shift
            BRANCH="$1"
            ;;
        -c)
            shift
            CHANNEL="$1"
            ;;
        -h)
            shift
            COMMIT_HASH="$1"
            ;;
        -r)
            shift
            FULLVERSION="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [ -z "$BRANCH" ] || [ -z "$COMMIT_HASH" ] || [ -z "$FULLVERSION" ]
then
    echo "[ERROR] $0 -b BRANCH -c CHANNEL -h COMMIT_HASH -r FULLVERSION"
    exit 1
fi

echo "[$0] Testing: algod -v"
if < /etc/os-release grep Ubuntu > /dev/null
then
    dpkg -i ./*.deb
else
    yum install ./*.rpm -y
fi

STR=$(algod -v)
SHORT_HASH=${COMMIT_HASH:0:8}

# We're looking for a line that looks like the following:
#
#       2.0.4.stable [rel/stable] (commit #729b125a)
#
# Since we're passing in the full hash, we won't using the closing paren.
# Use a regex over the multi-line string.
if [[ "$STR" =~ .*"$FULLVERSION.$CHANNEL [$BRANCH] (commit #$SHORT_HASH)".* ]]
then
    echo -e "[$0] The result of \`algod -v\` is a correct match.\n$STR"
    exit 0
fi

echo "[$0] The result of \`algod -v\` is an incorrect match."
exit 1

