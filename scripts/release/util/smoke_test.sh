#!/usr/bin/env bash

# This is currently used by `test_package.sh`.
# It is copied into a docker image at build time and then invoked at run time.

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
YELLOW_FG=$(tput setaf 3 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

BRANCH=
CHANNEL=stable
HASH=
RELEASE=

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
            HASH="$1"
            ;;
        -r)
            shift
            RELEASE="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [ -z "$BRANCH" ] || [ -z "$HASH" ] || [ -z "$RELEASE" ]
then
    echo "$YELLOW_FG[Usage]$END_FG_COLOR $0 -b BRANCH -c CHANNEL -h HASH -r RELEASE"
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
SHORT_HASH=${HASH:0:8}

# We're looking for a line that looks like the following:
#
#       2.0.4.stable [rel/stable] (commit #729b125a)
#
# Since we're passing in the full hash, we won't using the closing paren.
# Use a regex over the multi-line string.
if [[ "$STR" =~ .*"$RELEASE.$CHANNEL [$BRANCH] (commit #$SHORT_HASH)".* ]]
then
    echo -e "$GREEN_FG[$0]$END_FG_COLOR The result of \`algod -v\` is a correct match.\n$STR"
    exit 0
fi

echo "$RED_FG[$0]$END_FG_COLOR The result of \`algod -v\` is an incorrect match."
exit 1

