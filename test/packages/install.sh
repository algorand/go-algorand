#!/usr/bin/env bash

# This is currently used by `test_release.sh`.
# It is copied into a docker image at build time
# and then invoked at run time.

while [ "$1" != "" ]; do
    case "$1" in
        -b)
            shift
            BUCKET="$1"
            ;;
        -c)
            shift
            CHANNEL="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

curl --silent -L https://github.com/algorand/go-algorand-doc/blob/master/downloads/installers/linux_amd64/install_master_linux-amd64.tar.gz?raw=true | tar xzf -

./update.sh -b "$BUCKET" -c "$CHANNEL" -i -p ~/node -d ~/node/data -n

echo "[$0] Testing: algod -v"
./node/algod -v

