#!/usr/bin/env bash

gpgp=$(find /usr/lib/gnupg{2,,1} -type f -name gpg-preset-passphrase 2> /dev/null)

# Here we need to grab the signing subkey, hence `tail -1`.
KEYGRIP=$(gpg -K --with-keygrip --textmode dev@algorand.com | grep Keygrip | tail -1 | awk '{ print $3 }')
echo "enter dev@ password"
$gpgp --verbose --preset "$KEYGRIP"

KEYGRIP=$(gpg -K --with-keygrip --textmode rpm@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')
echo "enter rpm@ password"
$gpgp --verbose --preset "$KEYGRIP"

