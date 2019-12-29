#!/usr/bin/env bash

gpgp=$(find /usr/lib/gnupg{2,,1} -type f -name gpg-preset-passphrase 2> /dev/null)
KEYGRIP=$(gpg -K --with-keygrip --textmode rpm@algorand.com|grep Keygrip|head -1|awk '{ print $3 }')
echo "enter dev@ password"
$gpgp --verbose --preset "$KEYGRIP"
echo aoeu | gpg -u dev@algorand.com --clearsign

REMOTE_GPG_SOCKET=$(ssh ubuntu@"$HOME/scripts/buildhost/tmp/instance" gpgbin/remote_gpg_socket)
LOCAL_GPG_SOCKET=$(gpgconf --list-dirs | grep agent-socket | awk -F: '{ print $2 }')

gpg --export -a dev@algorand.com > /tmp/dev.pub
#gpg --export -a rpm@algorand.com > /tmp/rpm.pub

scp -p /tmp/dev.pub ubuntu@"$HOME/scripts/buildhost/tmp/instance":~/

ssh -A -R "$REMOTE_GPG_SOCKET:$LOCAL_GPG_SOCKET" ubuntu@"$HOME/scripts/buildhost/tmp/instance"
gpg --import dev.pub
echo aoeu | gpg -u dev@algorand.com --clearsign

