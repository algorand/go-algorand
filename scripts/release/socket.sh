#!/usr/bin/env bash

TARGET="$1"
gpgp=$(find /usr/lib/gnupg{2,,1} -type f -name gpg-preset-passphrase 2> /dev/null)
KEYGRIP=$(gpg -K --with-keygrip --textmode dev@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')

echo "enter dev@ password"
$gpgp --verbose --preset "$KEYGRIP"
echo aoeu | gpg -u dev@algorand.com --clearsign

REMOTE_GPG_SOCKET=$(ssh -i BuilderInstanceKey.pem ubuntu@"$TARGET" gpgbin/remote_gpg_socket)
LOCAL_GPG_SOCKET=$(gpgconf --list-dirs | grep agent-socket | awk -F: '{ print $2 }')

gpg --export -a dev@algorand.com > /tmp/dev.pub
gpg --export -a rpm@algorand.com > /tmp/rpm.pub

# TODO: Maybe scp the public keys into the $HOME/docker... dir on the remote server?
scp -i BuilderInstanceKey.pem -p /tmp/{dev,rpm}.pub ubuntu@"$TARGET":~/
ssh -i BuilderInstanceKey.pem ubuntu@"$TARGET" << EOF
    gpg --import dev.pub
    gpg --import rpm.pub
    echo SIGNING_KEY_ADDR=dev@algorand.com >> build_env
EOF
ssh -i BuilderInstanceKey.pem -A -R "$REMOTE_GPG_SOCKET:$LOCAL_GPG_SOCKET" ubuntu@"$TARGET"

#echo aoeu | gpg -u dev@algorand.com --clearsign
#echo aoeu | gpg -u rpm@algorand.com --clearsign

