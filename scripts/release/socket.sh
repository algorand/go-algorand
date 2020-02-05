#!/usr/bin/env bash

# TODO: ssh-keyscan?
# -o StrictHostKeyChecking=no suppresses the (yes/no) new key ssh question.
# This lessens the security, but it may be acceptable in this case.

if [ -z "$1" ]
then
    echo Missing \`instance\` variable.
    exit 1
fi

INSTANCE=$1
gpgp=$(find /usr/lib/gnupg{2,,1} -type f -name gpg-preset-passphrase 2> /dev/null)
#KEYGRIP=$(gpg -K --with-keygrip --textmode dev@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')

echo "enter dev@ password"
#$gpgp --verbose --preset "$KEYGRIP"
$gpgp --verbose --preset 54AAB31D7752B6103B40A2E007E6E473D98268E4

#KEYGRIP=$(gpg -K --with-keygrip --textmode rpm@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')

echo "enter rpm@ password"
#$gpgp --verbose --preset "$KEYGRIP"
$gpgp --verbose --preset 151555B500ED5C7A6CF8117D4D4C49AD5194FD03

REMOTE_GPG_SOCKET=$(ssh -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem ubuntu@"$INSTANCE" gpgbin/remote_gpg_socket)
LOCAL_GPG_SOCKET=$(gpgconf --list-dirs | grep agent-socket | awk -F: '{ print $2 }')

gpg --export -a dev@algorand.com > /tmp/dev.pub
gpg --export -a rpm@algorand.com > /tmp/rpm.pub

scp -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem -p /tmp/{dev,rpm}.pub ubuntu@"$INSTANCE":~/keys/
ssh -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem ubuntu@"$INSTANCE" << EOF
    gpg --import keys/dev.pub
    gpg --import keys/rpm.pub
    echo "SIGNING_KEY_ADDR=dev@algorand.com" >> build_env
EOF

ssh -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem -A -R "$REMOTE_GPG_SOCKET:$LOCAL_GPG_SOCKET" ubuntu@"$INSTANCE"

