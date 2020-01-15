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
KEYGRIP=$(gpg -K --with-keygrip --textmode dev@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')

echo "enter dev@ password"
$gpgp --verbose --preset "$KEYGRIP"

REMOTE_GPG_SOCKET=$(ssh -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem ubuntu@"$INSTANCE" gpgbin/remote_gpg_socket)
LOCAL_GPG_SOCKET=$(gpgconf --list-dirs | grep agent-socket | awk -F: '{ print $2 }')

gpg --export -a dev@algorand.com > /tmp/dev.pub
gpg --export -a rpm@algorand.com > /tmp/rpm.pub

scp -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem -p /tmp/{dev,rpm}.pub ubuntu@"$INSTANCE":~/docker_test_resources/
ssh -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem ubuntu@"$INSTANCE" << EOF
    gpg --import docker_test_resources/dev.pub
    gpg --import docker_test_resources/rpm.pub
    echo "SIGNING_KEY_ADDR=dev@algorand.com" >> build_env
EOF

ssh -o StrictHostKeyChecking=no -i ReleaseBuildInstanceKey.pem -A -R "$REMOTE_GPG_SOCKET:$LOCAL_GPG_SOCKET" ubuntu@"$INSTANCE"

