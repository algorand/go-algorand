#!/usr/bin/env bash

# shellcheck disable=2196

# JENKINS=username@ip
# JENKINS_KEY=location/to/jenkins/private_key.pem

if [ -z "$JENKINS" ] || [ -z "$JENKINS_KEY" ]
then
    echo Missing JENKINS or JENKINS_KEY environment variables.
    exit 1
fi

BRANCH=${1:-build-packages}
EC2_INSTANCE_KEY=ReleaseBuildInstanceKey.pem

# Get the ec2 instance name and the ephemeral private key from the Jenkins server.

# First, get the ephemeral key.
# To avoid permissions issues, it's necessary to first copy the key to $HOME and then chown.
rm -f "$EC2_INSTANCE_KEY"
ssh -i "$JENKINS_KEY" "$JENKINS" sudo cp "/opt/jenkins/workspace/$BRANCH/$EC2_INSTANCE_KEY" .
ssh -i "$JENKINS_KEY" "$JENKINS" 'sudo chown ubuntu ~/"$EC2_INSTANCE_KEY" .'
scp -i "$JENKINS_KEY" "$JENKINS":~/"$EC2_INSTANCE_KEY" .
# We need to remove the key from Jenkins $HOME when we're finished.
ssh -i "$JENKINS_KEY" "$JENKINS" 'rm ~/"$EC2_INSTANCE_KEY"'

# Second, get the ec2 instance name.
INSTANCE=$(ssh -i "$JENKINS_KEY" "$JENKINS" sudo cat /opt/jenkins/workspace/"$BRANCH"/scripts/release/common/ec2/tmp/instance)

gpgp=$(find /usr/lib/gnupg{2,,1} -type f -name gpg-preset-passphrase 2> /dev/null)

# Here we need to grab the signing subkey, hence `tail -1`.
KEYGRIP=$(gpg -K --with-keygrip --textmode dev@algorand.com | grep -AE 1 '^ssb[^#]' | grep Keygrip | awk '{ print $3 }')
echo "enter dev@ password"
$gpgp --verbose --preset "$KEYGRIP"

KEYGRIP=$(gpg -K --with-keygrip --textmode rpm@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')
echo "enter rpm@ password"
$gpgp --verbose --preset "$KEYGRIP"

REMOTE_GPG_SOCKET=$(ssh -o StrictHostKeyChecking=no -i "$EC2_INSTANCE_KEY" ubuntu@"$INSTANCE" gpgbin/remote_gpg_socket)
LOCAL_GPG_SOCKET=$(gpgconf --list-dirs | grep agent-socket | awk -F: '{ print $2 }')

gpg --export -a dev@algorand.com > /tmp/dev.pub
gpg --export -a rpm@algorand.com > /tmp/rpm.pub

scp -o StrictHostKeyChecking=no -i "$EC2_INSTANCE_KEY" -p /tmp/{dev,rpm}.pub ubuntu@"$INSTANCE":~/keys/
ssh -o StrictHostKeyChecking=no -i "$EC2_INSTANCE_KEY" ubuntu@"$INSTANCE" << EOF
    gpg --import keys/dev.pub
    gpg --import keys/rpm.pub
    echo "SIGNING_KEY_ADDR=dev@algorand.com" >> build_env
EOF

ssh -o StrictHostKeyChecking=no -i "$EC2_INSTANCE_KEY" -A -R "$REMOTE_GPG_SOCKET:$LOCAL_GPG_SOCKET" ubuntu@"$INSTANCE"

