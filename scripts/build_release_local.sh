#!/bin/bash
#
# This is a file of commands to copy and paste to run build_release.sh on an AWS EC2 instance.
# Should work on Ubuntu 16.04 ro 18.04
#
# Externally settable env vars:
# S3_PREFIX_BUILDLOG= where upload build log (no trailing /)

echo "this is a file of commands to copy and paste to run build_release.sh on an AWS EC2 instance"
exit 1

# use AWS console to create a new t3.large with the latest official Ubuntu 18.04

# ec2 public address here:
TARGET=

cd ${GOPATH}/src/github.com/algorand/go-algorand

git fetch
git checkout rel/stable
git merge origin/rel/stable
scp -p ${GOPATH}/src/github.com/algorand/go-algorand/scripts/build_release_setup.sh ubuntu@${TARGET}:~/

# upload the latest public key
GTMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
gpg --export --armor -o "${GTMPDIR}/key.gpg" dev@algorand.com
scp -p "${GTMPDIR}/key.gpg" "ubuntu@${TARGET}:~/key.gpg"
rm -rf ${GTMPDIR}

ssh -A ubuntu@${TARGET} bash build_release_setup.sh

# setup GPG key forwarding https://wiki.gnupg.org/AgentForwarding
umask 0077
mkdir -p ${HOME}/.gnupg
touch ${HOME}/.gnupg/gpg-agent.conf
if grep -q extra-socket ${HOME}/.gnupg/gpg-agent.conf; then
    echo "already have extra-socket"
else
    cat <<EOF>>${HOME}/.gnupg/gpg-agent.conf
extra-socket ${HOME}/.gnupg/S.gpg-agent.extra
default-cache-ttl 3600
EOF
fi
umask 0002

# this will require your key password, and export a private key file protected by the same password

# warm up your local gpg-agent
gpg -u dev@algorand.com --clearsign
type some stuff
^D

gpg -u rpm@algorand.com --clearsign


# TODO: use simpler expression when we can rely on gpg 2.2 on ubuntu >= 18.04
#REMOTE_GPG_SOCKET=$(ssh ubuntu@${TARGET} gpgconf --list-dir agent-socket)
#REMOTE_GPG_SOCKET=$(ssh ubuntu@${TARGET} "gpgconf --list-dirs|grep agent-socket|awk -F: '{ print \$2 }'")
REMOTE_GPG_SOCKET=$(ssh ubuntu@${TARGET} gpgbin/remote_gpg_socket)
LOCAL_GPG_SOCKET=$(gpgconf --list-dir agent-extra-socket)
ssh -A -R "${REMOTE_GPG_SOCKET}:${LOCAL_GPG_SOCKET}" ubuntu@${TARGET}

# check gpg agent connection
gpg -u dev@algorand.com --clearsign
blah blah
^D


# set AWS credentials so we can upload to S3 and connect to EFS
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=

# where we store persistent scratch space for aptly
export AWS_EFS_MOUNT=

# build_release.sh needs to be run in a terminal with a human watching
# to be prompted for GPG key password at a couple points.
# It can still steal the outer terminal from within piping the output to tee. Nifty, huh?
BUILDTIMESTAMP=$(cat "${HOME}/buildtimestamp")
(bash "${HOME}/go/src/github.com/algorand/go-algorand/scripts/build_release.sh" 2>&1)|tee -a "${HOME}/buildlog_${BUILDTIMESTAMP}"
(bash "${HOME}/go/src/github.com/algorand/go-algorand/scripts/build_release_sign.sh" 2>&1)|tee -a "${HOME}/buildlog_${BUILDTIMESTAMP}"
(bash "${HOME}/go/src/github.com/algorand/go-algorand/scripts/build_release_upload.sh" 2>&1)|tee -a "${HOME}/buildlog_${BUILDTIMESTAMP}"
if [ -f "${HOME}/rstamp" ]; then
    . "${HOME}/rstamp"
fi
if [ -z "${RSTAMP}" ]; then
    RSTAMP=$(${HOME}/go/src/github.com/algorand/go-algorand/scripts/reverse_hex_timestamp)
fi
if [ -z "${RSTAMP}" ]; then
    echo "could not figure out RSTAMP, script must have failed early"
    exit 1
fi
gzip "${HOME}/buildlog_${BUILDTIMESTAMP}"
if [ ! -z "${S3_PREFIX_BUILDLOG}" ]; then
    aws s3 cp "${HOME}/buildlog_${BUILDTIMESTAMP}.gz" "${S3_PREFIX_BUILDLOG}/${RSTAMP}/buildlog_${BUILDTIMESTAMP}.gz"
fi
