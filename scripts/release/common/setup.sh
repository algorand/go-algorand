#!/usr/bin/env bash

if [ -z "${BUILDTIMESTAMP}" ]; then
    date "+%Y%m%d_%H%M%S" > "${HOME}/buildtimestamp"
    BUILDTIMESTAMP=$(cat "${HOME}/buildtimestamp")
    export BUILDTIMESTAMP
    echo run "${0}" with output to "${HOME}/buildlog_${BUILDTIMESTAMP}"
    (bash "${0}" "${1}" "${2}" 2>&1) | tee "${HOME}/buildlog_${BUILDTIMESTAMP}"
    exit 0
fi

echo
date "+build_release begin SETUP stage %Y%m%d_%H%M%S"
echo

set -ex

GIT_REPO_PATH=https://github.com/algorand/go-algorand
BRANCH=${1:-"master"}
export BRANCH
CHANNEL=${2:-"stable"}
export CHANNEL
RELEASE="$3"
export RELEASE
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -q
sudo apt-get upgrade -q -y
sudo apt-get install -y build-essential automake autoconf awscli docker.io git gpg nfs-common python3 rpm sqlite3 python3-boto3 g++ libtool rng-tools
sudo rngd -r /dev/urandom

#umask 0077
mkdir -p "${HOME}"/{.gnupg,dummyaptly,dummyrepo,go,gpgbin,keys,node_pkg,prodrepo}
mkdir -p "${HOME}"/go/bin

# Check out
mkdir -p "${HOME}/go/src/github.com/algorand"
cd "${HOME}/go/src/github.com/algorand" && git clone --single-branch --branch "${BRANCH}" "${GIT_REPO_PATH}" go-algorand
# TODO: if we are checking out a release tag, `git tag --verify` it

# Install latest Go
cd "${HOME}"
python3 "${HOME}/go/src/github.com/algorand/go-algorand/scripts/get_latest_go.py" --version-prefix=1.12
# $HOME will be interpreted by the outer shell to create the string passed to sudo bash
sudo bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"

GOPATH=$(/usr/local/go/bin/go env GOPATH)
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
export GOPATH

cat <<EOF>"${HOME}/gpgbin/remote_gpg_socket"
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
gpgconf --list-dirs | grep agent-socket | awk -F: '{ print \$2 }'
EOF

chmod +x "${HOME}/gpgbin/remote_gpg_socket"

# This real name and email must precisely match GPG key
git config --global user.name "Algorand developers"
git config --global user.email dev@algorand.com

# configure GnuPG to rely on forwarded remote gpg-agent
umask 0077
touch "${HOME}/.gnupg/gpg.conf"
if grep -q no-autostart "${HOME}/.gnupg/gpg.conf"; then
    echo ""
else
    echo "no-autostart" >> "${HOME}/.gnupg/gpg.conf"
fi

if [ -f "${HOME}/key.gpg" ]; then
    gpg --import "${HOME}/key.gpg"
fi
# we had a tight umask for gpg setup, but need wider for git clone below
umask 0002

# allow ssh to clobber unix domain sockets for gpg-agent forwarding
if grep -q ^StreamLocalBindUnlink /etc/ssh/sshd_config; then
    echo already have StreamLocalBindUnlink sshd config
else
    sudo bash -c "echo 'StreamLocalBindUnlink yes' >> /etc/ssh/sshd_config"
    sudo systemctl restart sshd
fi

sudo usermod -a -G docker ubuntu
sg docker "docker pull centos:7"
sg docker "docker pull ubuntu:18.04"

cat<<EOF>> "${HOME}/.bashrc"
export EDITOR=vi
EOF

cat<<EOF>> "${HOME}/.profile"
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:\${GOPATH}/bin:/usr/local/go/bin:\${PATH}
EOF

# Install aptly for building debian repo
mkdir -p "$GOPATH/src/github.com/aptly-dev"
cd "$GOPATH/src/github.com/aptly-dev"
git clone https://github.com/aptly-dev/aptly
cd aptly && git fetch

# As of 2019-06-06 release tag v1.3.0 is 2018-May, GnuPG 2 support was added in October but they haven't tagged a new release yet. Hash below seems to work so far.
# 2019-07-06 v1.4.0
git checkout v1.4.0
make install

# a bash user might `source build_env` to manually continue a broken build
cat <<EOF>>"${HOME}"/build_env
CHANNEL=${CHANNEL}
DC_IP=$(curl --silent http://169.254.169.254/latest/meta-data/local-ipv4)
FULLVERSION=${RELEASE}
EOF

echo
date "+build_release end SETUP stage %Y%m%d_%H%M%S"
echo

