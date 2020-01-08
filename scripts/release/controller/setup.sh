#!/usr/bin/env bash

if [ -z "${BUILDTIMESTAMP}" ]; then
    date "+%Y%m%d_%H%M%S" > "${HOME}/buildtimestamp"
    BUILDTIMESTAMP=$(cat "${HOME}/buildtimestamp")
    export BUILDTIMESTAMP
    echo run "${0}" with output to "${HOME}/buildlog_${BUILDTIMESTAMP}"
    (bash "${0}" "${1}" "${2}" 2>&1) | tee "${HOME}/buildlog_${BUILDTIMESTAMP}"
    exit 0
fi

date "+setup start %Y%m%d_%H%M%S"

set -ex

GIT_REPO_PATH=https://github.com/btoll/go-algorand
TAG=${1:-"rel/stable"}
export TAG
CHANNEL=${1:-"stable"}
export CHANNEL
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -q
sudo apt-get upgrade -q -y

#umask 0077
mkdir -p "${HOME}"/{.gnupg,go,gpgbin,dummyaptly,dummyrepo,prodrepo}

# Check out
mkdir -p "${HOME}/go/src/github.com/algorand"
cd "${HOME}/go/src/github.com/algorand" && git clone --single-branch --branch "${TAG}" "${GIT_REPO_PATH}" go-algorand
# TODO: if we are checking out a release tag, `git tag --verify` it

# Install latest Go
# TODO: make a config file in root of repo with single source of truth for Go major-minor version
cd "${HOME}"
python3 "${HOME}/go/src/github.com/algorand/go-algorand/scripts/get_latest_go.py" --version-prefix=1.12
# $HOME will be interpreted by the outer shell to create the string passed to sudo bash
sudo bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"

GOPATH=${HOME}/go
export GOPATH
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}

cat <<EOF>"${HOME}/gpgbin/remote_gpg_socket"
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
gpgconf --list-dirs | grep agent-socket | awk -F: '{ print \$2 }'
EOF

chmod +x "${HOME}/gpgbin/remote_gpg_socket"

sudo apt-get update
sudo apt-get install -y build-essential automake autoconf awscli docker.io git gpg nfs-common python3 rpm sqlite3 python3-boto3 g++ libtool rng-tools

sudo rngd -r /dev/urandom

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
sg docker "docker pull ubuntu:16.04"

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

gpgconf --launch gpg-agent

REPO_PATH="${HOME}/go/src/github.com/algorand/go-algorand"
export RELEASE_GENESIS_PROCESS=true
PLATFORM=$("${REPO_PATH}"/scripts/osarchtype.sh)
PLATFORM_SPLIT=(${PLATFORM//\// })
OS=${PLATFORM_SPLIT[0]}
ARCH=${PLATFORM_SPLIT[1]}
DEFAULTNETWORK=$("${REPO_PATH}"/scripts/compute_branch_network.sh)
export DEFAULTNETWORK
export PKG_ROOT=${HOME}/node_pkg
export VARIATIONS="base"
FULLVERSION=$("${REPO_PATH}"/scripts/compute_build_number.sh -f)
export FULLVERSION

# Update version file for this build
if [ ! -z "${BUILD_NUMBER}" ]; then
    echo "using externally set BUILD_NUMBER=${BUILD_NUMBER} without incrementing"
else
    if [ -e buildnumber.dat ]; then
	BUILD_NUMBER=$(cat ./buildnumber.dat)
	BUILD_NUMBER=$(( BUILD_NUMBER + 1 ))
    else
	BUILD_NUMBER=0
    fi
    echo ${BUILD_NUMBER} > ./buildnumber.dat
    git add -A
    git commit -m "Build ${BUILD_NUMBER}"
fi

# What's my default IP address?
# get the datacenter IP address for this EC2 host.
# this might equivalently be gotten from `netstat -rn` and `ifconfig -a`
DC_IP=$(curl --silent http://169.254.169.254/latest/meta-data/local-ipv4)
if [ -z "${DC_IP}" ]; then
    echo "ERROR: need DC_IP to be set to your local (but not localhost) IP"
    exit 1
fi

# a bash user might `source build_env` to manually continue a broken build
cat <<EOF>"${HOME}"/build_env
export RELEASE_GENESIS_PROCESS=${RELEASE_GENESIS_PROCESS}
PLATFORM=${PLATFORM}
OS=${OS}
ARCH=${ARCH}
export CHANNEL=${CHANNEL}
export DEFAULTNETWORK=${DEFAULTNETWORK}
export PKG_ROOT=${PKG_ROOT}
export VARIATIONS=${VARIATIONS}
BUILD_NUMBER=${BUILD_NUMBER}
export FULLVERSION=${FULLVERSION}
DC_IP=${DC_IP}
EOF

date "+setup finish %Y%m%d_%H%M%S"

