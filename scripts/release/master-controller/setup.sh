#!/usr/bin/env bash
#
# Externally settable env vars:
# GIT_REPO_PATH= something to `git clone` from
# GIT_CHECKOUT_LABEL= something to `git checkout` and build from (branch or tag or hash)

if [ -z "${BUILDTIMESTAMP}" ]; then
    date "+%Y%m%d_%H%M%S" > "${HOME}/buildtimestamp"
    BUILDTIMESTAMP=$(cat "${HOME}/buildtimestamp")
    export BUILDTIMESTAMP
    echo run "${0}" with output to "${HOME}/buildlog_${BUILDTIMESTAMP}"
    (bash "${0}" 2>&1) | tee "${HOME}/buildlog_${BUILDTIMESTAMP}"
    exit 0
fi

date "+setup start %Y%m%d_%H%M%S"

set -ex

if [ -z "${GIT_REPO_PATH}" ]; then
    GIT_REPO_PATH=https://github.com/btoll/go-algorand
fi

if [ -z "${GIT_CHECKOUT_LABEL}" ]; then
    GIT_CHECKOUT_LABEL="rel/stable"
fi

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -q
sudo apt-get upgrade -q -y

# Some of these dirs aren't used until later scripts.
#umask 0077
#mkdir -p ~/.gnupg
#mkdir -p "${HOME}"/{.gnupg,go,gpgbin,docker_test_resources,dummyaptly,dummyrepo,prodrepo}
mkdir -p "${HOME}"/{.gnupg,go,gpgbin,dummyaptly,dummyrepo,prodrepo}

export GOPATH=${HOME}/go
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}

cat <<EOF>"${HOME}/gpgbin/remote_gpg_socket"
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
gpgconf --list-dirs|grep agent-socket|awk -F: '{ print \$2 }'
EOF

chmod +x "${HOME}/gpgbin/remote_gpg_socket"

sudo apt-get update
sudo apt-get install -y build-essential automake autoconf awscli docker.io git gpg nfs-common python3 rpm sqlite3 python3-boto3 g++ libtool rng-tools

sudo rngd -r /dev/urandom

# please keep packages sorted

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

# Check out
mkdir -p "${GOPATH}/src/github.com/algorand"
cd "${GOPATH}/src/github.com/algorand" && git clone --single-branch --branch build_release "${GIT_REPO_PATH}" go-algorand #cd go-algorand
#git checkout "${GIT_CHECKOUT_LABEL}"
# TODO: if we are checking out a release tag, `git tag --verify` it

gpg --import "${GOPATH}/src/github.com/algorand/go-algorand/installer/rpm/RPM-GPG-KEY-Algorand"

# Install latest Go
cd "$HOME"
# TODO: make a config file in root of repo with single source of truth for Go major-minor version
python3 "${GOPATH}/src/github.com/algorand/go-algorand/scripts/get_latest_go.py" --version-prefix=1.12
# $HOME will be interpreted by the outer shell to create the string passed to sudo bash
sudo bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"

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

date "+setup finish %Y%m%d_%H%M%S"

