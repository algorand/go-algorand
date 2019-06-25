#!/bin/bash
#
# Externally settable env vars:
# GIT_REPO_PATH= something to `git clone` from
# GIT_CHECKOUT_LABEL= something to `git checkout` and build from (branch or tag or hash)
# SIGNING_KEY_ADDR= dev@algorand.com or similar for GPG key

if [ -z "${BUILDTIMESTAMP}" ]; then
    date "+%Y%m%d_%H%M%S" > "${HOME}/buildtimestamp"
    BUILDTIMESTAMP=$(cat "${HOME}/buildtimestamp")
    export BUILDTIMESTAMP
    echo run "${0}" with output to ${HOME}/buildlog_${BUILDTIMESTAMP}
    (bash "${0}" 2>&1) | tee ${HOME}/buildlog_${BUILDTIMESTAMP}
    exit 0
fi

date "+setup start %Y%m%d_%H%M%S"

set -e
set -x

if [ -z "${GIT_REPO_PATH}" ]; then
    GIT_REPO_PATH=git@github.com:algorand/go-algorand.git
fi

if [ -z "${GIT_CHECKOUT_LABEL}" ]; then
    GIT_CHECKOUT_LABEL="rel/stable"
fi

sudo apt-get update
sudo apt-get upgrade -y

if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
fi

mkdir -p ${HOME}/go
mkdir -p ${HOME}/gpgbin

cat <<EOF>${HOME}/gpgbin/remote_gpg_socket
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
gpgconf --list-dirs|grep agent-socket|awk -F: '{ print \$2 }'
EOF
chmod +x ${HOME}/gpgbin/remote_gpg_socket

if [ "${DISTRIB_ID}" = "Ubuntu" ]; then
    if [ "${DISTRIB_RELEASE}" = "16.04" ]; then
	echo "WARNING: Ubuntu 16.04 is DEPRECATED"
	sudo apt-get install -y autoconf awscli docker.io g++ fakeroot git gnupg2 gpgv2 make nfs-common python3 rpm sqlite3 python3-boto3
	cat <<EOF>${HOME}/gpgbin/gpg
#!/bin/bash
exec /usr/bin/gpg2 "\$@"
EOF
	cat <<EOF>${HOME}/gpgbin/gpgv
#!/bin/bash
exec /usr/bin/gpgv2 "\$@"
EOF
	chmod +x ${HOME}/gpgbin/*
    elif [ "${DISTRIB_RELEASE}" = "18.04" ]; then
	sudo apt-get install -y autoconf awscli docker.io git gpg nfs-common python3 rpm sqlite3 python3-boto3
    else
	echo "don't know how to build on Ubuntu ${DISTRIB_RELEASE}"
	exit 1
    fi
else
    echo "don't know how to build non Ubuntu, /etc/lsb-release[DISTRIB_ID]=${DISTRIB_ID}"
    exit 1
fi

export GOPATH=${HOME}/go
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}

# please keep packages sorted

# This real name and email must precisely match GPG key
git config --global user.name "Algorand developers"
git config --global user.email dev@algorand.com

# configure GnuPG to rely on forwarded remote gpg-agent
umask 0077
mkdir -p "${HOME}/.gnupg"
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
mkdir -p ${GOPATH}/src/github.com/algorand
if [ ! -d "${GOPATH}/src/github.com/algorand/go-algorand/.git" ]; then
    (cd ${GOPATH}/src/github.com/algorand && git clone "${GIT_REPO_PATH}" go-algorand)
fi
cd ${GOPATH}/src/github.com/algorand/go-algorand
git checkout "${GIT_CHECKOUT_LABEL}"

gpg --import ${GOPATH}/src/github.com/algorand/go-algorand/installer/rpm/RPM-GPG-KEY-Algorand

# Install latest Go
cd $HOME
# TODO: make a config file in root of repo with single source of truth for Go major-minor version
if [ ! -e /usr/local/go/bin/go ]; then
    python3 ${GOPATH}/src/github.com/algorand/go-algorand/scripts/get_latest_go.py --version-prefix=1.12
    # $HOME will be interpreted by the outer shell to create the string passed to sudo bash
    sudo bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"
fi

cat<<EOF>> "${HOME}/.bashrc"
export EDITOR=vi
EOF

cat<<EOF>> "${HOME}/.profile"
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:\${GOPATH}/bin:/usr/local/go/bin:\${PATH}
EOF

date "+setup finish %Y%m%d_%H%M%S"
