#!/usr/bin/env bash

set -ex

if [ -z "${BUILDTIMESTAMP}" ]; then
    date "+%Y%m%d_%H%M%S" > "${HOME}/buildtimestamp"
    BUILDTIMESTAMP=$(cat "${HOME}/buildtimestamp")
    export BUILDTIMESTAMP
    echo run "${0}" with output to "${HOME}/buildlog_${BUILDTIMESTAMP}"
    bash "${0}" "${1}" 2>&1 | tee "${HOME}/buildlog_${BUILDTIMESTAMP}"
    # http://tldp.org/LDP/abs/html/internalvariables.html#PIPESTATUSREF
    exit "${PIPESTATUS[0]}"
fi

echo
date "+build_release begin SETUP stage %Y%m%d_%H%M%S"
echo

# `apt-get` fails randomly when downloading package, this is a hack that "works" reasonably well.
echo -e "deb http://us.archive.ubuntu.com/ubuntu/ bionic main universe multiverse\ndeb http://archive.ubuntu.com/ubuntu/ bionic main universe multiverse" | sudo tee /etc/apt/sources.list.d/ubuntu

sudo apt-get update
sudo apt-get upgrade -y

# `apt-get` fails randomly when downloading package, this is a hack that "works" reasonably well.
sudo apt-get update

sudo apt-get install -y build-essential automake autoconf awscli docker.io git gpg nfs-common python python3 rpm sqlite3 python3-boto3 g++ libtool rng-tools
sudo rngd -r /dev/urandom

#umask 0077
mkdir -p "${HOME}"/{.gnupg,dummyaptly,dummyrepo,go,gpgbin,keys,node_pkg,prodrepo}
mkdir -p "${HOME}"/go/bin

BRANCH=${1:-"master"}
export BRANCH

# Check out
mkdir -p "${HOME}/go/src/github.com/algorand"
cd "${HOME}/go/src/github.com/algorand"
if ! git clone --single-branch --branch "${BRANCH}" https://github.com/algorand/go-algorand go-algorand
then
    echo There has been a problem cloning the "$BRANCH" branch.
    exit 1
fi

cd go-algorand
COMMIT_HASH=$(git rev-parse "${BRANCH}")

export DEBIAN_FRONTEND=noninteractive

if ! ./scripts/check_golang_version.sh
then
    exit 1
fi
# Get the go build version.
GOLANG_VERSION=$(./scripts/get_golang_version.sh)

cd "${HOME}"
if ! curl -O "https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz"
then
    echo Golang could not be installed!
    exit 1
fi
sudo bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"

GOPATH=$(/usr/local/go/bin/go env GOPATH)
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
export GOPATH

cat << EOF > "${HOME}/gpgbin/remote_gpg_socket"
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

cat << EOF >> "${HOME}/.bashrc"
export EDITOR=vi
EOF

cat << EOF >> "${HOME}/.profile"
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:\${GOPATH}/bin:/usr/local/go/bin:\${PATH}
EOF

# Install aptly for building debian repo
mkdir -p "$GOPATH/src/github.com/aptly-dev"
cd "$GOPATH/src/github.com/aptly-dev"
if ! git clone https://github.com/aptly-dev/aptly
then
    echo There has been a problem cloning the aptly project.
    exit 1
fi
cd aptly && git fetch

# As of 2019-06-06 release tag v1.3.0 is 2018-May, GnuPG 2 support was added in October but they haven't tagged a new release yet. Hash below seems to work so far.
# 2019-07-06 v1.4.0
git checkout v1.4.0
make install

REPO_ROOT="${GOPATH}"/src/github.com/algorand/go-algorand
PLATFORM=$("${REPO_ROOT}"/scripts/osarchtype.sh)
PLATFORM_SPLIT=(${PLATFORM//\// })

CHANNEL=${CHANNEL:-$("${GOPATH}"/src/github.com/algorand/go-algorand/scripts/compute_branch_channel.sh "$BRANCH")}

# a bash user might `source build_env` to manually continue a broken build
cat << EOF > "${HOME}"/build_env
export BRANCH=${BRANCH}
export CHANNEL=${CHANNEL}
export COMMIT_HASH=${COMMIT_HASH}
export DEFAULTNETWORK=$(PATH=${PATH} "${REPO_ROOT}"/scripts/compute_branch_network.sh)
export DC_IP=$(curl --silent http://169.254.169.254/latest/meta-data/local-ipv4)
export FULLVERSION=$("${GOPATH}"/src/github.com/algorand/go-algorand/scripts/compute_build_number.sh -f)
export PKG_ROOT=${HOME}/node_pkg
export PLATFORM=${PLATFORM}
export OS=${PLATFORM_SPLIT[0]}
export ARCH=${PLATFORM_SPLIT[1]}
export REPO_ROOT=${REPO_ROOT}
export RELEASE_GENESIS_PROCESS=true
export VARIATIONS=base
export ALGORAND_PACKAGE_NAME=$("${GOPATH}"/src/github.com/algorand/go-algorand/scripts/compute_package_name.sh "${CHANNEL:-stable}")
export DEVTOOLS_PACKAGE_NAME=$("${GOPATH}"/src/github.com/algorand/go-algorand/scripts/compute_package_name.sh "${CHANNEL:-stable}" algorand-devtools)
EOF

# strip leading 'export ' for docker --env-file
sed 's/^export //g' < "${HOME}"/build_env > "${HOME}"/build_env_docker

echo
date "+build_release end SETUP stage %Y%m%d_%H%M%S"
echo

