#!/usr/bin/env bash

set -ex

WORKDIR="$6"

if [ -z "$WORKDIR" ]
then
    echo "WORKDIR variable must be defined."
    exit 1
fi

echo
date "+build_release begin SNAPSHOT stage %Y%m%d_%H%M%S"
echo

OS_TYPE="$1"
ARCH_TYPE="$2"
ARCH_BIT="$3"
VERSION=${VERSION:-$4}
#PKG_TYPE="$5"

BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
CHANNEL=${CHANNEL:-$("$WORKDIR/scripts/compute_branch_channel.sh" "$BRANCH")}
PKG_DIR="$WORKDIR/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
SIGNING_KEY_ADDR=dev@algorand.com

chmod 400 "$HOME/.gnupg"
#ls -al "$HOME/.gnupg"
#gpg --import < "$HOME/keys/signingkey.gpg"
#ls -al "$HOME/.gnupg"
echo wat | gpg -u "$SIGNING_KEY_ADDR" --clearsign
#gpg --version

if ! $USE_CACHE
then
    export ARCH_BIT
    export ARCH_TYPE
    export CHANNEL
    export OS_TYPE
    export VERSION

    mule -f package-deploy.yaml package-deploy-setup-deb
fi

apt-get install aptly gnupg2 -y

cat <<EOF>"${HOME}/.aptly.conf"
{
  "rootDir": "${HOME}/aptly",
  "downloadConcurrency": 4,
  "downloadSpeedLimit": 0,
  "architectures": [],
  "dependencyFollowSuggests": false,
  "dependencyFollowRecommends": false,
  "dependencyFollowAllVariants": false,
  "dependencyFollowSource": false,
  "dependencyVerboseResolve": false,
  "gpgDisableSign": false,
  "gpgDisableVerify": false,
  "gpgProvider": "gpg",
  "downloadSourcePackages": false,
  "skipLegacyPool": true,
  "ppaDistributorID": "ubuntu",
  "ppaCodename": "",
  "skipContentsPublishing": false,
  "FileSystemPublishEndpoints": {},
  "S3PublishEndpoints": {
    "ben-test-2.0.3": {
      "region":"us-east-1",
      "bucket":"ben-test-2.0.3",
      "acl":"public-read",
      "prefix":"deb"
    }
  },
  "SwiftPublishEndpoints": {}
}
EOF

DEBS_DIR="$HOME/packages/deb/$CHANNEL"
DEB="algorand_${CHANNEL}_linux-amd64_${VERSION}.deb"

cp "$PKG_DIR/$DEB" "$DEBS_DIR"

#SNAPSHOT="${CHANNEL}-${VERSION}"
SNAPSHOT=derp
aptly repo create -distribution="$CHANNEL" -component=main algorand
aptly repo add algorand "$DEBS_DIR"/*.deb
aptly snapshot create "$SNAPSHOT" from repo algorand
aptly publish snapshot -gpg-key="$SIGNING_KEY_ADDR" -origin=Algorand -label=Algorand "$SNAPSHOT" "s3:ben-test-2.0.3:"

echo
date "+build_release end SNAPSHOT stage %Y%m%d_%H%M%S"
echo

