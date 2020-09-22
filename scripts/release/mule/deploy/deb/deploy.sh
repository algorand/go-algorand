#!/usr/bin/env bash

set -ex

echo
date "+build_release begin SNAPSHOT stage %Y%m%d_%H%M%S"
echo

ARCH_BIT=$(uname -m)
ARCH_TYPE=$(./scripts/archtype.sh)
OS_TYPE=$(./scripts/ostype.sh)
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
PKG_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
SIGNING_KEY_ADDR=dev@algorand.com

chmod 400 "$HOME/.gnupg"

if ! $USE_CACHE
then
    export ARCH_BIT
    export ARCH_TYPE
    export CHANNEL
    export OS_TYPE
    export VERSION

    mule -f package-deploy.yaml package-deploy-setup-deb
fi

apt-get install aptly -y

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
    "algorand-releases": {
      "region":"us-east-1",
      "bucket":"algorand-releases",
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

SNAPSHOT="${CHANNEL}-${VERSION}"
aptly repo create -distribution="$CHANNEL" -component=main algorand
aptly repo add algorand "$DEBS_DIR"/*.deb
aptly snapshot create "$SNAPSHOT" from repo algorand
aptly publish snapshot -gpg-key="$SIGNING_KEY_ADDR" -origin=Algorand -label=Algorand "$SNAPSHOT" "s3:algorand-releases:"

echo
date "+build_release end SNAPSHOT stage %Y%m%d_%H%M%S"
echo

