#!/bin/bash
#
# Usage: release_deb.sh *.deb
#
# To run on an ephemeral instance, mount AWS EFS somewhere and use it:
# APTLY_DIR=/large/persistent/filesystem ./release_deb.sh *.deb


set -e
set -x

if [ -z "${APTLY_DIR}" ]; then
    APTLY_DIR=${HOME}/.aptly
fi

if [ -z "${APTLY_S3_NAME}" ]; then
    APTLY_S3_NAME=algorand-releases
fi

cat <<EOF>${HOME}/.aptly.conf
{
  "rootDir": "${APTLY_DIR}",
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

mkdir -p $GOPATH/src/github.com/aptly-dev
if [ ! -d $GOPATH/src/github.com/aptly-dev/aptly ]; then
    git clone https://github.com/aptly-dev/aptly $GOPATH/src/github.com/aptly-dev/aptly
fi
(cd $GOPATH/src/github.com/aptly-dev/aptly && git fetch)
# As of 2019-06-06 release tag v1.3.0 is 2018-May, GnuPG 2 support was added in October but they haven't tagged a new release yet. Hash below seems to work so far.
(cd $GOPATH/src/github.com/aptly-dev/aptly && git checkout e2d6a53de5ee03814b3fe19a8954a09a5c2969b9)
(cd $GOPATH/src/github.com/aptly-dev/aptly && make install)

FIRSTTIME=
if aptly repo create -distribution=stable -component=main algorand; then
   FIRSTTIME=1
fi
aptly repo add algorand "$@"
SNAPSHOT=algorand-$(date +%Y%m%d_%H%M%S)
aptly snapshot create ${SNAPSHOT} from repo algorand
if [ ! -z "${FIRSTTIME}" ]; then
    echo "first publish"
    aptly publish snapshot -origin=Algorand -label=Algorand ${SNAPSHOT} "s3:${APTLY_S3_NAME}:"
else
    echo "publish snapshot ${SNAPSHOT}"
    aptly publish switch stable "s3:${APTLY_S3_NAME}:" ${SNAPSHOT}
fi
