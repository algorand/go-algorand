#!/usr/bin/env bash
#
# Usage: release_deb.sh *.deb
#
# To run on an ephemeral instance, mount AWS EFS somewhere and use it:
# APTLY_DIR=/large/persistent/filesystem ./release_deb.sh *.deb

set -ex

if [ -z "${APTLY_DIR}" ]; then
    APTLY_DIR=${HOME}/.aptly
fi

if [ -z "${APTLY_S3_NAME}" ]; then
    APTLY_S3_NAME=algorand-builds
fi

cat <<EOF>"${HOME}"/.aptly.conf
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
      "bucket":"ben-test-release-bucket",
      "acl":"public-read",
      "prefix":"deb"
    }
  },
  "SwiftPublishEndpoints": {}
}
EOF

#      "bucket":"algorand-releases",

FIRSTTIME=
if aptly repo create -distribution=stable -component=main algorand; then
   FIRSTTIME=1
fi
aptly repo add algorand "$@"
SNAPSHOT=algorand-$(date +%Y%m%d_%H%M%S)
aptly snapshot create "${SNAPSHOT}" from repo algorand
if [ ! -z "${FIRSTTIME}" ]; then
    echo "first publish"
    aptly publish snapshot -origin=Algorand -label=Algorand "${SNAPSHOT}" "s3:${APTLY_S3_NAME}:"
else
    echo "publish snapshot ${SNAPSHOT}"
    aptly publish switch stable "s3:${APTLY_S3_NAME}:" "${SNAPSHOT}"
fi

