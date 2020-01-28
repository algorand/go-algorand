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
    "algorand-internal": {
      "region":"us-east-1",
      "bucket":"algorand-internal",
      "acl":"public-read",
      "prefix":"ben"
    }
  },
  "SwiftPublishEndpoints": {}
}
EOF

#      "bucket":"algorand-releases",

FIRSTTIME=
if "${HOME}"/go/bin/aptly repo create -distribution=stable -component=main algorand; then
   FIRSTTIME=1
fi
#"${HOME}"/go/bin/aptly repo add algorand "$@"
"${HOME}"/go/bin/aptly repo add algorand "${HOME}"/node_pkg/*.deb
SNAPSHOT=algorand-$(date +%Y%m%d_%H%M%S)
"${HOME}"/go/bin/aptly snapshot create "${SNAPSHOT}" from repo algorand
if [ ! -z "${FIRSTTIME}" ]; then
    echo "first publish"
    "${HOME}"/go/bin/aptly publish snapshot -origin=Algorand -label=Algorand "${SNAPSHOT}" "s3:${APTLY_S3_NAME}:"
else
    echo "publish snapshot ${SNAPSHOT}"
    "${HOME}"/go/bin/aptly publish switch stable "s3:${APTLY_S3_NAME}:" "${SNAPSHOT}"
fi

