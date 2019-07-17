#!/bin/bash
set -x
set -v

echo "starting local apt repo setup"

HOME=/Users/ericgieseke/GolandProjects/src/github.com/algorand/go-algorand
WORKING_DIR=${HOME}/test/e2e-go/debian

rm -rf ${WORKING_DIR}/dummyaptly
mkdir -p ${WORKING_DIR}/dummyaptly
cat <<EOF>${WORKING_DIR}/dummyaptly.conf
{
  "rootDir": "${WORKING_DIR}/dummyaptly",
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
  "S3PublishEndpoints": {},
  "SwiftPublishEndpoints": {}
}
EOF

aptly -config=${WORKING_DIR}/dummyaptly.conf repo create -distribution=stable -component=main algodummy
aptly -config=${WORKING_DIR}/dummyaptly.conf repo add algodummy ${HOME}/node_pkg/*.deb
SNAPSHOT=algodummy-$(date +%Y%m%d_%H%M%S)
aptly -config=${WORKING_DIR}/dummyaptly.conf snapshot create ${SNAPSHOT} from repo algodummy
aptly -config=${WORKING_DIR}/dummyaptly.conf publish snapshot -origin=Algorand -label=Algorand ${SNAPSHOT}

echo "local apt repo setup completed successfully"

