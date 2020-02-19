#!/usr/bin/env bash

set -ex

cat <<EOF>"${HOME}"/.aptly.conf
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

#  "S3PublishEndpoints": {
#    "algorand-releases": {
#      "region":"us-east-1",
#      "bucket":"algorand-releases",
#      "acl":"public-read",
#      "prefix":"deb"
#    },
#    "algorand-dev-deb-repo": {
#      "region":"us-east-1",
#      "bucket":"algorand-dev-deb-repo",
#      "acl":"public-read",
#      "prefix":"deb"
#    }
#  },

# Creates ~/aptly/db
"$HOME"/go/bin/aptly -config="${HOME}"/.aptly.conf repo create -distribution=stable -component=main algorand
# Creates ~/aptly/pool
"$HOME"/go/bin/aptly -config="${HOME}"/.aptly.conf repo add algorand "${HOME}"/node_pkg/*.deb
SNAPSHOT=algorand-$(date +%Y%m%d_%H%M%S)
"$HOME"/go/bin/aptly -config="${HOME}"/.aptly.conf snapshot create "${SNAPSHOT}" from repo algorand
# Creates ~/aptly/public
"$HOME"/go/bin/aptly -config="${HOME}"/.aptly.conf publish snapshot -gpg-key=dev@algorand.com -origin=Algorand -label=Algorand "${SNAPSHOT}" "s3:ben-test-2.0.3:"

