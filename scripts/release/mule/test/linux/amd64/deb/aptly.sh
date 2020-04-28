#!/usr/bin/env bash

set -ex

cat <<EOF>"$HOME/dummyaptly.conf"
{
  "rootDir": "$HOME/dummyaptly",
  "downloadConcurrency": 4,
  "downloadSpeedLimit": 0,
  "architectures": [],
  "dependencyFollowSuggests": false,
  "dependencyFollowRecommends": false,
  "dependencyFollowAllVariants": false,
  "dependencyFollowSource": false,
  "dependencyVerboseResolve": false,
  "gpgDisableSign": true,
  "gpgDisableVerify": true,
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

# Creates ~/dummyaptly/db
aptly -config="$HOME"/dummyaptly.conf repo create -distribution=stable -component=main algodummy
# Creates ~/dummyaptly/pool
aptly -config="$HOME"/dummyaptly.conf repo add algodummy "$WORKDIR/pkg"/*.deb
SNAPSHOT=algodummy-$(date +%Y%m%d_%H%M%S)
aptly -config="$HOME"/dummyaptly.conf snapshot create "$SNAPSHOT" from repo algodummy
# Creates ~/dummyaptly/public
aptly -config="$HOME"/dummyaptly.conf publish snapshot -origin=Algorand -label=Algorand "$SNAPSHOT"

# TODO: use `aptly serve`?
pushd "$HOME"/dummyaptly/public
#python3 "$MULE_TEST_DIR/util/httpd.py --pid $MULE_TEST_DIR/phttpd.pid" &
python3 "$MULE_TEST_DIR/util/httpd.py" &
popd
#trap '$MULE_TEST_DIR/util/kill_httpd.sh' 0

"$DEB_DIR/test/algorand.sh"
expect -d "$DEB_DIR/test/algorand.exp" /var/lib/algorand "$WORKDIR/test/testdata" "$WORKDIR/test/e2e-go/cli/goal/expect"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

