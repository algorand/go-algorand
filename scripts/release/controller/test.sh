#!/usr/bin/env bash
# shellcheck disable=2012

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

REPO_ROOT=/home/ubuntu/go/src/github.com/algorand/go-algorand/

export GNUPGHOME=${HOME}/tkey
gpgconf --kill gpg-agent
chmod 700 "${GNUPGHOME}"

cat > "${GNUPGHOME}"/keygenscript<<EOF
Key-Type: default
Subkey-Type: default
Name-Real: Algorand developers
Name-Email: dev@algorand.com
Expire-Date: 0
Passphrase: foogorand
%transient-key
EOF

cat > "${GNUPGHOME}"/rpmkeygenscript<<EOF
Key-Type: default
Subkey-Type: default
Name-Real: Algorand RPM
Name-Email: rpm@algorand.com
Expire-Date: 0
Passphrase: foogorand
%transient-key
EOF

# https://stackoverflow.com/a/49491997
cat <<EOF> "${GNUPGHOME}"/gpg-agent.conf
extra-socket "${GNUPGHOME}"/S.gpg-agent.extra
# Enable unattended daemon mode.
allow-preset-passphrase
# Cache password 30 days.
default-cache-ttl 2592000
max-cache-ttl 2592000
EOF

gpg --gen-key --batch "${GNUPGHOME}"/keygenscript
gpg --gen-key --batch "${GNUPGHOME}"/rpmkeygenscript
gpg --export -a dev@algorand.com > "${HOME}/docker_test_resources/key.pub"
gpg --export -a rpm@algorand.com > "${HOME}/docker_test_resources/rpm.pub"

gpgconf --kill gpg-agent
gpgconf --launch gpg-agent

gpgp=$(ls /usr/lib/gnupg{2,,1}/gpg-preset-passphrase | head -1)
for name in {dev,rpm}
do
    KEYGRIP=$(gpg -K --with-keygrip --textmode "$name"@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')
    echo foogorand | "${gpgp}" --verbose --preset "${KEYGRIP}"
done

cat <<EOF>"${HOME}"/dummyaptly.conf
{
  "rootDir": "${HOME}/dummyaptly",
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

# Creates ~/dummyaptly/db
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf repo create -distribution=stable -component=main algodummy
# Creates ~/dummyaptly/pool
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf repo add algodummy "${HOME}"/node_pkg/*.deb
SNAPSHOT=algodummy-$(date +%Y%m%d_%H%M%S)
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf snapshot create "${SNAPSHOT}" from repo algodummy
# Creates ~/dummyaptly/public
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf publish snapshot -origin=Algorand -label=Algorand "${SNAPSHOT}"

"${REPO_ROOT}"/scripts/release/helper/run_ubuntu_build_test.sh

date "+build_release done building ubuntu %Y%m%d_%H%M%S"

# Run RPM build in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < ${REPO_ROOT}/scripts/release/helper/centos-build.Dockerfile"

cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/S.gpg-agent --mount type=bind,src=${HOME}/dummyrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/docker_test_resources,dst=/root/stuff --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/helper/build_release_centos_docker.sh"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

