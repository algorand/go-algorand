#!/usr/bin/env bash
# shellcheck disable=2012

set -x

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

GNUPGHOME="${HOME}"/.gnupg
gpgconf --kill gpg-agent
chmod 700 "${GNUPGHOME}"

cat > "${GNUPGHOME}"/keygenscript <<EOF
Key-Type: default
Subkey-Type: default
Name-Real: Algorand developers
Name-Email: dev@algorand.com
Expire-Date: 0
Passphrase: foogorand
%transient-key
EOF

cat > "${GNUPGHOME}"/rpmkeygenscript <<EOF
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
# Only needed for gpg < 2.1.17 (https://wiki.gnupg.org/AgentForwarding)
#extra-socket "${HOME}"/S.gpg-agent.extra
# Enable unattended daemon mode.
allow-preset-passphrase
# Cache password 30 days.
default-cache-ttl 2592000
max-cache-ttl 2592000
EOF

# Added 2020-01-20
gpgconf --launch gpg-agent

gpg --gen-key --batch "${GNUPGHOME}"/keygenscript
gpg --gen-key --batch "${GNUPGHOME}"/rpmkeygenscript
gpg --export -a dev@algorand.com > "${HOME}/keys/dev.pub"
gpg --export -a rpm@algorand.com > "${HOME}/keys/rpm.pub"

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

"${HOME}"/ben-branch/scripts/release/test/deb/run_ubuntu.sh

date "+build_release done building ubuntu %Y%m%d_%H%M%S"

# Run RPM build in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < ${HOME}/ben-branch/scripts/release/rpm/centos-build.Dockerfile"

cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF

sg docker "docker run --rm --env-file ${HOME}/build_env --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/root/S.gpg-agent --mount type=bind,src=${HOME}/dummyrepo,dst=/root/dummyrepo --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/ben-branch/scripts/release/test/rpm/run_centos.sh"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

