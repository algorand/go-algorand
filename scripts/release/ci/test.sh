#!/usr/bin/env bash
# shellcheck disable=2012
#
# Create and export the fake keys used by the local test repos.

set -ex

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

"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/test/deb/run_ubuntu.sh
date "+build_release done testing ubuntu %Y%m%d_%H%M%S"

"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/test/rpm/run_centos.sh
date "+build_release done testing centos %Y%m%d_%H%M%S"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

