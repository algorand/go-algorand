#!/usr/bin/env bash
# shellcheck disable=2012

set -ex

echo
date "+build_release begin GPG SETUP stage %Y%m%d_%H%M%S"
echo

cat <<EOF>"${HOME}/gpgbin/remote_gpg_socket"
export GOPATH=\${HOME}/go
export PATH=\${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
gpgconf --list-dirs | grep agent-socket | awk -F: '{ print \$2 }'
EOF

chmod +x "${HOME}/gpgbin/remote_gpg_socket"

# This real name and email must precisely match GPG key
git config --global user.name "Algorand developers"
git config --global user.email dev@algorand.com

# configure GnuPG to rely on forwarded remote gpg-agent
umask 0077
touch "${HOME}/.gnupg/gpg.conf"
if grep -q no-autostart "${HOME}/.gnupg/gpg.conf"; then
    echo ""
else
    echo "no-autostart" >> "${HOME}/.gnupg/gpg.conf"
fi

umask 0002

gpgconf --launch gpg-agent

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

echo
date "+build_release end GPG SETUP stage %Y%m%d_%H%M%S"
echo

