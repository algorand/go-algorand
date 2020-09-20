#!/usr/bin/env bash
# shellcheck disable=2012
# sign centos rpm from inside docker

set -ex

export HOME=/root
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"

cd "$HOME" && tar jxf /root/subhome/gnupg*.tar.bz2

export PATH="$HOME/gnupg2/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/gnupg2/lib"

umask 0077
mkdir -p ~/.gnupg
umask 0022

touch "$HOME/.gnupg/gpg.conf"
if grep -q no-autostart "$HOME/.gnupg/gpg.conf"; then
    echo
else
    echo "no-autostart" >> "$HOME/.gnupg/gpg.conf"
fi
rm -f $HOME/.gnupg/S.gpg-agent
(cd ~/.gnupg && ln -s /root/S.gpg-agent S.gpg-agent)

gpg --import /root/keys/dev.pub
gpg --import /root/keys/rpm.pub
rpmkeys --import /root/keys/rpm.pub
echo wat | gpg -u rpm@algorand.com --clearsign

cat <<EOF>"$HOME/.rpmmacros"
%_gpg_name Algorand RPM <rpm@algorand.com>
%__gpg $HOME/gnupg2/bin/gpg
%__gpg_check_password_cmd true
EOF

cat <<EOF>"$HOME/rpmsign.py"
import rpm
import sys
rpm.addSign(sys.argv[1], '')
EOF

NEWEST_RPM=$(ls -t /root/subhome/node_pkg/*rpm | head -1)
python2 "$HOME/rpmsign.py" "$NEWEST_RPM"

