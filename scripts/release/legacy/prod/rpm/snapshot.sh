#!/usr/bin/env bash
# shellcheck disable=2012

set -ex

cd /root && tar jxf /root/subhome/gnupg*.tar.bz2
export PATH=/root/gnupg2/bin:"${PATH}"
export LD_LIBRARY_PATH=/root/gnupg2/lib

umask 0077
mkdir -p /root/.gnupg
umask 0022
touch /root/.gnupg/gpg.conf

if grep -q no-autostart /root/.gnupg/gpg.conf
then
    echo ""
else
    echo "no-autostart" >> /root/.gnupg/gpg.conf
fi

rm -f /root/.gnupg/S.gpg-agent
cd /root/.gnupg && ln -s /root/S.gpg-agent S.gpg-agent

gpg --import /root/keys/dev.pub
gpg --import /root/keys/rpm.pub
rpmkeys --import /root/keys/rpm.pub
echo "wat" | gpg -u rpm@algorand.com --clearsign

cat <<EOF> /root/.rpmmacros
%_gpg_name Algorand RPM <rpm@algorand.com>
%__gpg /root/gnupg2/bin/gpg
%__gpg_check_password_cmd true
EOF

cat <<EOF> /root/rpmsign.py
import rpm
import sys
rpm.addSign(sys.argv[1], '')
EOF

NEWEST_RPM=$(ls -t /root/subhome/node_pkg/*.rpm | head -1)
python2 /root/rpmsign.py "${NEWEST_RPM}"

cp -p "${NEWEST_RPM}" /root/prodrepo
createrepo --database /root/prodrepo
rm -f /root/prodrepo/repodata/repomd.xml.asc
gpg -u rpm@algorand.com --detach-sign --armor /root/prodrepo/repodata/repomd.xml

aws s3 sync --quiet /root/prodrepo/ s3://algorand-releases/rpm/stable/

echo CENTOS_DOCKER_SNAPSHOT_OK

