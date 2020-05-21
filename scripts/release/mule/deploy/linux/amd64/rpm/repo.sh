#!/usr/bin/env bash
# shellcheck disable=2045

set -ex

mule -f package-deploy.yaml package-deploy-setup-gnupg

cd /root
tar jxf gnupg*.tar.bz2

export PATH=/root/gnupg2/bin:"${PATH}"
export LD_LIBRARY_PATH=/root/gnupg2/lib

mkdir -p .gnupg
chmod 400 .gnupg
touch .gnupg/gpg.conf

if grep -q no-autostart .gnupg/gpg.conf
then
    echo ""
else
    echo "no-autostart" >> .gnupg/gpg.conf
fi

#gpg --import /root/keys/dev.pub
#gpg --import /root/keys/rpm.pub
#rpmkeys --import /root/keys/rpm.pub

echo "wat" | gpg -u rpm@algorand.com --clearsign

cat << EOF > .rpmmacros
%_gpg_name Algorand RPM <rpm@algorand.com>
%__gpg /root/gnupg2/bin/gpg
%__gpg_check_password_cmd true
EOF

cat << EOF > rpmsign.py
import rpm
import sys
rpm.addSign(sys.argv[1], '')
EOF

mkdir prodrepo
for rpm in $(ls packages/rpm/stable/*.rpm)
do
    python2 rpmsign.py "$rpm"
    cp -p "$rpm" prodrepo
done

createrepo --database prodrepo
rm -f prodrepo/repodata/repomd.xml.asc
gpg -u rpm@algorand.com --detach-sign --armor prodrepo/repodata/repomd.xml

#aws s3 sync prodrepo/ s3://ben-test-2.0.3/rpm/stable/

