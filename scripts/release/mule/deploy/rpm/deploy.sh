#!/usr/bin/env bash
# shellcheck disable=2035,2045

set -ex

echo
date "+build_release begin DEPLOY rpm stage %Y%m%d_%H%M%S"
echo

if [ -z "$NETWORK" ]; then
    echo "[$0] NETWORK is missing."
    exit 1
fi

CHANNEL=$("./scripts/release/mule/common/get_channel.sh" "$NETWORK")
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
NO_DEPLOY=${NO_DEPLOY:-false}
OS_TYPE=$(uname)
OS_TYPE=${OS_TYPE,}
PACKAGES_DIR=${PACKAGES_DIR:-"./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"}

if [ -n "$S3_SOURCE" ]
then
    PREFIX="$S3_SOURCE/$CHANNEL/$VERSION"

    aws s3 cp "s3://$PREFIX/algorand-$VERSION-1.x86_64.rpm" /root
    aws s3 cp "s3://$PREFIX/algorand-devtools-$VERSION-1.x86_64.rpm" /root
else
    cp "$PACKAGES_DIR"/*"$VERSION"*.rpm /root
fi

pushd /root

aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 .
tar jxf gnupg*.tar.bz2

export PATH="/root/gnupg2/bin:$PATH"
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

mkdir rpmrepo
for rpm in $(ls *"$VERSION"*.rpm)
do
    python2 rpmsign.py "$rpm"
    cp -p "$rpm" rpmrepo
done

createrepo --database rpmrepo
rm -f rpmrepo/repodata/repomd.xml.asc
gpg -u rpm@algorand.com --detach-sign --armor rpmrepo/repodata/repomd.xml

if $NO_DEPLOY
then
    popd
    cp -r /root/rpmrepo .
else
    aws s3 sync rpmrepo "s3://algorand-releases/rpm/$CHANNEL/"
    aws s3 cp *"$VERSION"*.rpm "s3://algorand-internal/packages/rpm/$CHANNEL/"
fi

echo
date "+build_release end DEPLOY rpm stage %Y%m%d_%H%M%S"
echo

