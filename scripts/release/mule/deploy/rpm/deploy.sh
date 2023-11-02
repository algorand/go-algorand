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

CHANNEL=$(./scripts/release/mule/common/get_channel.sh "$NETWORK")
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
NO_DEPLOY=${NO_DEPLOY:-false}
OS_TYPE=$(./scripts/release/mule/common/ostype.sh)
PACKAGES_DIR=${PACKAGES_DIR:-"./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"}
STAGING=${STAGING:-"algorand-staging/releases"}

if [ -n "$S3_SOURCE" ]
then
    PREFIX="$S3_SOURCE/$CHANNEL/$VERSION"
    if [ "$CHANNEL" == "beta" ]
    then
        aws s3 cp "s3://$PREFIX/algorand-beta-$VERSION-1.x86_64.rpm" /root
        aws s3 cp "s3://$PREFIX/algorand-devtools-beta-$VERSION-1.x86_64.rpm" /root
    else
        aws s3 cp "s3://$PREFIX/algorand-$VERSION-1.x86_64.rpm" /root
        aws s3 cp "s3://$PREFIX/algorand-devtools-$VERSION-1.x86_64.rpm" /root
    fi
else
    cp "$PACKAGES_DIR"/*"$VERSION"*.rpm /root
fi

pushd /root

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
%__gpg /usr/bin/gpg2
%__gpg_check_password_cmd true
EOF

mkdir rpmrepo
for rpm in $(ls *"$VERSION"*.rpm)
do
    rpmsign --addsign "$rpm"
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
    # sync signatures to releases so that the .sig files load from there
    aws s3 sync s3://$STAGING/releases/$CHANNEL/ s3://algorand-releases/rpm/sigs/$CHANNEL/ --exclude='*' --include='*.rpm.sig'
fi

echo
date "+build_release end DEPLOY rpm stage %Y%m%d_%H%M%S"
echo

