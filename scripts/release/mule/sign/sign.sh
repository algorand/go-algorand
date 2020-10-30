#!/usr/bin/env bash
# shellcheck disable=2035,2129

set -exo pipefail

echo
date "+build_release begin SIGN stage %Y%m%d_%H%M%S"
echo

ARCH_BIT=$(uname -m)
ARCH_TYPE=$(./scripts/archtype.sh)
OS_TYPE=$(./scripts/ostype.sh)
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
BRANCH=${BRANCH:-$(./scripts/compute_branch.sh)}
CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
PKG_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
SIGNING_KEY_ADDR=dev@algorand.com
STATUSFILE="build_status_${CHANNEL}_${VERSION}"

# It seems that copying/mounting the gpg dir from another machine can result in insecure
# access privileges, so set the correct permissions to avoid the following warning:
#
#   gpg: WARNING: unsafe permissions on homedir '/root/.gnupg'
#
find /root/.gnupg -type d -exec chmod 700 {} \;
find /root/.gnupg -type f -exec chmod 600 {} \;

cd "$PKG_DIR"

if [ -n "$S3_SOURCE" ]
then
    PREFIX="$S3_SOURCE/$CHANNEL/$VERSION"

    # deb
    aws s3 cp "s3://$PREFIX/algorand_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.deb" .
    aws s3 cp "s3://$PREFIX/algorand-devtools_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.deb" .

    # rpm
    aws s3 cp "s3://$PREFIX/algorand-${VERSION}-1.${ARCH_BIT}.rpm" .
    aws s3 cp "s3://$PREFIX/algorand-devtools-${VERSION}-1.${ARCH_BIT}.rpm" .
fi

# TODO: "$PKG_TYPE" == "source"

# Clean package directory of any previous operations.
rm -rf hashes* *.sig *.asc *.asc.gz

for file in *.tar.gz *.deb
do
    gpg -u "$SIGNING_KEY_ADDR" --detach-sign "$file"
done

for file in *.rpm
do
    gpg -u rpm@algorand.com --detach-sign "$file"
done

HASHFILE="hashes_${CHANNEL}_${OS_TYPE}_${ARCH_TYPE}_${VERSION}"

md5sum *.tar.gz *.deb *.rpm >> "$HASHFILE"
shasum -a 256 *.tar.gz *.deb *.rpm >> "$HASHFILE"
shasum -a 512 *.tar.gz *.deb *.rpm >> "$HASHFILE"

gpg -u "$SIGNING_KEY_ADDR" --detach-sign "$HASHFILE"
gpg -u "$SIGNING_KEY_ADDR" --clearsign "$HASHFILE"

gpg -u "$SIGNING_KEY_ADDR" --clearsign "$STATUSFILE"
gzip -c "$STATUSFILE.asc" > "$STATUSFILE.asc.gz"

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

