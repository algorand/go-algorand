#!/usr/bin/env bash
# shellcheck disable=2035,2129,2162

# TODO: This needs to be reworked a bit to support Darwin.

set -exo pipefail

echo
date "+build_release begin SIGN stage %Y%m%d_%H%M%S"
echo

if [ -z "$NETWORK" ] || [ -z "$VERSION" ]; then
    echo "[$0] NETWORK=$NETWORK or VERSION=$VERSION is missing."
    exit 1
fi

CHANNEL=$("./scripts/release/mule/common/get_channel.sh" "$NETWORK")
PKG_DIR="./tmp/node_pkgs"
SIGNING_KEY_ADDR=dev@algorand.com

# It seems that copying/mounting the gpg dir from another machine can result in insecure
# access privileges, so set the correct permissions to avoid the following warning:
#
#   gpg: WARNING: unsafe permissions on homedir '/root/.gnupg'
#
find /root/.gnupg -type d -exec chmod 700 {} \;
find /root/.gnupg -type f -exec chmod 600 {} \;

mkdir -p "$PKG_DIR"
cd "$PKG_DIR"

if [ -n "$S3_SOURCE" ]
then
    aws s3 cp --recursive --exclude "*" --include "*$CHANNEL*$VERSION*" "s3://$S3_SOURCE/$CHANNEL/$VERSION" .
fi

# TODO: "$PKG_TYPE" == "source"

# https://unix.stackexchange.com/a/46259
# Grab the directories directly underneath (max-depth 1) ./tmp/node_pkgs/ into a space-delimited string.
# This will help us target `linux`, `darwin` and (possibly) `windows` build assets.
# Note the surrounding parens turns the string created by `find` into an array.
OS_TYPES=($(find . -mindepth 1 -maxdepth 1 -type d -printf '%f\n'))
for os in "${OS_TYPES[@]}"; do
    if [ "$os" = linux ]
    then
        ARCHS=(amd64 arm arm64)
        for arch in "${ARCHS[@]}"; do
            (
                mkdir -p "$os/$arch"
                cd "$os/$arch"

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

                HASHFILE="hashes_${CHANNEL}_${os}_${arch}_${VERSION}"
                md5sum *.tar.gz *.deb *.rpm >> "$HASHFILE"
                shasum -a 256 *.tar.gz *.deb *.rpm >> "$HASHFILE"
                shasum -a 512 *.tar.gz *.deb *.rpm >> "$HASHFILE"

                gpg -u "$SIGNING_KEY_ADDR" --detach-sign "$HASHFILE"
                gpg -u "$SIGNING_KEY_ADDR" --clearsign "$HASHFILE"

                STATUSFILE="build_status_${CHANNEL}_${os}-${arch}_${VERSION}"
                gpg -u "$SIGNING_KEY_ADDR" --clearsign "$STATUSFILE"
                gzip -c "$STATUSFILE.asc" > "$STATUSFILE.asc.gz"
            )
        done
    fi
done

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

