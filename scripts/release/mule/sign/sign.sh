#!/usr/bin/env bash
# shellcheck disable=2035,2129

# TODO: This needs to be reworked a bit to support Darwin.

set -exo pipefail

echo
date "+build_release begin SIGN stage %Y%m%d_%H%M%S"
echo

if [ -z "$NETWORK" ]; then
    echo "[$0] NETWORK is missing."
    exit 1
fi

CHANNEL=$(./scripts/release/mule/common/get_channel.sh "$NETWORK")
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
PKG_DIR="./tmp/node_pkgs"
SIGNING_KEY_ADDR=dev@algorand.com
OS_TYPE=$(./scripts/release/mule/common/ostype.sh)
ARCHS=(amd64 arm arm64)
ARCH_BITS=(x86_64 armv7l aarch64)

if ./scripts/release/mule/common/running_in_docker.sh
then
    # It seems that copying/mounting the gpg dir from another machine can result in insecure
    # access privileges, so set the correct permissions to avoid the following warning:
    #
    #   gpg: WARNING: unsafe permissions on homedir '/root/.gnupg'
    #
    find /root/.gnupg -type d -exec chmod 700 {} \;
    find /root/.gnupg -type f -exec chmod 600 {} \;
fi

# Note that when downloading from the cloud that we'll get all packages for all architectures.
if [ -n "$S3_SOURCE" ]
then
    i=0
    for arch in "${ARCHS[@]}"; do
        arch_bit="${ARCH_BITS[$i]}"
        (
            mkdir -p "$PKG_DIR/$OS_TYPE/$arch"
            cd "$PKG_DIR"
            # Note the underscore after ${arch}!
            # Recall that rpm packages have the arch bit in the filenames (i.e., "x86_64" rather than "amd64").
            # Also, the order of the includes/excludes is important!
            aws s3 cp --recursive --exclude "*" --include "*${arch}_*" --include "*$arch_bit.rpm" --exclude "*.sig" --exclude "*.asc" --exclude "*.asc.gz" "s3://$S3_SOURCE/$CHANNEL/$VERSION" .
        )
        i=$((i + 1))
    done
fi

cd "$PKG_DIR"

# TODO: "$PKG_TYPE" == "source"

# https://unix.stackexchange.com/a/46259
# Grab the directories directly underneath (max-depth 1) ./tmp/node_pkgs/ into a space-delimited string.
# This will help us target `linux`, `darwin` and (possibly) `windows` build assets.
# Note the surrounding parens turns the string created by `find` into an array.
OS_TYPES=($(find . -mindepth 1 -maxdepth 1 -type d -printf '%f\n'))
for os in "${OS_TYPES[@]}"; do
    if [ "$os" = linux ]
    then
        for arch in "${ARCHS[@]}"; do
            if [ -d "$os/$arch" ]
            then
                # Only do the subsequent operations in a subshell if the directory is not empty.
                if stat -t "$os/$arch/"* > /dev/null 2>&1
                then
                (
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
                fi
            fi
        done
    fi
done

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

