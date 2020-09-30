#!/usr/bin/env bash
# shellcheck disable=2045

set -ex

export PKG_TYPE="$1"
ARCH_BIT=$(uname -m)
ARCH_TYPE=$(./scripts/archtype.sh)
OS_TYPE=$(./scripts/ostype.sh)

export BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
export CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
export NETWORK=${NETWORK:-$(./scripts/compute_branch_network.sh "$BRANCH")}
export SHA=${SHA:-$(git rev-parse HEAD)}
export VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}

if ! $USE_CACHE
then
    SRC_DIR="s3://algorand-staging/releases/$CHANNEL/$VERSION"
    DEST_DIR="/projects/go-algorand/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"

    # deb
    aws s3 cp "$SRC_DIR/algorand_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.deb" "$DEST_DIR"
    aws s3 cp "$SRC_DIR/algorand-devtools_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.deb" "$DEST_DIR"

    # rpm
    aws s3 cp "$SRC_DIR/algorand-devtools-$VERSION-1.$ARCH_BIT.rpm" "$DEST_DIR"
    aws s3 cp "$SRC_DIR/algorand-$VERSION-1.$ARCH_BIT.rpm" "$DEST_DIR"
fi

if [ "$PKG_TYPE" == "deb" ]
then
    for deb in $(ls "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"/*"$VERSION"*.deb); do
        if [[ ! "$deb" =~ devtools ]]; then
            dpkg -i "$deb"
        fi
    done
#else
#    for rpm in $(ls "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"/*"$VERSION"*.rpm); do
#        if [[ ! "$rpm" =~ devtools ]]; then
#            yum install "$rpm" -y
#        fi
#    done
fi

for test in $(ls ./scripts/release/mule/test/tests/*.sh)
do
    bash "$test"
done

