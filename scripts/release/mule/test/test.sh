#!/usr/bin/env bash
# shellcheck disable=2045

set -ex

export PKG_TYPE="$1"
ARCH_BIT=$(uname -m)
export ARCH_BIT
ARCH_TYPE=$(./scripts/archtype.sh)
export ARCH_TYPE
OS_TYPE=$(./scripts/ostype.sh)
export OS_TYPE

export BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
export CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
export NETWORK=${NETWORK:-$(./scripts/compute_branch_network.sh "$BRANCH")}
export SHA=${SHA:-$(git rev-parse HEAD)}
export VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}

PKG_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"

pushd "$PKG_DIR"

if ! $USE_CACHE
then
    SRC_DIR="s3://algorand-staging/releases/$CHANNEL/$VERSION"

    # deb
    aws s3 cp "$SRC_DIR/algorand_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.deb" .
    aws s3 cp "$SRC_DIR/algorand-devtools_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.deb" .

    # rpm
    aws s3 cp "$SRC_DIR/algorand-$VERSION-1.$ARCH_BIT.rpm" .
    aws s3 cp "$SRC_DIR/algorand-devtools-$VERSION-1.$ARCH_BIT.rpm" .
fi

popd

for test in $(ls ./scripts/release/mule/test/tests/pre/*.sh)
do
    bash "$test"
done

pushd "$PKG_DIR"

if [ "$PKG_TYPE" = deb ]
then
    dpkg -i algorand_*"$VERSION"*.deb
    dpkg -i algorand-devtools*"$VERSION"*.deb
else
    yum install yum-cron -y
    rpm -i algorand-"$VERSION"-1."$ARCH_BIT".rpm
    rpm -i algorand-devtools-"$VERSION"-1."$ARCH_BIT".rpm
fi

popd

for test in $(ls ./scripts/release/mule/test/tests/post/*.sh)
do
    bash "$test"
done

