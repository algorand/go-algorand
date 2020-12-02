#!/usr/bin/env bash
# shellcheck disable=2045

set -ex

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

if [ -z "$BRANCH" ] || [ -z "$NETWORK" ] || [ -z "$SHA" ]; then
    echo "[$0] BRANCH=$BRANCH, NETWORK=$NETWORK or SHA=$SHA is missing."
    exit 1
fi

CHANNEL=$("./scripts/release/mule/common/get_channel.sh" "$NETWORK")
export CHANNEL

VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
export VERSION

export BRANCH

export PKG_TYPE="$1"

ARCH_BIT=$(uname -m)
export ARCH_BIT

OS_TYPE=$(uname)
export OS_TYPE=${OS_TYPE,}

export SHA

ALGORAND_PACKAGE_NAME=$([ "$CHANNEL" = beta ] && echo algorand-beta || echo algorand)
DEVTOOLS_PACKAGE_NAME=$([ "$CHANNEL" = beta ] && echo algorand-devtools-beta || echo algorand-devtools)
export ALGORAND_PACKAGE_NAME
export DEVTOOLS_PACKAGE_NAME

PKG_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"

mkdir -p "$PKG_DIR"
pushd "$PKG_DIR"

if [ -n "$S3_SOURCE" ]
then
    PREFIX="$S3_SOURCE/$CHANNEL/$VERSION"
    PACKAGE_NAME_SUFFIX="${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}"

    # deb
    aws s3 cp "s3://$PREFIX/algorand_$PACKAGE_NAME_SUFFIX.deb" .
    aws s3 cp "s3://$PREFIX/algorand-devtools_$PACKAGE_NAME_SUFFIX.deb" .

    aws s3 cp "s3://$PREFIX/algorand_$PACKAGE_NAME_SUFFIX.deb.sig" .
    aws s3 cp "s3://$PREFIX/algorand-devtools_$PACKAGE_NAME_SUFFIX.deb.sig" .

    # Not only do we need to redefine the `PACKAGE_NAME_SUFFIX` for rpm but
    # we need to check the channel before defining it.
    #
    # Remember, rpm packages don't include the channel in the package name!
    #
    # ( `betanet` builds are special b/c "beta" is part of the package name,
    #   so although it appears as though I just lied to you, I did not :)
    #
    # rpm
    if [ "$CHANNEL" = "beta" ]
    then
        PACKAGE_NAME_SUFFIX="$CHANNEL-$VERSION-1.$ARCH_BIT"
    else
        PACKAGE_NAME_SUFFIX="$VERSION-1.$ARCH_BIT"
    fi

    aws s3 cp "s3://$PREFIX/algorand-$PACKAGE_NAME_SUFFIX.rpm" .
    aws s3 cp "s3://$PREFIX/algorand-devtools-$PACKAGE_NAME_SUFFIX.rpm" .

    aws s3 cp "s3://$PREFIX/algorand-$PACKAGE_NAME_SUFFIX.rpm.sig" .
    aws s3 cp "s3://$PREFIX/algorand-devtools-$PACKAGE_NAME_SUFFIX.rpm.sig" .
fi

popd

for test in $(ls ./scripts/release/mule/test/tests/pre/*.sh)
do
    echo ">>>>>>>>>> PRE TESTING $(basename "$test")"
    bash "$test"
done

pushd "$PKG_DIR"

if [ "$PKG_TYPE" = deb ]
then
    dpkg -i algorand_*"$VERSION"*.deb
    dpkg -i algorand-devtools*"$VERSION"*.deb
else
    # We need to install this since it's not being installed by a package manager.
    # Normally, this is installed for us b/c it's a dependency.
    # See `./installer/rpm/algorand/algorand.spec`.
    yum install yum-cron -y
    #
    # Note that the RPM package DOES NOT have the CHANNEL in its filename (unlike DEB),
    # instead it contains the package name.
    #
    # deb:
    #       algorand_CHANNEL*VERSION.deb
    #       algorand-devtools_CHANNEL*VERSION.deb
    #
    #       (this pattern is for all channels)
    #
    # rpm:
    #       (this pattern is for stable)
    #       algorand-VERSION*.rpm
    #       algorand-devtools-VERSION.rpm
    #
    #       (this pattern is for beta)
    #       algorand-beta-VERSION*.rpm
    #       algorand-devtools-beta-VERSION.rpm
    #
    #       SO.....
    #       ALGORAND_PACKAGE_NAME-VERSION*.rpm
    #       DEVTOOLS_PACKAGE_NAME-beta-VERSION.rpm
    #
    #       Hope that makes sense :)
    #
    rpm -i "$ALGORAND_PACKAGE_NAME"-"$VERSION"-1."$ARCH_BIT".rpm
    rpm -i "$DEVTOOLS_PACKAGE_NAME"-*"$VERSION"-1."$ARCH_BIT".rpm
fi

popd

for test in $(ls ./scripts/release/mule/test/tests/post/*.sh)
do
    echo ">>>>>>>>>> POST TESTING $(basename "$test")"
    bash "$test"
done

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

