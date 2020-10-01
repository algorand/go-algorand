#!/usr/bin/env bash
# shellcheck disable=2035

set -ex

echo "[$0] Verifying installed binaries."

RPMTMP=$(mktemp -d)

if [ "$PKG_TYPE" = deb ]
then
    dpkg -L algorand > "$RPMTMP/algorand.install"
    dpkg -L algorand-devtools > "$RPMTMP/algorand-devtools.install"
else
    rpm -ql algorand > "$RPMTMP/algorand.install"
    rpm -ql algorand-devtools > "$RPMTMP/algorand-devtools.install"
fi

ALGORAND_BINS=(
    /usr/bin/algocfg
    /usr/bin/algod
    /usr/bin/algoh
    /usr/bin/algokey
    /usr/bin/ddconfig.sh
    /usr/bin/diagcfg
    /usr/bin/goal
    /usr/bin/kmd
    /usr/bin/node_exporter
)
for bin in "${ALGORAND_BINS[@]}"; do
    if ! grep "$bin" "$RPMTMP/algorand.install"
    then
        echo "[$0] The binary $bin is not contained in the algorand package."
        exit 1
    fi
done

DEVTOOLS_BINS=(
    /usr/bin/carpenter
    /usr/bin/catchupsrv
    /usr/bin/msgpacktool
    /usr/bin/tealcut
    /usr/bin/tealdbg
)
for bin in "${DEVTOOLS_BINS[@]}"; do
    if ! grep "$bin" "$RPMTMP/algorand-devtools.install"
    then
        echo "[$0] The binary $bin is not contained in the algorand-devtools package."
        exit 1
    fi
done

