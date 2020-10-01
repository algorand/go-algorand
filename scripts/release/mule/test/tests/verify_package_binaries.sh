#!/usr/bin/env bash
# shellcheck disable=2116

set -e

echo "[$0] Verifying installed binaries..."

RET=0
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
    if ! grep "$bin" "$RPMTMP/algorand.install" > /dev/null
    then
        MISSING_ALGORAND_BINS+=("$bin")
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
    if ! grep "$bin" "$RPMTMP/algorand-devtools.install" > /dev/null
    then
        MISSING_DEVTOOLS_BINS+=("$bin")
    fi
done

LEN=$(echo ${#MISSING_ALGORAND_BINS[*]})
if [ "$LEN" -gt 0 ]
then
    echo "The following binaries are not contained in the \`algorand\` package:"
    for (( i=0; i<LEN; i++ ));
    do
        echo -e "\t${MISSING_ALGORAND_BINS[$i]}"
    done
    RET=1
fi

LEN=$(echo ${#MISSING_DEVTOOLS_BINS[*]})
if [ "$LEN" -gt 0 ]
then
    echo "The following binaries are not contained in the \`algorand-devtools\` package:"
    for (( i=0; i<LEN; i++ ));
    do
        echo -e "\t${MISSING_DEVTOOLS_BINS[$i]}"
    done
    RET=1
fi

exit $RET

