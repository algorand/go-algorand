#!/usr/bin/env bash
echo "goal subcommand sanity check"
set -e
set -x

TEMPDIR=$1

# Run all `goal ... -h` commands.
# This will make sure they work and that there are no conflicting subcommand options.
goal helptest > ${TEMPDIR}/helptest
if bash -x -e ${TEMPDIR}/helptest > ${TEMPDIR}/helptest.out 2>&1; then
    # ok
    echo "goal subcommands ok"
else
    cat ${TEMPDIR}/helptest.out
    exit 1
fi
