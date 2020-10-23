#!/usr/bin/env bash

set -ex

echo "[$0] Testing: algod -v"

STR=$(algod -v)
SHORT_HASH=${SHA:0:8}

# We're looking for a line that looks like the following:
#
#       2.0.4.stable [rel/stable] (commit #729b125a+)
#
# Since we're passing in the full hash, we won't using the closing paren.
# Use a regex over the multi-line string.
if [[ "$STR" =~ .*"$VERSION.$CHANNEL [$BRANCH] (commit #$SHORT_HASH".* ]] ||
    [[ "$STR" =~ .*"$VERSION. [$BRANCH] (commit #$SHORT_HASH".* ]]
then
    echo -e "[$0] The result of \`algod -v\` is a correct match.\n$STR"
    exit 0
fi

echo "[$0] The result of \`algod -v\` is an incorrect match."
exit 1

