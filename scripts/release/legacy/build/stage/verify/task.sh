#!/usr/bin/env bash

set -ex

echo
date "+build_release begin VERIFY %Y%m%d_%H%M%S"
echo

RETVAL=0

cd "$HOME/node_pkg"

for file in *.{gz,deb,rpm}
do
    key_id=dev@algorand.com

    # Check the filename extension.
    if [ "${file##*.}" == "rpm" ]
    then
        key_id=rpm@algorand.com
    fi

    if ! gpg -u "$key_id" --verify "$file".sig "$file"
    then
        echo -e "[$0] Could not verify signature for $file"
        RETVAL=1
    fi
done

if [ $RETVAL -eq 0 ]
then
    echo -e "[$0] All signatures have been verified as good."
fi

echo
date "+build_release end VERIFY stage %Y%m%d_%H%M%S"
echo

exit $RETVAL

