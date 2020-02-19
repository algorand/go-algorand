#!/usr/bin/env bash
# shellcheck disable=2045

if [ $# -ne 1 ]
then
    echo "Usage: $0 <DIRECTORY>"
    exit 1
fi

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)
RETVAL=0

pushd "$1" > /dev/null

for file in $(ls ./*.{gz,deb,rpm})
do
    key_id=dev@algorand.com

    # Check the filename extension.
    if [ "${file##*.}" == "rpm" ]
    then
        key_id=rpm@algorand.com
    fi

    if ! gpg -u "$key_id" --verify "$file".sig "$file"
    then
        echo -e "$RED_FG[$0]$END_FG_COLOR Could not verify signature for $file"
        RETVAL=1
    fi
done

popd > /dev/null

if [ $RETVAL -eq 0 ]
then
    echo -e "$GREEN_FG[$0]$END_FG_COLOR All signatures have been verified as good."
fi

exit $RETVAL

