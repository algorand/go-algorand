#!/usr/bin/env bash

DEST=$1
NO_SIGN=$2

SEQ=1
while read line; do
        echo line >> buffile
        if [[ $(find buffile -type f -size +1024c 2>/dev/null) ]]; then
                aws s3 cp buffile ${DEST}-${SEQ} ${NO_SIGN}
                rm -f buffile
                ((SEQ++))
        fi
done < /dev/stdin

if [ -f buffile ]; then
        aws s3 cp buffile ${DEST}-${SEQ} ${NO_SIGN}
        rm -f buffile
fi