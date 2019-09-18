#!/usr/bin/env bash

DEST=$1
NO_SIGN=$2

SEQ=1
SEND_NEXT=$((SECONDS+10))
BUFFER=
while read line; do
        BUFFER=${BUFFER}${line}$'\n'
        if [ ${#BUFFER} -gt 10240 ]; then
                echo "${BUFFER::-1}" | aws s3 cp - ${DEST}-${SEQ} ${NO_SIGN}
                ((SEQ++))
                SEND_NEXT=$((SECONDS+10))
                BUFFER=
        fi
        if [ $SECONDS -gt $SEND_NEXT ]; then
                if [ ${#BUFFER} -gt 0 ]; then
                        echo "${BUFFER::-1}" | aws s3 cp - ${DEST}-${SEQ} ${NO_SIGN}
                        ((SEQ++))
                        SEND_NEXT=$((SECONDS+10))
                        BUFFER=
                fi
        fi
done < /dev/stdin

if [ ${#BUFFER} -gt 0 ]; then
        echo "${BUFFER::-1}" | aws s3 cp - ${DEST}-${SEQ} ${NO_SIGN}
fi