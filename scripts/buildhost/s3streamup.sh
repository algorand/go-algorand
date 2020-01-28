#!/usr/bin/env bash

# s3streamup.sh - Streams the input stream into a S3 bucket.
#
# Syntax:   s3streamup.sh
#
# Usage:    Should only be used by a build host server.
#
# Examples: echo "123" | scripts/buildhost/s3streamup.sh <dest-s3-log-file> <no-sign>
#

DEST=$1
NO_SIGN=$2

SEQ=1
aws s3 rm ${DEST}-${SEQ} ${NO_SIGN}
aws s3 rm ${DEST}-$((SEQ+1)) ${NO_SIGN}
SEND_NEXT=$((SECONDS+10))
BUFFER=
while read line; do
        BUFFER=${BUFFER}${line}$'\n'
        if [ ${#BUFFER} -gt 10240 ]; then
                echo "${BUFFER::-1}" | aws s3 cp - ${DEST}-${SEQ} ${NO_SIGN}
                SEQ=$((SEQ+1))
                aws s3 rm ${DEST}-$((SEQ+1)) ${NO_SIGN}
                SEND_NEXT=$((SECONDS+10))
                BUFFER=
        fi
        if [ $SECONDS -gt $SEND_NEXT ]; then
                if [ ${#BUFFER} -gt 0 ]; then
                        echo "${BUFFER::-1}" | aws s3 cp - ${DEST}-${SEQ} ${NO_SIGN}
                        SEQ=$((SEQ+1))
                        aws s3 rm ${DEST}-$((SEQ+1)) ${NO_SIGN}
                        SEND_NEXT=$((SECONDS+10))
                        BUFFER=
                fi
        fi
done < /dev/stdin

if [ ${#BUFFER} -gt 0 ]; then
        echo "${BUFFER::-1}" | aws s3 cp - ${DEST}-${SEQ} ${NO_SIGN}
fi
