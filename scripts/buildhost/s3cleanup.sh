#!/usr/bin/env bash

# s3cleanup.sh - Invokes the build host
#
# Syntax:   s3cleanup.sh
#
# Usage:    Should only be used by a build host server.
#
# Examples: scripts/buildhost/s3cleanup.sh <bucket> <no-sign>
#

BUCKET=$1
NO_SIGN=$2

LISTFILE=${BUCKET}.buildRequests.txt
aws s3 ls --recursive s3://${BUCKET} ${NO_SIGN} > ${LISTFILE}
if [ "$?" != "0" ]; then
    rm ${LISTFILE}
    exit 1
fi
# current time = date +"%Y-%m-%d %H:%M:%S"
# ten hours ago : date -d " - 12 hours " +"%Y-%m-%d %H:%M:%S"
# the above doesn't work on mac, but works well on ubuntu
REF_TIME=$(date -d " - 12 hours " +"%Y-%m-%d %H:%M:%S")
REF_TIME="${REF_TIME/ /.}"
while read line; do
    FILE_TIME="${line:0:19}"
    FILE_TIME="${FILE_TIME/ /.}"
    if [[ "${FILE_TIME}" < "${REF_TIME}" ]];then
        # this is where we want to delete the file.
        FILE_NAME="${line:31}"
        aws s3 rm s3://${BUCKET}/${FILE_NAME} ${NO_SIGN}
    fi
done < ${LISTFILE}
rm -f ${LISTFILE}
exit 0
