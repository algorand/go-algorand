#!/usr/bin/env bash

BUILD_REQUEST=$1
OUTPUTFILE=$2
LOGFILE=$3
BUCKET=$4
NO_SIGN=$5
echo "linux-arm64 $1 $2 $3 $4 $5"

SCRIPTPATH=$(pwd)
TMPPATH=$(dirname ${BUILD_REQUEST})
pushd .
cd ${TMPPATH}

AWS_REGION="us-west-2"
AWS_LINUX_AMI="ami-0c579621aaac8bade"
AWS_INSTANCE_TYPE="a1.2xlarge"
INSTANCE_NUMBER=$RANDOM

set +e

${SCRIPTPATH}/start_ec2_instance.sh ${AWS_REGION} ${AWS_LINUX_AMI} ${AWS_INSTANCE_TYPE}
if [ "$?" != "0" ]; then
    popd
    rm -rf ${TMPPATH}
    exit 1
fi

BRANCH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_BRANCH')
COMMIT_HASH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_COMMIT')
PULL_REQUEST=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_PULL_REQUEST')

echo > exescript << EOF
git clone --depth=50 https://github.com/algorand/go-algorand -b ${BRANCH} go/src/github.com/algorand/go-algorand
cd go/src/github.com/algorand/go-algorand
EOF
if [ "${PULL_REQUEST}" = "false" ]; then
    echo >> exescript << EOF
git checkout ${COMMIT_HASH}
EOF
else
    echo >> exescript << EOF
git fetch origin +refs/pull/${PULL_REQUEST}/merge; git checkout -qf FETCH_HEAD
EOF
fi
    echo >> exescript << EOF
export DEBIAN_FRONTEND=noninteractive
 ./scripts/travis/build.sh
EOF

ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) < exescript 2>&1 | aws s3 cp - s3://${BUCKET}/${LOGFILE} ${NO_SIGN}
ERR=$?
if [ "${OUTPUTFILE}" != "" ]; then
    echo "{ \"error\": ${ERR}, \"log\": \"\" }" | aws s3 cp - s3://${BUCKET}/${OUTPUTFILE} ${NO_SIGN}
fi

${SCRIPTPATH}/shutdown_ec2_instance.sh ${AWS_REGION}
if [ "$?" != "0" ]; then
    popd
    rm -rf ${TMPPATH}
    exit 1
fi

popd
rm -rf ${TMPPATH}
