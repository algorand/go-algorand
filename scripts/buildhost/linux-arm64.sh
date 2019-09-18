#!/usr/bin/env bash

BUILD_REQUEST=$1
OUTPUTFILE=$2
LOGFILE=$3
BUCKET=$4
NO_SIGN=$5
echo "linux-arm64 $1 $2 $3 $4 $5"

if [ "${BUILD_REQUEST}" = "" ]; then
    echo "Missing BUILD_REQUEST argument"
    exit 1
fi

SCRIPTPATH=$(pwd)
TMPPATH=$(dirname ${BUILD_REQUEST})
pushd .
cd ${TMPPATH}

AWS_REGION="us-west-2"
AWS_LINUX_AMI="ami-0c579621aaac8bade"
AWS_INSTANCE_TYPE="a1.2xlarge"
INSTANCE_NUMBER=$RANDOM

set +e

exitWithError() {
    local ERROR_CODE=$1
    local ERROR_MESSAGE=$2

    if [ "${OUTPUTFILE}" != "" ]; then
        echo "{ \"error\": ${ERROR_CODE}, \"log\": \"${ERROR_MESSAGE}\" }" | aws s3 cp - s3://${BUCKET}/${OUTPUTFILE} ${NO_SIGN}
    fi

    ${SCRIPTPATH}/shutdown_ec2_instance.sh ${AWS_REGION}
    if [ "$?" != "0" ]; then
        popd
        rm -rf ${TMPPATH}
        exit 1
    fi

    popd
    rm -rf ${TMPPATH}
    exit ${ERROR_CODE}
}

${SCRIPTPATH}/start_ec2_instance.sh ${AWS_REGION} ${AWS_LINUX_AMI} ${AWS_INSTANCE_TYPE}
if [ "$?" != "0" ]; then
    exitWithError $? "Unable to start EC2 instance"
fi

BRANCH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_BRANCH')
COMMIT_HASH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_COMMIT')
PULL_REQUEST=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_PULL_REQUEST')
BUILD_AWS_ACCESS_KEY_ID=$(cat $BUILD_REQUEST | jq -r '.AWS_ACCESS_KEY_ID')
BUILD_AWS_SECRET_ACCESS_KEY=$(cat $BUILD_REQUEST | jq -r '.AWS_SECRET_ACCESS_KEY')
EXEC=$(cat $BUILD_REQUEST | jq -r '.EXEC')

cat << EOF > exescript
git clone --depth=50 https://github.com/algorand/go-algorand -b ${BRANCH} go/src/github.com/algorand/go-algorand
cd go/src/github.com/algorand/go-algorand
export AWS_ACCESS_KEY_ID=${BUILD_AWS_ACCESS_KEY_ID}
export AWS_SECRET_ACCESS_KEY=${BUILD_AWS_SECRET_ACCESS_KEY}
EOF
if [ "${PULL_REQUEST}" = "false" ]; then
    cat << FOE >> exescript
git checkout ${COMMIT_HASH}
FOE
else
    cat << FOE >> exescript
git fetch origin +refs/pull/${PULL_REQUEST}/merge; git checkout -qf FETCH_HEAD
FOE
fi
cat << FOE >> exescript
export DEBIAN_FRONTEND=noninteractive
${EXEC}
FOE

ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) 'bash -s' < exescript 2>&1 | ${SCRIPTPATH}/s3streamup.sh s3://${BUCKET}/${LOGFILE} ${NO_SIGN}
ERR=$?
exitWithError ${ERR} ""
