#!/usr/bin/env bash

BUILD_REQUEST=$1
OUTPUTFILE=$2
BUCKET=$3
NO_SIGN=$4
echo "linux-arm64 $1 $2 $3 $4"

SCRIPTPATH=$(pwd)
TMPPATH=$(dirname ${BUILD_REQUEST})
pushd .
cd ${TMPPATH}

AWS_REGION="us-west-2"
AWS_LINUX_AMI="ami-0c579621aaac8bade"
INSTANCE_NUMBER=$RANDOM

set +e

${SCRIPTPATH}/start_ec2_instance.sh ${AWS_REGION} ${AWS_LINUX_AMI}
if [ "$?" != "0" ]; then
    popd
    rm -rf ${TMPPATH}
    exit 1
fi

BRANCH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_BRANCH')
COMMIT_HASH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_COMMIT')
PULL_REQUEST=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_PULL_REQUEST')

ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) git clone --depth=50 https://github.com/algorand/go-algorand -b ${BRANCH}
if [ "${PULL_REQUEST}" = "false" ]; then
    ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) "cd go-algorand; git checkout ${COMMIT_HASH}"
else
    ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) "cd go-algorand; git fetch origin +refs/pull/${PULL_REQUEST}/merge; git checkout -qf FETCH_HEAD"
fi
ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) "export DEBIAN_FRONTEND=noninteractive; cd go-algorand; ./scripts/travis/build.sh" 2>&1 > build_log.txt
ERR=$?
if [ "${OUTPUTFILE}" != "" ]; then
    echo "{ \"error\": ${ERR} }" > ./err_file.json
    jq --rawfile texts build_log.txt '.log=$texts' ./err_file.json > ./result.json
    aws s3 cp ./result.json s3://${BUCKET}/${OUTPUTFILE} ${NO_SIGN}
    rm err_file.json result.json
fi
rm build_log.txt

${SCRIPTPATH}/shutdown_ec2_instance.sh ${AWS_REGION}
if [ "$?" != "0" ]; then
    popd
    rm -rf ${TMPPATH}
    exit 1
fi

popd
rm -rf ${TMPPATH}
