#!/usr/bin/env bash

BUILD_REQUEST=$1
OUTPUTFILE=$2
BUCKET=$3
NO_SIGN=$4

TMPPATH=$(dirname ${BUILD_REQUEST})

AWS_REGION="us-west-2"
AWS_LINUX_AMI="ami-0c579621aaac8bade"
INSTANCE_NUMBER=$RANDOM

set +e

./start_ec2_instance.sh ${AWS_REGION} ${AWS_LINUX_AMI}
if [ "$?" != "0" ]; then
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
ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) "go-algorand/scripts/travis/configure_dev.sh"
ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance) "cd go-algorand; make -j4 2>&1" 2>&1 > build_log.txt
ERR=$?
if [ "$OUTPUTFILE" != "" ]; then
    echo "{ \"error\": ${ERR} }" > ./err_file.json
    jq --rawfile texts build_log.txt '.log=$texts' ./err_file.json > ./result.json
    aws s3 cp ./result.json s3://${BUCKET}/${OUTPUTFILE} ${NO_SIGN}
    rm err_file.json result.json
fi
rm build_log.txt

./shutdown_ec2_instance.sh ${AWS_REGION}
if [ "$?" != "0" ]; then
    exit 1
fi

rm -rf ${TMPPATH}
