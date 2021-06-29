#!/usr/bin/env bash

BUILD_REQUEST=$1
OUTPUTFILE=$2
LOGFILE=$3
BUCKET=$4
NO_SIGN=$5
echo "linux-arm $1 $2 $3 $4 $5"

if [ "${BUILD_REQUEST}" = "" ]; then
    echo "Missing BUILD_REQUEST argument"
    exit 1
fi

SCRIPTPATH=$(pwd)
TMPPATH=$(dirname ${BUILD_REQUEST})
pushd .
cd ${TMPPATH}

AWS_REGION="us-west-2"
# this is the private AMI that contains the RasPI VM running on port 5022
#AWS_LINUX_AMI="ami-06819013739d79715"
AWS_LINUX_AMI="ami-009f7a201c82c42e1"
AWS_INSTANCE_TYPE="i3.xlarge"
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
    exitWithError 1 "Unable to start EC2 instance"
fi

scp -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance):/home/ubuntu/armv6_stretch/id_rsa ./id_rsa
if [ "$?" != "0" ]; then
    exitWithError 1 "Unable to retrieve RasPI credentials from EC2 instance at $(cat instance)"
fi

echo "Waiting for RasPI SSH connection at $(cat instance)"
end=$((SECONDS+1200))
RASPI_READY=false
while [ $SECONDS -lt $end ]; do
    ssh -i id_rsa -o "StrictHostKeyChecking no" -p 5022 pi@$(cat instance) "uname -a" 2>/dev/null
    if [ "$?" = "0" ]; then
        echo "RasPI SSH connection ready"
        RASPI_READY=true
        break
    fi
    sleep 4s
done

if [ "${RASPI_READY}" = "false" ]; then
    exitWithError 1 "Timed out waiting for raspi service to start on $(cat instance)"
fi

BRANCH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_BRANCH')
COMMIT_HASH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_COMMIT')
PULL_REQUEST=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_PULL_REQUEST')
BUILD_AWS_ACCESS_KEY_ID=$(cat $BUILD_REQUEST | jq -r '.AWS_ACCESS_KEY_ID')
BUILD_AWS_SECRET_ACCESS_KEY=$(cat $BUILD_REQUEST | jq -r '.AWS_SECRET_ACCESS_KEY')
EXEC=$(cat $BUILD_REQUEST | jq -r '.EXEC')
S3_RELEASE_BUCKET=$(cat $BUILD_REQUEST | jq -r '.S3_RELEASE_BUCKET')

cat << EOF > exescript
git clone --depth=50 --branch ${BRANCH} https://github.com/algorand/go-algorand go/src/github.com/algorand/go-algorand
cd go/src/github.com/algorand/go-algorand
export AWS_ACCESS_KEY_ID=${BUILD_AWS_ACCESS_KEY_ID}
export AWS_SECRET_ACCESS_KEY=${BUILD_AWS_SECRET_ACCESS_KEY}
export TRAVIS_BRANCH=${BRANCH}
export TRAVIS_COMMIT=${COMMIT_HASH}
export TRAVIS_PULL_REQUEST=${PULL_REQUEST}
export S3_RELEASE_BUCKET=${S3_RELEASE_BUCKET}
EOF
if [ "${PULL_REQUEST}" = "false" ]; then
    cat << FOE >> exescript
git checkout -qf ${COMMIT_HASH}
FOE
else
    cat << FOE >> exescript
git fetch origin +refs/pull/${PULL_REQUEST}/merge; git checkout -qf FETCH_HEAD
FOE
fi
cat << FOE >> exescript
export DEBIAN_FRONTEND=noninteractive
${EXEC}
exit \$?
FOE

timeout_monitor() {
    local timeout=$1 # in minutes
    local count=0
    while [ $count -lt $timeout ]; do
        count=$(($count + 1))
        sleep 60s
    done
    # at this point, we want to terminate the EC2 instance.
    exitWithError 1 "EC2 instance $(cat instance) timed out after ${timeout} minutes"
}

timeout_monitor 360 &
timeout_monitor_pid=$!

set -o pipefail
ssh -i id_rsa -tt -o "StrictHostKeyChecking no" -p 5022 pi@$(cat instance) 'bash -s' < exescript 2>&1 | ${SCRIPTPATH}/s3streamup.sh s3://${BUCKET}/${LOGFILE} ${NO_SIGN}
ERR=$?

ps -p$timeout_monitor_pid &>/dev/null && kill $timeout_monitor_pid

exitWithError ${ERR} ""

