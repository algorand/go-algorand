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
# the following is the base linux AMI
#AWS_LINUX_AMI="ami-06f2f779464715dc5"
# this is the private AMI that contains the RasPI VM running on port 5022
AWS_LINUX_AMI="ami-077aa2f293886f758"
AWS_INSTANCE_TYPE="t2.2xlarge"
INSTANCE_NUMBER=$RANDOM

set +e

${SCRIPTPATH}/start_ec2_instance.sh ${AWS_REGION} ${AWS_LINUX_AMI} ${AWS_INSTANCE_TYPE}
if [ "$?" != "0" ]; then
    popd
    rm -rf ${TMPPATH}
    exit 1
fi

scp -i key.pem -o "StrictHostKeyChecking no" ubuntu@$(cat instance):/home/ubuntu/armv6_stretch/id_rsa ./id_rsa

echo "Waiting for RasPI SSH connection"
end=$((SECONDS+90))
while [ $SECONDS -lt $end ]; do
    ssh -i id_rsa -o "StrictHostKeyChecking no" -p 5022 pi@$(cat instance) "uname -a"
    if [ "$?" = "0" ]; then
        echo "RasPI SSH connection ready"
        break
    fi
    sleep 1s
done

BRANCH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_BRANCH')
COMMIT_HASH=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_COMMIT')
PULL_REQUEST=$(cat $BUILD_REQUEST | jq -r '.TRAVIS_PULL_REQUEST')
BUILD_AWS_ACCESS_KEY_ID=$(cat $BUILD_REQUEST | jq -r '.AWS_ACCESS_KEY_ID')
BUILD_AWS_SECRET_ACCESS_KEY=$(cat $BUILD_REQUEST | jq -r '.AWS_SECRET_ACCESS_KEY')


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
 ./scripts/travis/build.sh
FOE

ssh -i id_rsa -o "StrictHostKeyChecking no" -p 5022 pi@$(cat instance) 'bash -s' < exescript 2>&1 | ${SCRIPTPATH}/s3streamup.sh s3://${BUCKET}/${LOGFILE} ${NO_SIGN}
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
