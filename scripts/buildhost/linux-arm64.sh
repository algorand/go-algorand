#!/usr/bin/env bash

BUILD_REQUEST=$1
OUTPUTFILE=$2
BUCKET=$3
NO_SIGN=$4

AWS_REGION="us-west-2"
AWS_LINUX_AMI="ami-0c579621aaac8bade"
INSTANCE_NUMBER=$RANDOM

set +e

./start_ec2_instance.sh ${AWS_REGION} ${AWS_LINUX_AMI}
if [ "$?" != "0" ]; then
    exit 1
fi

if [ "$OUTPUTFILE" != "" ]; then
    echo "{ \"error\": 1, \"log\":\"The requested operation is not yet functional\"}" > ./result.json

    aws s3 cp ./result.json s3://${BUCKET}/${OUTPUTFILE} ${NO_SIGN}
fi

./shutdown_ec2_instance.sh ${AWS_REGION}
if [ "$?" != "0" ]; then
    exit 1
fi
