#!/usr/bin/env bash

BUILD_REQUEST=$1
OUTPUTFILE=$2
BUCKET=$3
NO_SIGN=$4

AWS_REGION="us-west-2"
AWS_LINUX_AMI="ami-0c579621aaac8bade"
INSTANCE_NUMBER=$RANDOM

SGID=$(aws ec2 create-security-group --group-name EC2SecurityGroup${INSTANCE_NUMBER} --description "Security Group for ARM64 ephermal build machine to allow port 22" --region ${AWS_REGION} | jq -r '.GroupId')
if [ "$?" != "0" ]; then
    exit 1
fi

aws ec2 authorize-security-group-ingress --group-name EC2SecurityGroup${INSTANCE_NUMBER} --protocol tcp --port 22 --cidr 0.0.0.0/0 --region ${AWS_REGION}
if [ "$?" != "0" ]; then
    aws ec2 delete-security-group --group-id "${SGID}" --region ${AWS_REGION}
    exit 1
fi

aws ec2 create-key-pair --key-name "ARM64BuilderKey${INSTANCE_NUMBER}" --region ${AWS_REGION} | jq -r '.KeyMaterial' > key.pem
if [ "$?" != "0" ]; then
    aws ec2 delete-security-group --group-id "${SGID}" --region ${AWS_REGION}
    exit 1
fi



aws ec2 run-instances --image-id ${AWS_LINUX_AMI} --key-name "ARM64BuilderKey${INSTANCE_NUMBER}" --security-groups EC2SecurityGroup${INSTANCE_NUMBER} --instance-type a1.2xlarge --block-device-mappings DeviceName=/dev/sdh,Ebs={VolumeSize=100} --count 1 --region ${AWS_REGION} > instance.json
if [ "$?" != "0" ]; then
    aws ec2 delete-key-pair --key-name "ARM64BuilderKey${INSTANCE_NUMBER}" --region ${AWS_REGION}
    aws ec2 delete-security-group --group-id "${SGID}" --region ${AWS_REGION}
    exit 1
fi


INSTANCE_ID=$(cat instance.json | jq -r '.Instances[].InstanceId')

echo "Waiting for instance to start"
end=$((SECONDS+90))
while [ $SECONDS -lt $end ]; do
    aws ec2 describe-instance-status --instance-id ${INSTANCE_ID} --region ${AWS_REGION} --include-all-instances > instance2.json
    INSTANCE_CODE=$(cat instance2.json | jq '.InstanceStatuses[].InstanceState.Code')
    INSTANCE_STATE=$(cat instance2.json | jq '.InstanceStatuses[].InstanceState.Name')
    if [ "${INSTANCE_CODE}" = "16" ]; then
        echo "Instance started"
        break
    fi
    if [ "${INSTANCE_STATE}" != "" ]; then
        echo "Instance is ${INSTANCE_STATE}"
    else
        cat instance2.json
    fi
    sleep 1s
done

aws ec2 describe-instances --region ${AWS_REGION} --instance-id ${INSTANCE_ID} > instance2.json
INSTANCE_NAME=$(cat instance2.json | jq -r '.Reservations[].Instances[].PublicDnsName')

echo "Instance name = ${INSTANCE_NAME}"
rm instance.json instance2.json





echo "Waiting for instance to terminate"
end=$((SECONDS+1200))
while [ $SECONDS -lt $end ]; do
    aws ec2 terminate-instances --instance-ids ${INSTANCE_ID} --region ${AWS_REGION} > instance2.json
    INSTANCE_STATE=$(cat instance2.json | jq '.TerminatingInstances[].CurrentState.Name')
    if [ "${INSTANCE_STATE}" != "" ]; then
        echo "Instance is ${INSTANCE_STATE}"
    else
        cat instance2.json
    fi
    sleep 5s
    aws ec2 describe-instance-status --instance-id ${INSTANCE_ID} --region ${AWS_REGION} --include-all-instances > instance2.json
    INSTANCE_CODE=$(cat instance2.json | jq '.InstanceStatuses[].InstanceState.Code')
    INSTANCE_STATE=$(cat instance2.json | jq '.InstanceStatuses[].InstanceState.Name')
    if [ "${INSTANCE_CODE}" = "48" ]; then
        echo "Instance terminated"
        break
    fi
    if [ "${INSTANCE_STATE}" != "" ]; then
        echo "Instance is ${INSTANCE_STATE}"
    else
        cat instance2.json
    fi    
    sleep 10s
done

aws ec2 delete-key-pair --key-name "ARM64BuilderKey${INSTANCE_NUMBER}" --region ${AWS_REGION}

if [ "$OUTPUTFILE" != "" ]; then
    echo "{ \"error\": 1, \"log\":\"The requested operation is not yet functional\"}" > ./result.json

    aws s3 cp ./result.json s3://${BUCKET}/${OUTPUTFILE} ${NO_SIGN}
fi

aws ec2 delete-security-group --group-id "${SGID}" --region ${AWS_REGION}
rm instance2.json key.pem

