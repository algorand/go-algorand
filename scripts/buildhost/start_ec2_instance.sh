#!/usr/bin/env bash

# start_ec2_instance.sh - Invokes the build host
#
# Syntax:   start_ec2_instance.sh
#
# Usage:    Should only be used by a build host server.
#
# Exit Code: returns 0 if instance started successfully, non-zero otherwise
#
# Examples: scripts/buildhost/start_ec2_instance.sh <AWS_REGION> <AWS_AMI>
#
# Upon successfull execution, the following files would be created:
# sgid - contain the security group identifier
# key.pem - contains the certificate required to log on to the server
# instance - contains the address of the created instance
#

AWS_REGION=$1
AWS_AMI=$2
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
    rm key.pem
    exit 1
fi



aws ec2 run-instances --image-id ${AWS_AMI} --key-name "ARM64BuilderKey${INSTANCE_NUMBER}" --security-groups EC2SecurityGroup${INSTANCE_NUMBER} --instance-type a1.2xlarge --block-device-mappings DeviceName=/dev/sdh,Ebs={VolumeSize=100} --count 1 --region ${AWS_REGION} > instance.json
if [ "$?" != "0" ]; then
    aws ec2 delete-key-pair --key-name "ARM64BuilderKey${INSTANCE_NUMBER}" --region ${AWS_REGION}
    aws ec2 delete-security-group --group-id "${SGID}" --region ${AWS_REGION}
    rm key.pem
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

echo "${SGID}" > sgid
echo "${INSTANCE_NAME}" > instance
echo "${INSTANCE_ID}" > instance-id
echo "ARM64BuilderKey${INSTANCE_NUMBER}" > key-name

