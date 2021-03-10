#!/usr/bin/env bash

# start_ec2_instance.sh - Invokes the build host
#
# Syntax:   start_ec2_instance.sh
#
# Usage:    Should only be used by a build host server.
#
# Exit Code: returns 0 if instance started successfully, non-zero otherwise
#
# Examples: scripts/buildhost/start_ec2_instance.sh <AWS_REGION> <AWS_AMI> <AWS_INSTANCE_TYPE>
#
# Upon successful execution, the following files would be created:
# sgid - contain the security group identifier
# key.pem - contains the certificate required to log on to the server
# instance - contains the address of the created instance
#

set -eo pipefail

AWS_REGION=$1
AWS_AMI=$2
AWS_INSTANCE_TYPE=$3
INSTANCE_NUMBER=$RANDOM
KEY_NAME="BuilderInstanceKey_${INSTANCE_NUMBER}"
SECURITY_GROUP_NAME="BuilderMachineSSH_${INSTANCE_NUMBER}"

function security_group_exists {
    if aws ec2 describe-security-groups --group-name "${SECURITY_GROUP_NAME}" --region "$AWS_REGION" > /dev/null 2>&1; then
        echo "WARNING: security group ${SECURITY_GROUP_NAME} exists"
        return 0
    fi
    
    return 1
}

function key_pair_exists {
    if aws ec2 describe-key-pairs --key-names "${KEY_NAME}" --region "$AWS_REGION" > /dev/null 2>&1; then
        echo "WARNING: key pair ${KEY_NAME} exists"
        return 0
    fi
        return 1
}

while security_group_exists || key_pair_exists; do
    echo "Selecting new random instance number"
    INSTANCE_NUMBER=$RANDOM
    KEY_NAME="BuilderInstanceKey_${INSTANCE_NUMBER}"
    SECURITY_GROUP_NAME="BuilderMachineSSH_${INSTANCE_NUMBER}"
done

if ! SGID=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} --description "Security Group for ephemeral build machine to allow port 22" --region "${AWS_REGION}" | jq -r '.GroupId') ; then
    exit 1
fi

if ! aws ec2 authorize-security-group-ingress --group-name ${SECURITY_GROUP_NAME} --protocol tcp --port 22 --cidr 0.0.0.0/0 --region "${AWS_REGION}" ; then
    aws ec2 delete-security-group --group-id "${SGID}" --region "${AWS_REGION}"
    exit 1
fi

if ! aws ec2 authorize-security-group-ingress --group-name ${SECURITY_GROUP_NAME} --protocol tcp --port 5022 --cidr 0.0.0.0/0 --region "${AWS_REGION}" ; then
    aws ec2 delete-security-group --group-id "${SGID}" --region "${AWS_REGION}"
    exit 1
fi

rm -f key.pem
if ! aws ec2 create-key-pair --key-name "${KEY_NAME}" --region "${AWS_REGION}" | jq -r '.KeyMaterial' > key.pem ; then
    aws ec2 delete-security-group --group-id "${SGID}" --region "${AWS_REGION}"
    rm key.pem
    exit 1
fi

if ! aws ec2 run-instances --image-id "${AWS_AMI}" --key-name "${KEY_NAME}" --security-groups ${SECURITY_GROUP_NAME} --instance-type "${AWS_INSTANCE_TYPE}" --tag-specifications "ResourceType=instance,Tags=[{Key=\"Name\",Value=\"Buildhost_Ephermal_Instance_${INSTANCE_NUMBER}\"}, {Key=\"For\",Value=\"Buildhost_Ephermal_Instance\"}]" --block-device-mappings DeviceName="/dev/sdh,Ebs={VolumeSize=100}" --count 1 --region "${AWS_REGION}" > instance.json ; then
    aws ec2 delete-key-pair --key-name "${KEY_NAME}" --region "${AWS_REGION}"
    aws ec2 delete-security-group --group-id "${SGID}" --region "${AWS_REGION}"
    rm key.pem
    exit 1
fi


INSTANCE_ID=$(jq -r '.Instances[].InstanceId' < instance.json)

echo "Waiting for instance to start"
end=$((SECONDS+90))
while [ $SECONDS -lt $end ]; do
    aws ec2 describe-instance-status --instance-id "${INSTANCE_ID}" --region "${AWS_REGION}" --include-all-instances > instance2.json
    INSTANCE_CODE=$(jq '.InstanceStatuses[].InstanceState.Code' < instance2.json)
    INSTANCE_STATE=$(jq '.InstanceStatuses[].InstanceState.Name' < instance2.json)
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

aws ec2 describe-instances --region "${AWS_REGION}" --instance-id "${INSTANCE_ID}" > instance2.json
INSTANCE_NAME=$(jq -r '.Reservations[].Instances[].PublicDnsName' < instance2.json)

echo "Instance name = ${INSTANCE_NAME}"
rm instance.json instance2.json

echo "${SGID}" > sgid
echo "${INSTANCE_NAME}" > instance
echo "${INSTANCE_ID}" > instance-id
echo "${KEY_NAME}" > key-name
chmod 400 key.pem


echo "Waiting for SSH connection"
end=$((SECONDS+90))
while [ $SECONDS -lt $end ]; do
    if ssh -i key.pem -o "StrictHostKeyChecking no" ubuntu@"$(cat instance)" "uname" ; then
        echo "SSH connection ready"
        exit 0
    fi
    sleep 1s
done

echo "error: Unable to establish SSH connection"

# Fallthrough error condition - run shutdown to delete security group, keypair, and instance
"$(cd "$(dirname "$0")" && pwd)"/shutdown_ec2_instance.sh "$AWS_REGION"

exit 1
