#!/usr/bin/env bash

# shutdown_ec2_instance.sh - Invokes the build host
#
# Syntax:   shutdown_ec2_instance.sh
#
# Usage:    Should only be used by a build host server.
#
# Exit Code: returns 0 if instance stop successfully, non-zero otherwise
#
# Examples: scripts/buildhost/shutdown_ec2_instance.sh <AWS_REGION>
#
#

AWS_REGION=$1

if [ "${AWS_REGION}" = "" ]; then
    echo "Missing AWS_REGION argument"
    exit 1
fi

SGID=$(cat sgid)
INSTANCE_ID=$(cat instance-id)
KEY_NAME=$(cat key-name)

echo "Waiting for instance to terminate"
end=$((SECONDS+1200))
while [ $SECONDS -lt $end ]; do
    aws ec2 terminate-instances --instance-ids "${INSTANCE_ID}" --region "${AWS_REGION}" > instance2.json
    INSTANCE_CODE=$(jq '.TerminatingInstances[].CurrentState.Code' < instance2.json)
    INSTANCE_STATE=$(jq '.TerminatingInstances[].CurrentState.Name' < instance2.json)
    if [ "${INSTANCE_CODE}" = "48" ]; then
        echo "Instance terminated"
        break
    fi
    if [ "${INSTANCE_STATE}" != "" ]; then
        echo "Instance is ${INSTANCE_STATE}"
    else
        cat instance2.json
    fi
    sleep 5s
    aws ec2 describe-instance-status --instance-id "${INSTANCE_ID}" --region "${AWS_REGION}" --include-all-instances > instance2.json
    INSTANCE_CODE=$(jq '.InstanceStatuses[].InstanceState.Code' < instance2.json)
    INSTANCE_STATE=$(jq '.InstanceStatuses[].InstanceState.Name' < instance2.json)
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

if [ "${KEY_NAME}" != "" ]; then
    aws ec2 delete-key-pair --key-name "${KEY_NAME}" --region "${AWS_REGION}"
fi

if [ "${SGID}" != "" ]; then
    aws ec2 delete-security-group --group-id "${SGID}" --region "${AWS_REGION}"
fi

rm instance2.json sgid instance-id instance key-name
rm -f key.pem
