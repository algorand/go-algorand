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

AWS_REGION=${1-us-east-1}
GREEN_FG=$(echo -en "\e[32m")
YELLOW_FG=$(echo -en "\e[33m")
END_FG_COLOR=$(echo -en "\e[39m")

#if [ "$AWS_REGION" = "" ]
#then
#    echo "Missing AWS_REGION argument"
#    exit 1
#fi

pushd tmp > /dev/null
SGID=$(cat sgid)
INSTANCE_ID=$(cat instance-id)
#INSTANCE_NAME=$(cat instance)
KEY_NAME=$(cat key-name)
popd > /dev/null

echo "$YELLOW_FG[$0]$END_FG_COLOR: Waiting for instance to terminate."
end=$((SECONDS+1200))
PRIOR_INSTANCE_STATE=
while [ $SECONDS -lt $end ]
do
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" > tmp/instance.json
    INSTANCE_CODE=$(< tmp/instance.json jq '.TerminatingInstances[].CurrentState.Code')
    INSTANCE_STATE=$(< tmp/instance.json jq '.TerminatingInstances[].CurrentState.Name')

    if [ "$INSTANCE_CODE" = "48" ]
    then
        echo "$GREEN_FG[$0]$END_FG_COLOR: Instance terminated."
        break
    fi

    if [ "$INSTANCE_STATE" != "$PRIOR_INSTANCE_STATE" ]
    then
        echo "$YELLOW_FG[$0]$END_FG_COLOR: Instance is in state $INSTANCE_STATE..."
        PRIOR_INSTANCE_STATE="$INSTANCE_STATE"
#    else
#        cat tmp/instance.json
    fi

    sleep 5s
#    aws ec2 describe-instance-status --instance-id "$INSTANCE_ID" --region "$AWS_REGION" --include-all-instances > tmp/instance.json
#    INSTANCE_CODE=$(< tmp/instance.json jq '.InstanceStatuses[].InstanceState.Code')
#    INSTANCE_STATE=$(< tmp/instance.json jq '.InstanceStatuses[].InstanceState.Name')
#
#    if [ "$INSTANCE_CODE" = "48" ]
#    then
#        echo "$GREEN_FG[$0]$END_FG_COLOR: Instance terminated."
#        break
#    fi
#
#    if [ "$INSTANCE_STATE" != "$PRIOR_INSTANCE_STATE" ]
#    then
#        echo "$YELLOW_FG[$0]$END_FG_COLOR: Instance is in state $INSTANCE_STATE..."
#        PRIOR_INSTANCE_STATE="$INSTANCE_STATE"
##    else
##        cat tmp/instance.json
#    fi
#    sleep 10s
done

if [ "$KEY_NAME" != "" ]
then
    aws ec2 delete-key-pair --key-name "$KEY_NAME" --region "$AWS_REGION"
fi

if [ "$SGID" != "" ]
then
    aws ec2 delete-security-group --group-id "$SGID" --region "$AWS_REGION"
fi

rm -rf BuilderInstanceKey.pem tmp

