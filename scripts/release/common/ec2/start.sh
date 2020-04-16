#!/usr/bin/env bash
# shellcheck disable=2164

AWS_REGION="$1"
AWS_AMI="$2"
AWS_INSTANCE_TYPE="$3"
INSTANCE_NUMBER=$RANDOM
KEY_NAME=algorand_baseline
KEY_NAME_FILE=algorand_baseline.pem
SECURITY_GROUP_NAME="ReleaseBuildMachineSSH_$INSTANCE_NUMBER"
CIDR="0.0.0.0/0"
RED_FG=$(echo -en "\e[31m")
GREEN_FG=$(echo -en "\e[32m")
YELLOW_FG=$(echo -en "\e[33m")
END_FG_COLOR=$(echo -en "\e[39m")
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"

cleanup () {
    rm -rf "$REPO_ROOT"/tmp
}

delete_security_group () {
    if ! aws ec2 delete-security-group --group-id "$SGID" --region "$AWS_REGION"
    then
        exit 1
        echo "$RED_FG[$0]$END_FG_COLOR: Security group was not deleted!"
    fi
}

manage_instance_info () {
    pushd "$REPO_ROOT"/tmp > /dev/null
    rm instance*.json
    echo "$SGID" > sgid
    echo "$INSTANCE_NAME" > instance
    echo "$INSTANCE_ID" > instance-id
    echo "$KEY_NAME" > key-name
    popd > /dev/null
    echo "$GREEN_FG[$0]$END_FG_COLOR: Created $REPO_ROOT/tmp/ dir containing instance information."
}

if ! SGID=$(aws ec2 create-security-group --group-name "$SECURITY_GROUP_NAME" --description "Security Group for ephemeral build machine to allow port 22" --region "$AWS_REGION" | jq -r '.GroupId')
then
    exit 1
fi

for port in {22,5022}
do
    if ! aws ec2 authorize-security-group-ingress --group-name "$SECURITY_GROUP_NAME" --protocol tcp --port $port --cidr "$CIDR" --region "$AWS_REGION"
    then
        delete_security_group
        echo "$RED_FG[$0]$END_FG_COLOR: There was a problem opening port $port!"
        exit 1
    fi
done

mkdir -p "$REPO_ROOT/tmp"

if ! aws ec2 run-instances --image-id "$AWS_AMI" --key-name "$KEY_NAME" --security-groups "$SECURITY_GROUP_NAME" --instance-type "$AWS_INSTANCE_TYPE" --tag-specifications "ResourceType=instance,Tags=[{Key=\"Name\",Value=\"Release_Build_Ephemeral_${INSTANCE_NUMBER}\"}, {Key=\"For\",Value=\"Release_Build_Ephemeral\"}]" --block-device-mappings '{ "DeviceName": "/dev/sda1", "Ebs": { "VolumeSize": 40 } }' --count 1 --region "$AWS_REGION" > "$REPO_ROOT"/tmp/instance.json
then
    echo "$RED_FG[$0]$END_FG_COLOR: There was a problem launching the instance! Deleting the security group and the key pair!"
    delete_security_group
    cleanup
    exit 1
fi

INSTANCE_ID=$(< "$REPO_ROOT"/tmp/instance.json jq -r '.Instances[].InstanceId')

echo "$YELLOW_FG[$0]$END_FG_COLOR: Waiting for instance to start."
end=$((SECONDS+90))
PRIOR_INSTANCE_STATE=
while [ $SECONDS -lt $end ]
do
    aws ec2 describe-instance-status --instance-id "$INSTANCE_ID" --region "$AWS_REGION" --include-all-instances > "$REPO_ROOT"/tmp/instance2.json
    INSTANCE_CODE=$(< "$REPO_ROOT"/tmp/instance2.json jq '.InstanceStatuses[].InstanceState.Code')
    INSTANCE_STATE=$(< "$REPO_ROOT"/tmp/instance2.json jq '.InstanceStatuses[].InstanceState.Name')

    if [ "$INSTANCE_CODE" == "16" ]
    then
        echo "$GREEN_FG[$0]$END_FG_COLOR: Instance started."
        break
    fi

    if [ "$INSTANCE_STATE" != "$PRIOR_INSTANCE_STATE" ]
    then
        echo "$YELLOW_FG[$0]$END_FG_COLOR: Instance is in state $INSTANCE_STATE..."
        PRIOR_INSTANCE_STATE="$INSTANCE_STATE"
    fi

    sleep 1s
done

aws ec2 describe-instances --region "$AWS_REGION" --instance-id "$INSTANCE_ID" > "$REPO_ROOT"/tmp/instance2.json
INSTANCE_NAME=$(< "$REPO_ROOT"/tmp/instance2.json jq -r '.Reservations[].Instances[].PublicDnsName')
echo "$GREEN_FG[$0]$END_FG_COLOR: Instance name = $INSTANCE_NAME"

manage_instance_info

echo "$YELLOW_FG[$0]$END_FG_COLOR: Waiting for SSH connection"
end=$((SECONDS+90))
while [ $SECONDS -lt $end ]
do
    if ssh -i "$KEY_NAME_FILE" -o "StrictHostKeyChecking no" "ubuntu@$INSTANCE_NAME" "uname"
    then
        echo "$GREEN_FG[$0]$END_FG_COLOR: SSH connection ready"
        exit 0
    fi

    sleep 1s
done

echo "$RED_FG[$0]$END_FG_COLOR: Unable to establish SSH connection"
cleanup
exit 1

