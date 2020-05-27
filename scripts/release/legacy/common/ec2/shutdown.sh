#!/usr/bin/env bash
# shellcheck disable=2164

AWS_REGION="${1:-us-west-1}"
GREEN_FG=$(echo -en "\e[32m")
YELLOW_FG=$(echo -en "\e[33m")
END_FG_COLOR=$(echo -en "\e[39m")
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"

pushd "$REPO_ROOT"/tmp > /dev/null
SGID=$(cat sgid)
INSTANCE_ID=$(cat instance-id)
KEY_NAME=$(cat key-name)
popd > /dev/null

echo "$YELLOW_FG[$0]$END_FG_COLOR: Waiting for instance to terminate."
end=$((SECONDS+1200))
PRIOR_INSTANCE_STATE=
while [ $SECONDS -lt $end ]
do
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" > "$REPO_ROOT"/tmp/instance.json
    INSTANCE_CODE=$(< "$REPO_ROOT"/tmp/instance.json jq '.TerminatingInstances[].CurrentState.Code')
    INSTANCE_STATE=$(< "$REPO_ROOT"/tmp/instance.json jq '.TerminatingInstances[].CurrentState.Name')

    if [ "$INSTANCE_CODE" = "48" ]
    then
        echo "$GREEN_FG[$0]$END_FG_COLOR: Instance terminated."
        break
    fi

    if [ "$INSTANCE_STATE" != "$PRIOR_INSTANCE_STATE" ]
    then
        echo "$YELLOW_FG[$0]$END_FG_COLOR: Instance is in state $INSTANCE_STATE..."
        PRIOR_INSTANCE_STATE="$INSTANCE_STATE"
    fi

    sleep 5s
done

if [ "$KEY_NAME" != "" ]
then
    aws ec2 delete-key-pair --key-name "$KEY_NAME" --region "$AWS_REGION"
fi

if [ "$SGID" != "" ]
then
    aws ec2 delete-security-group --group-id "$SGID" --region "$AWS_REGION"
fi

rm -rf BuilderInstanceKey.pem "$REPO_ROOT"/tmp

