#!/usr/bin/env bash

date '+assets-app start %Y%m%d_%H%M%S'

set -ex
set -o pipefail
export SHELLOPTS

CREATOR=$(goal account list | grep 500 | sort | head -n 1 | cut -d '	' -f 3)
ALICE=$(goal account list | grep 500 | sort | head -n 2 | tail -n 1 | cut -d '	' -f 3)
BOB=$(goal account list | grep 500 | sort | head -n 3 | tail -n 1 | cut -d '	' -f 3)
ZERO='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'
SUPPLY=10000000
XFER1=1000
XFER2=42
XFER3=99999
XFER4=11
DEFAULTFROZEN=0

APP_CREATED_STR='Created app with app index'
ERR_APP_CL_STR='only clearing out is supported for applications that do not exist'
ERR_APP_NE_STR='application does not exist'
ERR_APP_OI_STR1='has not opted in to application'
ERR_APP_OI_STR2='not opted in to app'
ERR_APP_OI_STR3='is not currently opted in'
ERR_APP_REJ_STR1='transaction rejected by ApprovalProgram'
ERR_APP_REJ_STR2='TEAL runtime encountered err opcode'
ERR_APP_REJ_STR3='- would result negative'
CREATE_SCRIPT="{args: [{encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"int\", value: \"$SUPPLY\"}, {encoding: \"int\", value: \"$DEFAULTFROZEN\"}]}"
XFER0_SCRIPT="{args: [{encoding: \"int\", value: \"$XFER1\"}], accounts: [\"$BOB\", \"$ZERO\"]}"
XFER1_SCRIPT="{args: [{encoding: \"int\", value: \"$XFER1\"}], accounts: [\"$ALICE\", \"$ZERO\"]}"
XFER2_SCRIPT="{args: [{encoding: \"int\", value: \"$XFER2\"}], accounts: [\"$CREATOR\", \"$ZERO\"]}"
XFER3_SCRIPT="{args: [{encoding: \"int\", value: \"$XFER3\"}], accounts: [\"$BOB\", \"$ZERO\"]}"
XFER4_SCRIPT="{args: [{encoding: \"int\", value: \"$XFER4\"}], accounts: [\"$CREATOR\", \"$BOB\"]}"
XFER5_SCRIPT="{args: [{encoding: \"int\", value: \"0\"}], accounts: [\"$ZERO\", \"$ALICE\"]}"
FREEZE_SCRIPT="{args: [{encoding: \"int\", value: \"1\"}], accounts: [\"$ALICE\"]}"
UNFREEZE_SCRIPT="{args: [{encoding: \"int\", value: \"0\"}], accounts: [\"$ALICE\"]}"

### Basic reading, creation, deletion, transfers, and freezing

# create
APP_ID=$(goal app create --approval-prog appprog.teal --clear-prog appclear.teal --creator $CREATOR --global-byteslices 5 --global-ints 4 --local-byteslices 0 --local-ints 2 --app-input <(jq -n "$CREATE_SCRIPT") | grep "$APP_CREATED_STR" | cut -d ' ' -f 6)

# read global
RES=$(goal app read --guess-format --app-id $APP_ID --global | jq -r .tt.u)
if [[ $RES != $SUPPLY ]]; then
    date "+assets-app FAIL expected supply to be set to $SUPPLY %Y%m%d_%H%M%S"
    false
fi

RES=$(goal app read --guess-format --app-id $APP_ID --global | jq -r .bl.u)
if [[ $RES != $SUPPLY ]]; then
    date "+assets-app FAIL expected creator to begin with $SUPPLY %Y%m%d_%H%M%S"
    false
fi

# read alice F
RES=$(goal app read --guess-format --app-id $APP_ID --local -f $ALICE 2>&1 || true)
if [[ $RES != *"$ERR_APP_OI_STR1"* ]]; then
    date '+assets-app FAIL expected read of non-opted in account to fail %Y%m%d_%H%M%S'
    false
fi

# optin alice
goal app optin --app-id $APP_ID -f $ALICE

# read alice
RES=$(goal app read --guess-format --app-id $APP_ID --local -f $ALICE | jq .bl.u)
if [[ $RES != 'null' ]]; then
    date '+assets-app FAIL expected opted-in account to start with no balance %Y%m%d_%H%M%S'
    false
fi

RES=$(goal app read --guess-format --app-id $APP_ID --local -f $ALICE | jq .fz.u)
if [[ $RES != 'null' ]]; then
    date '+assets-app FAIL expected opted-in account to be non-frozen %Y%m%d_%H%M%S'
    false
fi

# xfer0 creator -> bob F
RES=$(goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER0_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_OI_STR2"* ]]; then
    date '+assets-app FAIL transfer succeeded on account which has not opted in %Y%m%d_%H%M%S'
    false
fi
    
# xfer1 (2) creator -> alice
goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER1_SCRIPT")
goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER1_SCRIPT")

# read alice
RES=$(goal app read --guess-format --app-id $APP_ID --local -f $ALICE | jq .bl.u)
if [[ $RES != $(( $XFER1 + $XFER1 )) ]]; then
    date "+assets-app FAIL transfer recipient does not have $XFER1 %Y%m%d_%H%M%S"
    false
fi

# delete F
RES=$(goal app delete --app-id $APP_ID -f $CREATOR 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR1"* ]]; then
    date "+assets-app FAIL should not be able to delete asset while outstanding holdings exist %Y%m%d_%H%M%S"
    false
fi

# freeze
goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$FREEZE_SCRIPT")

# xfer2 alice -> creator F
RES=$(goal app call --app-id $APP_ID -f $ALICE --app-input <(jq -n "$XFER2_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR2"* ]]; then
    date "+assets-app FAIL frozen account should not be able to send %Y%m%d_%H%M%S"
    false
fi

# xfer1 creator -> alice F
RES=$(goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER1_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR2"* ]]; then
    date "+assets-app FAIL frozen account should not be able to receive %Y%m%d_%H%M%S"
    false
fi

# unfreeze
goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$UNFREEZE_SCRIPT")

# xfer1 creator -> alice
goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER1_SCRIPT")

# xfer5 alice |-> alice F
RES=$(goal app closeout --app-id $APP_ID -f $ALICE --app-input <(jq -n "$XFER5_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR1"* ]]; then
    date "+assets-app FAIL closing to self not permitted %Y%m%d_%H%M%S"
    false
fi

# optin bob
goal app optin --app-id $APP_ID -f $BOB

# xfer3 alice -> bob overdraw F
RES=$(goal app call --app-id $APP_ID -f $ALICE --app-input <(jq -n "$XFER3_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR3"* ]]; then
    date "+assets-app FAIL overdraws are not permitted %Y%m%d_%H%M%S"
    false
fi

# xfer4 alice -> creator |-> bob
goal app closeout --app-id $APP_ID -f $ALICE --app-input <(jq -n "$XFER4_SCRIPT")

# xfer5 bob |-> alice F
RES=$(goal app closeout --app-id $APP_ID -f $BOB --app-input <(jq -n "$XFER5_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_OI_STR2"* ]]; then
    date "+assets-app FAIL overdraws are not permitted %Y%m%d_%H%M%S"
    false
fi

# optin alice
goal app optin --app-id $APP_ID -f $ALICE

# xfer5 bob |-> alice
goal app closeout --app-id $APP_ID -f $BOB --app-input <(jq -n "$XFER5_SCRIPT")

# clear alice
goal app clear --app-id $APP_ID -f $ALICE

# clear alice F
RES=$(goal app clear --app-id $APP_ID -f $ALICE 2>&1 || true)
if [[ $RES != *"$ERR_APP_OI_STR3"* ]]; then
    date "+assets-app FAIL should not be able to clear asset holding twice %Y%m%d_%H%M%S"
    false
fi

# delete
goal app delete --app-id $APP_ID -f $CREATOR

# delete F
RES=$(goal app delete --app-id $APP_ID -f $CREATOR 2>&1 || true)
if [[ $RES != *"$ERR_APP_CL_STR"* ]]; then
    date '+assets-app FAIL second deletion of application should fail %Y%m%d_%H%M%S'
    false
fi

# optin alice F
RES=$(goal app optin --app-id $APP_ID -f $ALICE 2>&1 || true)
if [[ $RES != *"$ERR_APP_CL_STR"* ]]; then
    date '+assets-app FAIL optin of deleted application should fail %Y%m%d_%H%M%S'
    false
fi

# read global F
RES=$(goal app read --guess-format --app-id $APP_ID --global 2>&1 || true)
if [[ $RES != *"$ERR_APP_NE_STR"* ]]; then
    date '+assets-app FAIL read global of deleted application should fail %Y%m%d_%H%M%S'
    false
fi

### Reconfiguration, default-frozen, and clawback

MANAGER=$(goal account list | grep 500 | sort | head -n 4 | tail -n 1 | cut -d '	' -f 3)
DEFAULTFROZEN=1

CREATE_SCRIPT="{args: [{encoding: \"addr\", value: \"$MANAGER\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"addr\", value: \"$MANAGER\"}, {encoding: \"addr\", value: \"$MANAGER\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"int\", value: \"$SUPPLY\"}, {encoding: \"int\", value: \"$DEFAULTFROZEN\"}]}"

# note that creator, supply, and defaultfrozen are ignored
RECONFIG_SCRIPT="{args: [{encoding: \"addr\", value: \"$MANAGER\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"addr\", value: \"$ALICE\"}, {encoding: \"addr\", value: \"$MANAGER\"}, {encoding: \"addr\", value: \"$CREATOR\"}, {encoding: \"int\", value: \"$SUPPLY\"}, {encoding: \"int\", value: \"$DEFAULTFROZEN\"}]}"

CLOSEOUT_SCRIPT="{args: [{encoding: \"int\", value: \"0\"}], accounts: [\"$ZERO\", \"$CREATOR\"]}"
CLAW1_SCRIPT="{args: [{encoding: \"int\", value: \"$XFER1\"}, {encoding: \"int\", value: \"0\"}], accounts: [\"$CREATOR\", \"$BOB\"]}"
CLAW2_SCRIPT="{args: [{encoding: \"int\", value: \"$XFER1\"}, {encoding: \"int\", value: \"0\"}], accounts: [\"$BOB\", \"$CREATOR\"]}"

# create frozen
APP_ID=$(goal app create --approval-prog appprog.teal --clear-prog appclear.teal --creator $CREATOR --global-byteslices 5 --global-ints 4 --local-byteslices 0 --local-ints 2 --app-input <(jq -n "$CREATE_SCRIPT") | grep "$APP_CREATED_STR" | cut -d ' ' -f 6)

# delete bad manager F
RES=$(goal app delete --app-id $APP_ID -f $CREATOR 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR1"* ]]; then
    date "+assets-app FAIL non-manager should not be able to delete asset %Y%m%d_%H%M%S"
    false
fi

# optin alice
goal app optin --app-id $APP_ID -f $ALICE

# xfer1 F
RES=$(goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER1_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR2"* ]]; then
    date "+assets-app FAIL frozen account should not be able to receive %Y%m%d_%H%M%S"
    false
fi

# bad unfreeze F
RES=$(goal app call --app-id $APP_ID -f $ALICE --app-input <(jq -n "$UNFREEZE_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR1"* ]]; then
    date "+assets-app FAIL non-freezer should not be able to unfreeze account %Y%m%d_%H%M%S"
    false
fi

# set freezer alice
goal app call --app-id $APP_ID -f $MANAGER --app-input <(jq -n "$RECONFIG_SCRIPT")

# unfreeze
goal app call --app-id $APP_ID -f $ALICE --app-input <(jq -n "$UNFREEZE_SCRIPT")

# xfer1
goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER1_SCRIPT")

# freeze
goal app call --app-id $APP_ID -f $ALICE --app-input <(jq -n "$FREEZE_SCRIPT")

# xfer1 F
RES=$(goal app call --app-id $APP_ID -f $CREATOR --app-input <(jq -n "$XFER1_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR2"* ]]; then
    date "+assets-app FAIL re-frozen account should not be able to receive %Y%m%d_%H%M%S"
    false
fi

# closeout F
RES=$(goal app call --app-id $APP_ID -f $ALICE --app-input <(jq -n "$CLOSEOUT_SCRIPT") 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR2"* ]]; then
    date "+assets-app FAIL frozen account should not be able to closeout w/o clear %Y%m%d_%H%M%S"
    false
fi

# clear alice
goal app clear --app-id $APP_ID -f $ALICE

# optin bob
goal app optin --app-id $APP_ID -f $BOB

# clawback transfer
goal app call --app-id $APP_ID -f $MANAGER --app-input <(jq -n "$CLAW1_SCRIPT")

# delete F
RES=$(goal app delete --app-id $APP_ID -f $MANAGER 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR1"* ]]; then
    date "+assets-app FAIL should not be able to delete asset while outstanding holdings exist %Y%m%d_%H%M%S"
    false
fi

# clawback
goal app call --app-id $APP_ID -f $MANAGER --app-input <(jq -n "$CLAW2_SCRIPT")

# delete
goal app delete --app-id $APP_ID -f $MANAGER

# clear bob
goal app clear --app-id $APP_ID -f $BOB
