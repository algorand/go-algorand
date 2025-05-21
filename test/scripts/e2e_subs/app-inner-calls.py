#!/usr/bin/env python

import os
import sys
from goal import Goal
import algosdk.logic as logic

from datetime import datetime

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} start {stamp}")

goal = Goal(sys.argv[1], autosend=True)

joe = goal.new_account()

_, err = goal.pay(goal.account, joe, amt=500_000)
assert not err, err

# Turn off rewards for precise balance checking
_, err = goal.keyreg(joe, nonpart=True)
assert not err, err

# When invoked, this app funds the app that was created in the txn
# before it and invokes its start(asset) method.  Of course, this app must
# be prefunded to do so. And in real life, would want to check its
# sender as access control
fund_previous = """
#pragma version 6
 txn ApplicationID
 bz end

 itxn_begin
  int pay
  itxn_field TypeEnum

  txn GroupIndex
  int 1
  -
  gtxns CreatedApplicationID
  dup
  store 0
  app_params_get AppAddress
  assert
  itxn_field Receiver

  int 1000000
  itxn_field Amount

 itxn_next

  int appl
  itxn_field TypeEnum

  load 0
  itxn_field ApplicationID

  txn GroupIndex
  int 2
  -
  gtxns CreatedAssetID
  itxn_field Assets

  method "start(asset)"
  itxn_field ApplicationArgs

  byte 0x00
  itxn_field ApplicationArgs
 itxn_submit


end:
 int 1
"""

txinfo, err = goal.app_create(joe, goal.assemble(fund_previous))
assert not err, err
funder = txinfo['application-index']
assert funder

# Fund the funder
_, err = goal.pay(goal.account, goal.app_address(funder), amt=4_000_000)
assert not err, err

# Construct a group that creates an ASA and an app, then "starts" the
# new app by funding and invoking "start(asset)" on it. Inside the new
# app's start() method, there will be yet another inner transaction:
# it opts into the supplied asset.

goal.autosend = False
create_asa = goal.asset_create(joe, total=10_000, unit_name="oz", asset_name="Gold")
app_teal = """
#pragma version 6
 txn ApplicationID
 bz end
 txn ApplicationArgs 0
 method "start(asset)"
 ==
 bz next0

 itxn_begin

 int axfer
 itxn_field TypeEnum

 txn ApplicationArgs 1
 btoi
 txnas Assets
 itxn_field XferAsset

 global CurrentApplicationAddress
 itxn_field AssetReceiver

 itxn_submit

next0:

end:
 int 1
"""
create_app = goal.app_create(joe, goal.assemble(app_teal))
start_app = goal.app_call(joe, funder)

[asa_info, app_info, start_info], err = goal.send_group([create_asa, create_app, start_app])
assert not err, err

goal.autosend = True

import json

asa_id = asa_info['asset-index']
app_id = app_info['application-index']
assert asa_id+1 == app_id
app_account = logic.get_application_address(app_id)

# Check balance on app account is right (1m - 1 optin fee)
assert 1_000_000-1000 == goal.balance(app_account), goal.balance(app_account)
assert 0 == goal.balance(app_account, asa_id)
# Check min-balance on app account is right (base + 1 asa)
assert 200_000 == goal.min_balance(app_account), goal.min_balance(app_account)

# Ensure creator can send asa to app
_, err = goal.axfer(joe, app_account, 10, asa_id)
assert not err, err
assert 10 == goal.balance(app_account, asa_id)


stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
