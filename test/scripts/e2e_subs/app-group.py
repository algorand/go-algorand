#!/usr/bin/env python

import os
import sys
from goal import Goal

from datetime import datetime

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} start {stamp}")

goal = Goal(sys.argv[1], autosend=True)

joe = goal.new_account()

txinfo, err = goal.pay(goal.account, joe, amt=500_000)
assert not err, err

# Turn off rewards for precise balance checking
txinfo, err = goal.keyreg(joe, nonpart=True)
assert not err, err
joeb = goal.balance(joe)

teal = """
#pragma version 6
 txn ApplicationID
 bz end
 // Pay the sender and Accounts[1]. Force the second fee to default high
 itxn_begin
  int pay
  itxn_field TypeEnum

  txn Sender
  itxn_field Receiver

  int 5
  itxn_field Amount

  int 0
  itxn_field Fee                // No fee, so 2nd fee is doubled

 itxn_next

  int pay
  itxn_field TypeEnum

  txn Accounts 1
  itxn_field Receiver

  int 5
  itxn_field Amount

 itxn_submit

 itxn Fee
 int 2000
 ==
 assert

end:
 int 1
"""

txinfo, err = goal.app_create(joe, goal.assemble(teal))
assert not err, err
app_id = txinfo['application-index']
assert app_id

# Fund the app account
txinfo, err = goal.pay(goal.account, goal.app_address(app_id), amt=400_000)
assert not err, err


txinfo, err = goal.app_call(joe, app_id, accounts=[goal.account])
assert not err, err

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
