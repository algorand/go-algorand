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

txinfo1, err = goal.pay(goal.account, joe, amt=500_000)
assert not err, err

txinfo1, err = goal.keyreg(joe, nonpart=True)
assert not err, err
joeb = goal.balance(joe)

# app1 calls the clear state program of app2 (after opting into it) which issues an
# inner app call to app3. This verifies that both accessing a CSP through inner app
# calls and issuing inner app calls from a CSP is possible.
app1 = """
#pragma version 6
 txn ApplicationID
 bz end

 itxn_begin
  int appl
  itxn_field TypeEnum

  txn Applications 1
  dup
  store 0
  itxn_field ApplicationID

  int OptIn
  itxn_field OnCompletion

  txn Applications 2
  itxn_field Applications

 itxn_next
  int appl
  itxn_field TypeEnum

  load 0
  itxn_field ApplicationID

  txn Applications 2
  itxn_field Applications

  int ClearState
  itxn_field OnCompletion

 itxn_submit


end:
 int 1
"""

app2 = """
#pragma version 6
 txn ApplicationID
 bz end

 itxn_begin
  int appl
  itxn_field TypeEnum

  txn Applications 1
  itxn_field ApplicationID
 itxn_submit


 end:
  int 1
"""

app3 = """
#pragma version 6
int 1
"""

goal.autosend = True

txinfo1, err = goal.app_create(joe, goal.assemble(app1))
assert not err, err
app1ID = txinfo1['application-index']
assert app1ID

# insert clear state program with inner app call
txinfo2, err = goal.app_create(joe, goal.assemble(app2), goal.assemble(app2))
assert not err, err
app2ID = txinfo2['application-index']
assert app2ID

# dummy destination app
txinfo3, err = goal.app_create(joe, goal.assemble(app3))
assert not err, err
app3ID = txinfo3['application-index']
assert app3ID

# fund the apps
txinfo1, err = goal.pay(goal.account, goal.app_address(app1ID), amt=4_000_000)
assert not err, err

txinfo2, err = goal.pay(goal.account, goal.app_address(app2ID), amt=4_000_000)
assert not err, err

# execute c2c w/ CSP
start_app, err = goal.app_call(joe, app1ID, foreign_apps=[int(app2ID), int(app3ID)])
assert not err, err

print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
