#!/usr/bin/env python

import os
import sys
from goal import Goal

from datetime import datetime

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} start {stamp}")

goal = Goal(sys.argv[1], autosend=True)

joe = goal.new_account()

_, err = goal.pay(goal.account, joe, amt=500_000_000)
assert not err, err

_, err = goal.keyreg(joe, nonpart=True)
assert not err, err

# On creation app1 does nothing to avoid fee complications. Further calls to app1 must
# contain an app arg that determines the execution path. An arg value of 0 opts app1 
# into app2 while a nonzero value issues an inner app call to app2's CSP. This verifies
# that accessing a CSP with inner app calls is possible.
app1 = """
#pragma version 6
 txn ApplicationID
 bz end

 int 0
 txn ApplicationArgs 0
 btoi
 ==
 bz nxt

 itxn_begin
  int appl
  itxn_field TypeEnum

  txn Applications 1
  itxn_field ApplicationID

  txn Applications 2
  itxn_field Applications

  int OptIn
  itxn_field OnCompletion

 itxn_submit
 b end

 nxt:
 itxn_begin
  int appl
  itxn_field TypeEnum

  txn Applications 1
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
pushbytes "success"
log
int 1
"""

goal.autosend = True

# app1 creation
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

# fund app1
_, err = goal.pay(goal.account, goal.app_address(app1ID), amt=4_000_000)
assert not err, err

# fund app2
_, err = goal.pay(goal.account, goal.app_address(app2ID), amt=4_000_000)
assert not err, err

# execute c2c to opt app1 into app2 and verify that the response is structured as
# expected for a successful execution of all 3 apps.
txinfo, err = goal.app_call(joe, app1ID, app_args=[0x00], foreign_apps=[int(app2ID), int(app3ID)])
assert not err, err
assert len(txinfo["inner-txns"]) == 1
assert len(txinfo["inner-txns"][0]["inner-txns"]) == 1
assert len(txinfo["inner-txns"][0]["inner-txns"][0]["logs"]) == 1

# execute c2c w/ CSP to opt app1 out of app2. Note that the CSP of app2 attempts
# to issue an inner app call, which is not allowed. The expected behavior is for
# the CSP to fail (so app3 won't be called) but for the Clear State operation to
# succeed.
txinfo, err = goal.app_call(joe, app1ID, app_args=[0x01], foreign_apps=[int(app2ID), int(app3ID)])
assert not err, err
assert len(txinfo["inner-txns"]) == 1
assert "inner-txns" not in txinfo["inner-txns"][0]

# attempt additional CSP inner app call that's intended to fail because app1 is
# no longer opted into app2 after previous call to CSP.
_, err = goal.app_call(joe, app1ID, app_args=[0x01], foreign_apps=[int(app2ID), int(app3ID)])
assert err
assert "is not currently opted in" in str(err)

# opt app1 into app2 again and call CSP again to verify that re optin works as expected
_, err = goal.app_call(joe, app1ID, app_args=[0x00], foreign_apps=[int(app2ID), int(app3ID)])
assert not err, err

_, err = goal.app_call(joe, app1ID, app_args=[0x01], foreign_apps=[int(app2ID), int(app3ID)])
assert not err, err

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
