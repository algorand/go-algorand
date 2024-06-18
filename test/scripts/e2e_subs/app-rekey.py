#!/usr/bin/env python

import os
import sys
from goal import Goal

from datetime import datetime

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} start {stamp}")

goal = Goal(sys.argv[1], autosend=True)

joe = goal.new_account()
flo = goal.new_account()

txinfo, err = goal.pay(goal.account, joe, amt=500_000)
assert not err, err

# Turn off rewards for precise balance checking
txinfo, err = goal.keyreg(joe, nonpart=True)
assert not err, err
joeb = goal.balance(joe)

txinfo, err = goal.pay(goal.account, flo, amt=500_000)
assert not err, err

teal = """
#pragma version 6
 txn ApplicationID
 bz end
 // Use the rekeyed account to make a payment, and give it back
 itxn_begin
  int pay
  itxn_field TypeEnum

  txn Accounts 1
  itxn_field Sender

  txn Accounts 0
  itxn_field Receiver

  int 5
  itxn_field Amount

  txn Accounts 1
  itxn_field RekeyTo
 itxn_submit

end:
 int 1
"""

txinfo, err = goal.app_create(joe, goal.assemble(teal))
assert not err, err
joeb = joeb-1000
app_id = txinfo['application-index']
assert app_id

app_addr = goal.app_address(app_id)
# flo rekeys her account to the app, app spends from it, then rekeys it back
txinfo, err = goal.pay(flo, joe, amt=1, rekey_to=app_addr)
assert not err, err
assert goal.balance(joe) == joeb+1, goal.balance(joe)

# can no longer spend
txinfo, err = goal.pay(flo, joe, amt=1)
assert err
assert goal.balance(joe) == joeb+1, goal.balance(joe)

txinfo, err = goal.app_call(joe, app_id, accounts=[flo])
assert not err, err
joeb = joeb-1000
assert goal.balance(joe) == joeb+6, goal.balance(joe)

# can spend again
txinfo, err = goal.pay(flo, joe, amt=1)
assert not err, err
assert goal.balance(joe) == joeb+7, goal.balance(joe)

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
