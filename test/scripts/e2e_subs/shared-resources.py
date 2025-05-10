#!/usr/bin/env python

import os
import sys
import algosdk.encoding as enc
import algosdk.transaction as txn
from goal import Goal

from datetime import datetime

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} start {stamp}")

goal = Goal(sys.argv[1], autosend=True)

joe = goal.new_account()

txinfo, err = goal.pay(goal.account, joe, amt=500_000)
assert not err, err

putTeal = """
#pragma version 8
txn ApplicationID
bz end

txn ApplicationArgs 0
byte 0x1032
txn ApplicationArgs 1
btoi
app_local_put

end: int 1
"""

txinfo, err = goal.app_create(joe, goal.assemble(putTeal),
                              local_schema=(2, 0))
assert not err, err
app_id = txinfo['application-index']
assert app_id

print("goal.account: ", goal.account)
print("joe:          ", joe)

goal.autosend = False
grp1 = goal.app_call(goal.account, app_id,
                     on_complete=txn.OnComplete.OptInOC,
                     app_args=[enc.decode_address(goal.account), 10])
grp2 = goal.app_call(joe, app_id,
                     app_args=[enc.decode_address(goal.account), 20])
[grp1_info, grp2_info], err = goal.send_group([grp1, grp2])

# Won't work, because v8 can't modify an account (goal.account) that
# isn't in the `grp2` txn
assert err
assert "unavailable Account "+goal.account in str(err)

# Now, upgrade program to same thing, but v9

optin = goal.app_call(joe, app_id,
                      on_complete=txn.OnComplete.OptInOC,
                      app_args=[enc.decode_address(joe), 40])
optin_info, err = goal.send(optin)
assert not err, err

putTealV9 = putTeal.replace("#pragma version 8", "#pragma version 9")

update = goal.app_call(joe, app_id,
                       on_complete=txn.OnComplete.UpdateApplicationOC,
                       approval_program=goal.assemble(putTealV9),
                       clear_program=goal.assemble(putTealV9),
                       app_args=[enc.decode_address(joe), 50])
update_info, err = goal.send(update)
assert not err, err

# Works now, because a v9 program is allowed to modify a "non-local"
# account. Under the covers, the txn gets a "SharedAccts" array, and
# the index points there.  But the REST API hides that.
grp1 = goal.app_call(goal.account, app_id,
                     on_complete=txn.OnComplete.OptInOC,
                     app_args=[enc.decode_address(goal.account), 60])
grp2 = goal.app_call(joe, app_id,
                     app_args=[enc.decode_address(goal.account), 70])
[grp1_info, grp2_info], err = goal.send_group([grp1, grp2])
assert not err, err

# Both txns should have a local-state-delta that modified
# goal.account, even though that would have been impossible in v8
# because goal.account does not appear in the `grp2` transaction.
assert len(grp1_info["local-state-delta"]) == 1
assert grp1_info["local-state-delta"][0]["address"] == goal.account
assert grp1_info["local-state-delta"][0]["delta"][0]["value"]["uint"] == 60

assert len(grp2_info["local-state-delta"]) == 1
assert grp2_info["local-state-delta"][0]["address"] == goal.account
assert grp2_info["local-state-delta"][0]["delta"][0]["value"]["uint"] == 70

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
