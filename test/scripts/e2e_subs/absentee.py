#!/usr/bin/env python

import base64
import os
import sys
from goal import Goal
import algosdk.encoding as enc

from datetime import datetime

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} start {stamp}")

goal = Goal(sys.argv[1], autosend=True)

joe = goal.new_account()

txinfo, err = goal.pay(goal.account, joe, amt=500_000)
assert not err, err

# Joe is a brand new account, it has neither proposed nor heartbeat
joe_info = goal.algod.account_info(joe)
assert "last-proposed" not in joe_info, joe_info
assert "last-heartbeat" not in joe_info, joe_info

# Find info on the proposer of the pay block
pblock = goal.algod.block_info(txinfo['confirmed-round'])['block']
assert pblock["prp"] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
prp_info = goal.algod.account_info(pblock["prp"])
assert "last-proposed" in prp_info, prp_info # they just did!
assert prp_info["last-proposed"] > 0
assert "last-heartbeat" not in prp_info, prp_info # was a genesis account

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
