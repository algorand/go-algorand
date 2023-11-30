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

txinfo, err = goal.pay(goal.account, joe, amt=10_000_000)
assert not err, err

# Joe is a brand new account, it is not incentive eligible
joe_info = goal.algod.account_info(joe)
assert "incentive-eligible" not in joe_info, joe_info

# Go online, but without paying enough to be incentive eligible
txinfo, err = goal.keyreg(joe, votekey=base64.b64encode(b'1'*32),
                          selkey=base64.b64encode(b'1'*32),
                          sprfkey=base64.b64encode(b'1'*64),
                          votekd=1,
                          votefst=1, votelst=2000)
assert not err, err

# No extra fee paid, so not eligible
joe_info = goal.algod.account_info(joe)
assert "incentive-eligible" not in joe_info, joe_info

# Pay the extra fee to become eligible
txinfo, err = goal.keyreg(joe, fee=3_000_000,
                          votekey=base64.b64encode(b'1'*32),
                          selkey=base64.b64encode(b'1'*32),
                          sprfkey=base64.b64encode(b'1'*64),
                          votekd=2,
                          votefst=1, votelst=2000)
assert not err, err
joe_info = goal.algod.account_info(joe)
assert joe_info.get("incentive-eligible", None) == True, joe_info



stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
