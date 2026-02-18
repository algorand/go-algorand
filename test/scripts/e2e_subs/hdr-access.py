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

teal = """
#pragma version 7
 txn FirstValidTime
"""
v7 = goal.assemble(teal)
txinfo, err = goal.app_create(joe, v7)
assert not err, err

# It won't assemble in earlier versions, so manipulate the bytecode to test v6
v6 = bytearray(v7)
v6[0] = 6
txinfo, err = goal.app_create(joe, v6)
assert err
assert "invalid txn field FirstValidTime" in str(err), err


# Can't access two behind FirstValid because LastValid is 1000 after
teal = """
#pragma version 7
 txn FirstValid
 int 2
 -
 block BlkTimestamp
"""
txinfo, err = goal.app_create(joe, goal.assemble(teal))
assert "not available" in str(err), err

# We will be able to access more than one previous block by using a
# shorter tx liftetime. So we test that the block timestamp from two
# blocks ago is between 2 and 5 (inclusive) seconds before the
# previous block timestamp. devMode might mess this test up.
teal = """
#pragma version 7
 txn FirstValid
 int 1
 -
 block BlkTimestamp

 txn FirstValid
 int 2
 -
 block BlkTimestamp
 // last two times are on stack
 -
 dup
 // difference in times is on stack twice

 int 1
 >
 assert

 int 6
 <
"""
txinfo, err = goal.app_create(joe, goal.assemble(teal), lifetime=100)
assert not err, err

# block 0 is not accessible even with a low LastValid
teal = """
#pragma version 7
 int 0
 block BlkTimestamp
"""
txinfo, err = goal.app_create(joe, goal.assemble(teal), lifetime=100)
assert "round 0 is not available" in str(err), err
assert "outside [1-" in str(err), err  # confirms that we can look back to 1


# Get FeeSink from `block` opcode, compare to REST API
teal = """
#pragma version 11
 txn FirstValid
 int 2
 -
 block BlkFeeSink
 log
 int 1
 return
"""
txinfo, err = goal.app_create(joe, goal.assemble(teal), lifetime=100)
assert not err, err
assert len(txinfo["logs"]) == 1
opcode = txinfo["logs"][0]

block = goal.algod.block_info(txinfo['confirmed-round']-2)['block']
api = base64.b64encode(enc.decode_address(block['fees'])).decode("utf-8")

print(opcode, api)

assert opcode == api

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
