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


# Test that the block timestamp from two blocks ago is between 2 and 5
# (inclusive) seconds before the previous block timestamp. devMode
# might mess this test up.  This works because FirstValid is set to
# the last committed block by SDK, not the next coming one.
teal = """
#pragma version 7
 txn FirstValid
 block BlkTimestamp

 txn FirstValid
 int 1
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
checktimes = goal.assemble(teal)
txinfo, err = goal.app_create(joe, checktimes)
assert not err, err

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

# We want to manipulate lastvalid, so we need to turn off autosend
goal.autosend = False

tx = goal.app_create(joe, goal.assemble(teal))
tx.last_valid_round = tx.last_valid_round - 800
txinfo, err = goal.send(tx)
assert not err, err

# block 0 is not accessible even with a low LastValid
teal = """
#pragma version 7
 int 0
 block BlkTimestamp
"""
tx = goal.app_create(joe, goal.assemble(teal))
tx.last_valid_round = tx.last_valid_round - 800
txinfo, err = goal.send(tx)
assert "round 0 is not available" in str(err), err
assert "outside [1-" in str(err), err  # confirms that we can look back to 1

print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
