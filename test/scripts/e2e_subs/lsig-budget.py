#!/usr/bin/env python

import os
import sys
from goal import Goal
import algosdk.logic as logic

from datetime import datetime

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} start {stamp}")

goal = Goal(sys.argv[1], autosend=True)

# This lsig runs keccak256 (cost=130) the number of times in its first
# logicsig arg, then accepts.  In effect, it accepts if it has enough
# budget to run the number of hashes requested. The program consumes 6
# opcodes in the base case (args[0] == 0), and 137 for each loop.
run_hashes = """
#pragma version 6
 arg 0
 btoi
loop:
 dup
 bz end
 byte 0x0102030405060708
 keccak256
 pop
 int 1
 -
 b loop
end:
 pop                            // the 0 loop variable
 int 1
"""

code = goal.assemble(run_hashes)
escrow = goal.logic_address(code)

# Fund the lsig's escrow account
_, err = goal.pay(goal.account, escrow, amt=1_000_000)
assert not err, err

# Construct a transaction that uses the lsig. Can't send, because we
# have to fill in the lsig (and args)
tx = goal.pay(escrow, escrow, amt=0, note=b'5', send=False)
# 5 loops is fine (20k budget)
stx = goal.sign_with_program(tx, code, [(5).to_bytes(8, "big")])
txinfo, err = goal.send(stx)
assert not err, err

# 145 loops is fine 6+145*137 < 20k budget
tx = goal.pay(escrow, escrow, amt=0, note=b'145', send=False)
stx = goal.sign_with_program(tx, code, [(145).to_bytes(8, "big")])
txinfo, err = goal.send(stx)
assert not err, err

# 146 is not 6+146*137 = 20,008 (20k budget)
tx = goal.pay(escrow, escrow, amt=0, note=b'146', send=False)
stx = goal.sign_with_program(tx, code, [(146).to_bytes(8, "big")])
txinfo, err = goal.send(stx)
assert "dynamic cost budget exceeded, executing keccak256" in str(err)

# Now, try pooling across multiple logicsigs 39988/137 = 291.xxx
tx0 = goal.pay(escrow, escrow, amt=0, note=b'200', send=False)
tx1 = goal.pay(escrow, escrow, amt=0, note=b'91', send=False)
stx0 = goal.sign_with_program(tx0, code, [(200).to_bytes(8, "big")])
stx1 = goal.sign_with_program(tx1, code, [(91).to_bytes(8, "big")])
txinfo, err = goal.send_group([stx0, stx1])
assert not err, err

# order doesn't matter
tx0.group = None
tx1.group = None
txinfo, err = goal.send_group([stx1, stx0])  # rearrange
assert not err, err

# 292 is too much
tx0 = goal.pay(escrow, escrow, amt=0, note=b'200', send=False)
tx1 = goal.pay(escrow, escrow, amt=0, note=b'92', send=False)
stx0 = goal.sign_with_program(tx0, code, [(200).to_bytes(8, "big")])
stx1 = goal.sign_with_program(tx1, code, [(92).to_bytes(8, "big")])
txinfo, err = goal.send_group([stx0, stx1])
assert "dynamic cost budget exceeded, executing keccak256" in str(err)

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
