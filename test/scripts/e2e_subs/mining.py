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

_, err = goal.pay(goal.account, joe, amt=500_000)
assert not err, err

# Turn off rewards for precise balance checking
_, err = goal.keyreg(joe, nonpart=True)
assert not err, err

get_proposer = """
#pragma version 11
 txn ApplicationArgs 0; btoi
 block BlkProposer; global ZeroAddress; !=; assert

 txn ApplicationArgs 0; btoi
 block BlkProposer; log

 txn ApplicationArgs 0; btoi
 block BlkFeesCollected; itob; log

 int 1
"""



# During construction, the app examines an arbitrary round, a little before the latest.
examined = max(goal.params().first-5, 1)
txinfo, err = goal.app_create(joe, goal.assemble(get_proposer), app_args=[examined], lifetime=50)
assert not err, err
getter = txinfo['application-index']
assert getter

# There should be two logs, the proposer of the examined round, and the fees from that round
rnd = txinfo['confirmed-round']
# Look at the block of the creation. We know fees collected is non-zero
block = goal.algod.block_info(rnd)['block']
assert "fc" in block
assert block["fc"] > 0           # We don't test exact, because other tests are running
assert "prp" in block
assert block["prp"] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

create_proposer = block["prp"]
immediately_after = goal.balance(create_proposer)
assert immediately_after > 10000000 # Our proposers in e2e tests have pretty much all the money

# Compare the examined block's header to what the AVM saw (and logged)
block = goal.algod.block_info(examined)['block']
print("creation", txinfo['logs'], block)
assert base64.b64decode(txinfo['logs'][0]) == enc.decode_address(block['prp'])
assert base64.b64decode(txinfo['logs'][1]) == block.get('fc',0).to_bytes(8, "big")

# Now have the app examine the round the app was constructed, so we
# can check the log and know there should be a fee.
goal.wait_for_block(rnd+1)      # because fv is set to current latest (rnd), so it `block rnd` wouldn't work
txinfo, err = goal.app_call(joe, getter, app_args=[rnd], lifetime=10)
assert not err, err

block = goal.algod.block_info(rnd)['block']
# note we use block['fc'], not block.get('fc', 0)
print("call", txinfo['logs'], block)
assert base64.b64decode(txinfo['logs'][0]) == enc.decode_address(block['prp'])
assert base64.b64decode(txinfo['logs'][1]) == block['fc'].to_bytes(8, "big")

# We can not do checks on whether the proposer actually gets paid here
# because in our e2e tests, the proposers _won't_ get paid.  Their
# accounts have too many algos.

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
