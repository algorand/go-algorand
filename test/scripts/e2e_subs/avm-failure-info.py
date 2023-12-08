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
#pragma version 6
 int 42
 int 7
 store 10
 int 1
 int 2
 -                              // Fail!
end:
 int 1
"""

txinfo, err = goal.app_create(joe, goal.assemble(teal))
print(txinfo)
assert not err, err

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
