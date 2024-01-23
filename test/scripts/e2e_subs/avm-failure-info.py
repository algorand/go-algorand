#!/usr/bin/env python

import os
import json
import subprocess
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
 byte 0x1a00011afb                // be sure to test non-ascii logs
 byte 0x2a00012afc                // be sure to test non-ascii logs
 log
 log
 int 42
 byte 0x4a01004afa                // be sure to test non-ascii stack
 int 7
 store 10
 byte 0x4a00014afe                // be sure to test non-ascii scratch
 store 12
 int 1
 int 2
 -                              // Fail!
end:
 int 1
"""

tx = goal.app_create(joe, goal.assemble(teal), send=False)
command = goal.curl_command(tx)
response = subprocess.check_output(command, shell=True)
j = json.loads(response)
print(j)
assert j['data']['pc'] == 45
assert j['data']['group-index'] == 0
assert j['data']['app-index'] > 1000
assert j['data']['eval-states'][0]['scratch'][10] == 7
assert j['data']['eval-states'][0]['scratch'][12] == 'SgABSv4='
assert j['data']['eval-states'][0]['stack'] == [42, 'SgEASvo=', 1, 2]
assert j['data']['eval-states'][0]['logs'] == ['KgABKvw=', 'GgABGvs=']

# Test some omit-empty behavior. That `scratch` simply doesn't appear,
# and that `logs` does appear, even if the only log entry is an empty
# message.
teal = """
#pragma version 6
 byte 0x; log                   // Log (only) an empty msg
 int 1
 int 2
 -                              // Fail!
end:
 int 1
"""

tx = goal.app_create(joe, goal.assemble(teal), send=False)
command = goal.curl_command(tx)
response = subprocess.check_output(command, shell=True)
j = json.loads(response)
print(j)

assert j['data']['group-index'] == 0
assert 'scratch' not in j['data']['eval-states'][0]
assert j['data']['eval-states'][0]['logs'] == ['']
assert j['data']['pc'] == 10

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
