#!/usr/bin/env python

import os
import sys
from goal import Goal

import algosdk.future.transaction as txn

goal = Goal(sys.argv[1])

joe = goal.new_account()
flo = goal.new_account()

# Pays

pay = goal.pay(goal.account, receiver=joe, amt=10000)
txid, err = goal.send(pay)
assert err

pay = goal.pay(goal.account, receiver=joe, amt=500_000)
txinfo, err = goal.send(pay)
assert not err, err
tx = txinfo['txn']['txn']
assert tx['amt'] == 500_000
assert tx['fee'] == 1000
assert goal.balance(joe) == 500_000

# Asset creation
acfg = goal.acfg(joe,
                 total=10_000, unit_name='oz', asset_name='Gold',
                 freeze=flo)
txinfo, err = goal.send(acfg)
assert not err, err
gold = txinfo['asset-index']
assert goal.balance(joe, gold) == 10_000

# Asset transfer
axfer = goal.axfer(joe, goal.account, 50, gold)
txinfo, err = goal.send(axfer)
assert err
assert goal.balance(joe, gold) == 10_000

optin = goal.axfer(goal.account, goal.account, 0, gold)
txinfo, err = goal.send(optin)
assert not err, err

axfer = goal.axfer(joe, goal.account, 50, gold)
txinfo, err = goal.send(axfer)
assert not err, err
assert goal.balance(joe, gold) == 9_950
assert goal.balance(goal.account, gold) == 50

txinfo, err = goal.send(goal.pay(goal.account, receiver=flo, amt=1500_000))
assert not err, err

# Freezing, and txgroup
assert not goal.holding(goal.account, gold)[1]
freeze1 = goal.afrz(flo, gold, goal.account, True)
freeze2 = goal.afrz(flo, gold, joe, True)
txinfo, err = goal.send_group([freeze1, freeze2])
assert not err, err
assert goal.holding(goal.account, gold)[1]
assert goal.holding(joe, gold)[1]

# App create
teal = "test/scripts/e2e_subs/tealprogs"
approval = goal.assemble(os.path.join(teal, "app-escrow.teal"))
yes = goal.assemble("#pragma version 2\nint 28") # 28 is just to uniquify
create = goal.appl(flo, 0,
                   local_schema=(1, 0),
                   global_schema=(0, 4),
                   approval_program=approval,
                   clear_program=yes)
txinfo, err = goal.send(create)
app_id = txinfo['application-index']
assert app_id

# app_create is a convenience wrapper around appl
create = goal.app_create(flo, approval, local_schema=(1, 0))
txinfo, err = goal.send(create)
assert not err, err

app2_id = txinfo['application-index']
assert app_id

app_info = goal.app_info(app_id)
assert app_info['local-state-schema']['num-uint'] == 1, app_info

# App opt-in
optin = goal.appl(joe, app2_id, txn.OnComplete.OptInOC)
txinfo, err = goal.send(optin)
assert not err, err

# convenience wrapper
optin = goal.app_optin(joe, app_id)
txinfo, err = goal.send(optin)
assert not err, err

# App call, with group
deposit = goal.appl(joe, app_id, app_args=["deposit():void"])
payin = goal.pay(goal.account, goal.app_address(app_id), 150_000)
txinfo, err = goal.send_group([deposit, payin])
assert not err, err

app_info = goal.app_info(app_id)
global_state = goal.app_read(app_id)
assert global_state[b'debug'] == b'deposit', global_state
local_state = goal.app_read(app_id, joe)
assert local_state[b'balance'] == 150_000, local_state

# Pay to logicsig, and spend from there, which requires signing by logicsig
fund = goal.pay(goal.account, goal.logic_address(yes), 110_000)
txinfo, err = goal.send(fund)
assert not err, err

spend = goal.pay(goal.logic_address(yes), joe, 2_000)
spend = goal.sign_with_program(spend, yes)
txinfo, err = goal.send(spend)
assert not err, err
assert goal.balance(goal.logic_address(yes)) == 107_000, goal.balance(goal.logic_address(yes))
