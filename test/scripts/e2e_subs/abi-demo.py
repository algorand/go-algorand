#!/usr/bin/env python

from datetime import datetime
from pathlib import PurePath
import sys

from goal import Goal, AtomicABI

import algosdk.future.transaction as txn


def initialize_debugger():
    import multiprocessing

    if multiprocessing.current_process().pid > 1:
        import debugpy

        debugpy.listen(("0.0.0.0", 9999))
        print("Debugger is ready to be attached, press F5", flush=True)
        debugpy.wait_for_client()
        print("Visual Studio Code debugger is now attached", flush=True)


# uncomment out the following to run a remote interactive debug session on port 9999
# initialize_debugger()

script_path, WALLET = sys.argv
ppath = PurePath(script_path)

CWD, SCRIPT = ppath.parent, ppath.name
TEAL_DIR = CWD / "tealprogs"


stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")


# Initialize goal and fund a new account joe
goal = Goal(WALLET, autosend=False)

joe = goal.new_account()
print(f"Joe's account: {joe}")

pay = goal.pay(goal.account, joe, amt=100_000_000)
txinfo, err = goal.send(pay)
assert not err, err

jb = goal.balance(joe)
joe_bal = f"Joe's balance: {jb:,} µAlgo"
print(joe_bal)
assert jb == 100_000_000


# ABI Method Calls

# App create
approval_abi = goal.assemble(TEAL_DIR / "abi-demo.teal")
create = goal.app_create(joe, approval_abi)
txinfo, err = goal.send(create)
assert not err, err

abi_app_id = txinfo["application-index"]
assert abi_app_id

abi = AtomicABI(goal, abi_app_id, TEAL_DIR / "abi-demo.json", joe)
pymt = txn.PaymentTxn(joe, abi.get_suggested_params(), joe, 10_000)
txn_sgn = abi.get_txn_with_signer(pymt)

abi.next_abi_call_add(29, 13)
abi.next_abi_call_sub(3, 1)
abi.next_abi_call_div(4, 2)
abi.next_abi_call_mul(3, 2)
abi.next_abi_call_qrem(27, 5)
abi.next_abi_call_reverse("desrever yllufsseccus")
abi.next_abi_call_txntest(10_000, txn_sgn, 1000)
abi.next_abi_call_manyargs(*([2] * 20))
abi.next_abi_call__closeOut(1)
abi.next_abi_call__optIn(1)
abi.next_abi_call_concat_strings(["this", "string", "is", "joined"])

executed_methods, summary = abi.execute_all_methods()
print("\n".join(map(str, summary)))


stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Finished {SCRIPT} inside {CWD} @ {stamp}")


# Uncomment the following if you want to print out the test output:
# exit(1)
