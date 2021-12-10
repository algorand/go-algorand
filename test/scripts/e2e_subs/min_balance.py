#!/usr/bin/env python

from datetime import datetime
from pathlib import PurePath
import sys

import algosdk.future.transaction as txn

from goal import Goal, AtomicABI

CONSENSUS_MIN_BALANCE = 100_000
ASSET_MIN_BALANCE = 100_000
APP_MIN_BALANCE = 100_000
OPTIN_MIN_BALANCE = 100_000
# app schemas:
APP_KV_MIN_BALANCE = 25_000
APP_INTS_MIN_BALANCE = 3_500
APP_BYTES_MIN_BALANCE = 25_000

EXTRA_PAGE_MIN_BALANCE = (
    APP_MIN_BALANCE  # per userBalance.go::MinBalance() as of Dec 2021
)


# Set INTERACTIVE True if you want to run a remote debugger interactively on the given PORT
INTERACTIVE, DEBUGPORT = False, 4312


def initialize_debugger():
    import multiprocessing

    if multiprocessing.current_process().pid > 1:
        import debugpy

        debugpy.listen(("0.0.0.0", DEBUGPORT))
        print("Debugger is ready to be attached, press F5", flush=True)
        debugpy.wait_for_client()
        print("Visual Studio Code debugger is now attached", flush=True)


if INTERACTIVE:
    initialize_debugger()


def get_pysdk_min_balance(goal, account):
    return goal.algod.account_info(account)["min-balance"]


def get_teal_min_balance(abi, account):
    # can't execute an abi object twice so must clone it before each execution:
    abi = abi.clone(caller_acct=account)
    sender_pymt = txn.PaymentTxn(account, abi.get_suggested_params(), account, 10_000)
    sender_tx_sig = abi.get_txn_with_signer(sender_pymt)

    # TODO: abi.sender_min_balance(sender_tx_sig)
    return abi.execute_singleton("sender_min_balance", method_args=[sender_tx_sig])


def assert_min_balance(abi_or_goal, account, expected_min_balance, skip_abi=False):
    goal = abi_or_goal if skip_abi else abi_or_goal.goal
    algod_mb = get_pysdk_min_balance(goal, account)
    assert (
        algod_mb == expected_min_balance
    ), f"case 1: {algod_mb} != {expected_min_balance}"
    if not skip_abi:
        abi = abi_or_goal
        teal_mb = get_teal_min_balance(abi, account)
        assert algod_mb == teal_mb, f"case 2: {algod_mb} != {teal_mb}"


script_path, WALLET = sys.argv
ppath = PurePath(script_path)

CWD, SCRIPT = ppath.parent, ppath.name
TEAL_DIR = CWD / "tealprogs"

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")

# Initialize goal
goal = Goal(WALLET, autosend=False)
if INTERACTIVE:
    # good to know so you can query the temp REST endpoints
    rest_endpoints = goal.get_endpoint_info()

# Initialize AtomicABI using the min-balance TEAL app:
approval_teal_path = TEAL_DIR / "abi-min_balance.teal"
print(f"approval_teal_path: {approval_teal_path}")
approval_teal = goal.assemble(approval_teal_path)

txinfo, err = goal.app_create(goal.account, approval_teal, send=True)
print(f"txinfo for create request: {txinfo}")
app_id = txinfo["application-index"]
assert_min_balance(
    goal, goal.account, CONSENSUS_MIN_BALANCE + APP_MIN_BALANCE, skip_abi=True
)

# ABI needs funded accounts:
joe = goal.new_account()
flo = goal.new_account()

print(f"Joe & Flo: {joe}, {flo}")

txinfo, err = goal.pay(goal.account, joe, amt=50_000_000, send=True)
txinfo, err = goal.pay(goal.account, flo, amt=100_000_000, send=True)


abi = AtomicABI(goal, app_id, TEAL_DIR / "abi-min_balance.json", joe)


# starting out, should be at global min
assert_min_balance(abi, flo, CONSENSUS_MIN_BALANCE)
assert_min_balance(abi, joe, CONSENSUS_MIN_BALANCE)


# flo creates an asset
txinfo, err = goal.asset_create(
    flo, total=10_000, unit_name="oz", asset_name="Gold", manager=flo, send=True
)
assert not err, err
assets = {"Gold": txinfo["asset-index"]}

expected_mb = CONSENSUS_MIN_BALANCE + ASSET_MIN_BALANCE
assert_min_balance(abi, flo, expected_mb)


# goal creates 2 assets
for total, unit, asset in [(1000, "oz", "Silver"), (100, "oz", "Platinum")]:
    txinfo, err = goal.asset_create(
        goal.account,
        total=total,
        unit_name=unit,
        asset_name=asset,
        manager=goal.account,
        send=True,
    )
    assets[asset] = txinfo["asset-index"]
    assert not err, err

expected_mb = CONSENSUS_MIN_BALANCE + APP_MIN_BALANCE + 2 * ASSET_MIN_BALANCE
assert_min_balance(goal, goal.account, expected_mb, skip_abi=True)

# joe opts into Gold and Silver:
txinfo, err = goal.axfer(joe, joe, 0, assets["Gold"], send=True)
txinfo, err = goal.axfer(joe, joe, 0, assets["Silver"], send=True)
assert not err, err
expected_mb = CONSENSUS_MIN_BALANCE + 2 * ASSET_MIN_BALANCE
assert_min_balance(abi, joe, expected_mb)

# next, destroy Gold and Silver
txinfo, err = goal.acfg(flo, index=assets["Gold"], send=True)
assert not err, err
expected_mb = CONSENSUS_MIN_BALANCE
assert_min_balance(abi, flo, expected_mb)

txinfo, err = goal.acfg(goal.account, index=assets["Silver"], send=True)
assert not err, err
expected_mb = CONSENSUS_MIN_BALANCE + APP_MIN_BALANCE + ASSET_MIN_BALANCE
assert_min_balance(goal, goal.account, expected_mb, skip_abi=True)

# flo creates an app with 2 global schema ints, 10 global schema bytes, 1 extra page
txinfo, err = goal.app_create(
    flo,
    approval_teal,
    local_schema=(2, 0),
    global_schema=(0, 10),
    extra_pages=1,
    send=True,
)
assert not err, err
expected_mb = (
    CONSENSUS_MIN_BALANCE
    + APP_MIN_BALANCE
    # Not these local var requirements because not opting in
    # + 2 * APP_KV_MIN_BALANCE
    # + 2 * APP_INTS_MIN_BALANCE
    + 10 * APP_KV_MIN_BALANCE
    + 10 * APP_BYTES_MIN_BALANCE
    + EXTRA_PAGE_MIN_BALANCE
)
assert_min_balance(abi, flo, expected_mb)

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")
