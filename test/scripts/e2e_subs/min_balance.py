#!/usr/bin/env python

from base64 import b64decode
from datetime import datetime
from pathlib import PurePath
import sys

from goal import Goal

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


CONSENSUS_MIN_BALANCE = 100_000
ASSET_MIN_BALANCE = 100_000
APP_MIN_BALANCE = 100_000
OPTIN_MIN_BALANCE = 100_000
# app schemas:
APP_KV_MIN_BALANCE = 25_000
APP_INTS_MIN_BALANCE = 3_500
APP_BYTES_MIN_BALANCE = 25_000

# per userBalance.go::MinBalance() as of Dec 2021:
EXTRA_PAGE_MIN_BALANCE = APP_MIN_BALANCE

TEAL = f"""#pragma version 5
byte "Hello Min Balance!"
log

// even when creating the app, calc the min balance:
byte "min_balance="
log

txn Accounts 0
min_balance
itob
log

int 1"""


def get_endpoint_info(goal) -> dict:
    return {
        "algod": {
            "url": goal.algod.algod_address,
            "auth": goal.algod.algod_token,
        },
        "kmd": {
            "url": goal.kmd.kmd_address,
            "auth": goal.kmd.kmd_token,
        },
    }


def get_pysdk_min_balance(goal, account):
    return goal.algod.account_info(account)["min-balance"]


def create_sender_min_balance_app(goal):
    txinfo, err = goal.app_create(goal.account, goal.assemble(TEAL))
    assert not err, f"err: {err}"

    appid = txinfo["application-index"]
    creator_min_balance = int.from_bytes(b64decode(txinfo["logs"][2]), byteorder="big")
    return appid, creator_min_balance


def assert_teal_min_balance(
    goal, account, expected_account_mb, expected_goal_mb, goal_only=False
):
    appid, goal_mb = create_sender_min_balance_app(goal)
    assert (
        goal_mb == expected_goal_mb
    ), f"GOAL teal v. expected: {goal_mb} != {expected_goal_mb}"

    txinfo, err = goal.app_call(account, appid)
    assert not err, f"err = {err}"

    if goal_only:
        return

    min_balance = int.from_bytes(b64decode(txinfo["logs"][2]), byteorder="big")
    assert (
        min_balance == expected_account_mb
    ), f"SENDER teal v. expected: {min_balance} != {expected_account_mb}"


def assert_min_balance(
    goal, account, expected_sender_mb, expected_goal_mb, goal_only=False
):
    algod_mb = get_pysdk_min_balance(goal, account)
    assert (
        algod_mb == expected_sender_mb
    ), f"SENDER algod v. expected: {algod_mb} != {expected_sender_mb}"
    assert_teal_min_balance(
        goal, account, expected_sender_mb, expected_goal_mb, goal_only=goal_only
    )


script_path, WALLET = sys.argv
ppath = PurePath(script_path)

CWD, SCRIPT = ppath.parent, ppath.name
TEAL_DIR = CWD / "tealprogs"

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")

# Initialize goal
goal = Goal(WALLET, autosend=True)
rest_endpoints = get_endpoint_info(goal)
print(f"Python Goal cennected to {rest_endpoints}")


joe = goal.new_account()
flo = goal.new_account()

print(f"Joe & Flo: {joe}, {flo}")

txinfo, err = goal.pay(goal.account, joe, amt=50_000_000, send=True)
txinfo, err = goal.pay(goal.account, flo, amt=100_000_000, send=True)

expected_goal_mb = CONSENSUS_MIN_BALANCE + APP_MIN_BALANCE

# starting out, should be at global min
assert_min_balance(goal, flo, CONSENSUS_MIN_BALANCE, expected_goal_mb)

expected_goal_mb += APP_MIN_BALANCE
assert_min_balance(goal, joe, CONSENSUS_MIN_BALANCE, expected_goal_mb)


# flo creates an asset
txinfo, err = goal.asset_create(
    flo, total=10_000, unit_name="oz", asset_name="Gold", manager=flo, send=True
)
assert not err, err
assets = {"Gold": txinfo["asset-index"]}

expected_mb = CONSENSUS_MIN_BALANCE + ASSET_MIN_BALANCE
expected_goal_mb += APP_MIN_BALANCE
assert_min_balance(goal, flo, expected_mb, expected_goal_mb)


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

expected_goal_mb += 2 * ASSET_MIN_BALANCE
assert_min_balance(
    goal,
    goal.account,
    expected_goal_mb,
    expected_goal_mb + APP_MIN_BALANCE,
    goal_only=True,
)
expected_goal_mb += APP_MIN_BALANCE

# joe opts into Gold and Silver:
txinfo, err = goal.axfer(joe, joe, 0, assets["Gold"], send=True)
txinfo, err = goal.axfer(joe, joe, 0, assets["Silver"], send=True)
assert not err, err

expected_mb = CONSENSUS_MIN_BALANCE + 2 * ASSET_MIN_BALANCE
expected_goal_mb += APP_MIN_BALANCE
assert_min_balance(goal, joe, expected_mb, expected_goal_mb)

# next, destroy Gold and Silver
txinfo, err = goal.acfg(flo, index=assets["Gold"], send=True)
assert not err, err
expected_mb = CONSENSUS_MIN_BALANCE
expected_goal_mb += APP_MIN_BALANCE
assert_min_balance(goal, flo, expected_mb, expected_goal_mb)

txinfo, err = goal.acfg(goal.account, index=assets["Silver"], send=True)
assert not err, err
expected_goal_mb -= ASSET_MIN_BALANCE
assert_min_balance(
    goal,
    goal.account,
    expected_goal_mb,
    expected_goal_mb + APP_MIN_BALANCE,
    goal_only=True,
)
expected_goal_mb += APP_MIN_BALANCE


# flo creates an app with 2 global schema ints, 10 global schema bytes, 1 extra page
txinfo, err = goal.app_create(
    flo,
    goal.assemble(TEAL),
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
expected_goal_mb += APP_MIN_BALANCE
assert_min_balance(goal, flo, expected_mb, expected_goal_mb)

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")
