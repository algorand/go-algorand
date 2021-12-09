#!/usr/bin/env python

from datetime import datetime
from pathlib import PurePath
import sys

import algosdk.future.transaction as txn

from goal import Goal, AtomicABI


def initialize_debugger(port):
    import multiprocessing

    if multiprocessing.current_process().pid > 1:
        import debugpy

        debugpy.listen(("0.0.0.0", port))
        print("Debugger is ready to be attached, press F5", flush=True)
        debugpy.wait_for_client()
        print("Visual Studio Code debugger is now attached", flush=True)


# uncomment out the following to run a remote interactive debug session:
initialize_debugger(1330)


script_path, WALLET = sys.argv
ppath = PurePath(script_path)

CWD, SCRIPT = ppath.parent, ppath.name
TEAL_DIR = CWD / "tealprogs"

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")

# Initialize goal and fund a new account joe
goal = Goal(WALLET, autosend=False)

joe = goal.new_account()
flo = goal.new_account()
print(f"Joe & Flo: {joe}, {flo}")

txinfo, err = goal.pay(goal.account, joe, amt=50_000_000, send=True)
txinfo, err = goal.pay(goal.account, flo, amt=100_000_000, send=True)

# App create
approval_teal_path = TEAL_DIR / "abi-min_balance.teal"
print(f"approval_teal_path: {approval_teal_path}")
approval_teal = goal.assemble(approval_teal_path)

txinfo, err = goal.app_create(joe, approval_teal, send=True)
print(f"txinfo for create request: {txinfo}")
app_id = txinfo["application-index"]

abi = AtomicABI(goal, app_id, TEAL_DIR / "abi-min_balance.json", flo)

# Dummy complement call (for now)
abi.next_abi_call_complement(bytes.fromhex("00ff00ff"))
executed_methods, summary = abi.execute_atomic_group()


# def min_balances(abi, joe, flo):
#     abi = abi.clone()

#     joe_sig = abi.get_atxn_signer(sender=joe)
#     flo_sig = abi.get_atxn_signer(sender=flo)

#     joe_pymt = txn.PaymentTxn(joe, abi.get_suggested_params(), flo, 10_000)
#     joe_tx_sig = abi.get_txn_with_signer(joe_pymt, signer=joe_sig)

#     flo_pymt = txn.PaymentTxn(flo, abi.get_suggested_params(), joe, 10_000)
#     flo_tx_sig = abi.get_txn_with_signer(flo_pymt, signer=flo_sig)

#     abi.next_abi_call_sender_min_balance(joe_tx_sig)
#     abi.next_abi_call_sender_min_balance(flo_tx_sig)
#     _, summaries = abi.execute_atomic_group()
#     return {
#         "joe_minb": summaries[0].result.return_value,
#         "flo_minb": summaries[1].result.return_value,
#     }


def min_balance(abi, sender, receiver):
    abi = abi.clone()

    sender_sig = abi.get_atxn_signer(sender=sender)
    sender_pymt = txn.PaymentTxn(sender, abi.get_suggested_params(), receiver, 10_000)
    sender_tx_sig = abi.get_txn_with_signer(sender_pymt, signer=sender_sig)

    return abi.execute_singleton("sender_min_balance", method_args=[sender_tx_sig])


joe_minb = min_balance(abi, joe, flo)
flo_minb = min_balance(abi, flo, joe)

x = 42
# abi.next_abi_call_add(29, 13)
# abi.next_abi_call_sub(3, 1)
# abi.next_abi_call_div(4, 2)
# abi.next_abi_call_mul(3, 2)
# abi.next_abi_call_qrem(27, 5)
# abi.next_abi_call_reverse("desrever yllufsseccus")
# abi.next_abi_call_txntest(10_000, txn_sgn, 1000)


# flo_mb1 = min_balance(flo)
# joe_mb1 = min_balance(joe)
x = 42

"""
	ledger.NewAccount(ep.Txn.Txn.Sender, 234)
	ledger.NewAccount(ep.Txn.Txn.Receiver, 123)

	testApp(t, "int 0; min_balance; int 1001; ==", ep)
	// Sender makes an asset, min balance goes up
	ledger.NewAsset(ep.Txn.Txn.Sender, 7, basics.AssetParams{Total: 1000})
	testApp(t, "int 0; min_balance; int 2002; ==", ep)
	schemas := makeApp(1, 2, 3, 4)
	ledger.NewApp(ep.Txn.Txn.Sender, 77, schemas)
	// create + optin + 10 schema base + 4 ints + 6 bytes (local
	// and global count b/c NewApp opts the creator in)
	minb := 2*1002 + 10*1003 + 4*1004 + 6*1005
	testApp(t, fmt.Sprintf("int 0; min_balance; int %d; ==", 2002+minb), ep)
	// request extra program pages, min balance increase
	withepp := makeApp(1, 2, 3, 4)
	withepp.ExtraProgramPages = 2
	ledger.NewApp(ep.Txn.Txn.Sender, 77, withepp)
	minb += 2 * 1002
	testApp(t, fmt.Sprintf("int 0; min_balance; int %d; ==", 2002+minb), ep)

	testApp(t, "int 1; min_balance; int 1001; ==", ep) // 1 == Accounts[0]
	testProg(t, "txn Accounts 1; min_balance; int 1001; ==", directRefEnabledVersion-1,
		expect{2, "min_balance arg 0 wanted type uint64..."})
	testProg(t, "txn Accounts 1; min_balance; int 1001; ==", directRefEnabledVersion)
	testApp(t, "txn Accounts 1; min_balance; int 1001; ==", ep) // 1 == Accounts[0]
	// Receiver opts in
	ledger.NewHolding(ep.Txn.Txn.Receiver, 7, 1, true)
	testApp(t, "int 1; min_balance; int 2002; ==", ep) // 1 == Accounts[0]

	testApp(t, "int 2; min_balance; int 1001; ==", ep, "invalid Account reference 2")
"""

teal = """
#pragma version 6
 txn ApplicationID
 bz end
 // Pay the sender and Accounts[1]. Force the second fee to default high
 itxn_begin
  int pay
  itxn_field TypeEnum

  txn Sender
  itxn_field Receiver

  int 5
  itxn_field Amount

  int 0
  itxn_field Fee                // No fee, so 2nd fee is doubled

 itxn_next

  int pay
  itxn_field TypeEnum

  txn Accounts 1
  itxn_field Receiver

  int 5
  itxn_field Amount

 itxn_submit

 itxn Fee
 int 2000
 ==
 assert

end:
 int 1
"""

txinfo, err = goal.app_create(joe, goal.assemble(teal))
assert not err, err
app_id = txinfo["application-index"]
assert app_id

# Fund the app account
txinfo, err = goal.pay(goal.account, goal.app_address(app_id), amt=400_000)
assert not err, err


txinfo, err = goal.app_call(joe, app_id, accounts=[goal.account])
assert not err, err


stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")
