#!/usr/bin/env python

from datetime import datetime
from pathlib import PurePath
import sys

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
initialize_debugger(1339)


script_path, WALLET = sys.argv
ppath = PurePath(script_path)

CWD, SCRIPT = ppath.parent, ppath.name
# TEAL_DIR = CWD / "tealprogs"

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
print(f"Running {SCRIPT} inside {CWD} @ {stamp}")

# Initialize goal and fund a new account joe
goal = Goal(WALLET, autosend=True)

joe = goal.new_account()
flo = goal.new_account()
print(f"Joe & Flo: {joe}, {flo}")

txinfo, err = goal.pay(goal.account, joe, amt=50_000_000)
txinfo, err = goal.pay(goal.account, flo, amt=100_000_000)

abi = AtomicABI(
    goal,
)

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

print(f"{os.path.basename(sys.argv[0])} OK {stamp}")
