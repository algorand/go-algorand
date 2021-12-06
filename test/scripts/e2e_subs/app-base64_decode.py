#!/usr/bin/env python

from datetime import datetime
from pathlib import PurePath
import sys

from goal import Goal, AtomicABI


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

# App create
approval_teal_path = TEAL_DIR / "app-base64_decode.teal"
print(f"approval_teal_path: {approval_teal_path}")
approval_teal = goal.assemble(approval_teal_path)

# create = goal.app_create(joe, approval_teal, local_schema=(1, 0))
create = goal.app_create(joe, approval_teal)
txinfo, err = goal.send(create)
print(f"txinfo for create request: {txinfo}")
assert not err, err

# ABI Method Calls
abi_app_id = txinfo["application-index"]
assert abi_app_id

abi = AtomicABI(goal, abi_app_id, TEAL_DIR / "app-base64_decode.json", joe)
abi.next_abi_call_add(29, 13)

# URL and filename safe baes 64
abi.next_abi_call_base64URL_decode("YWJjMTIzIT8kKiYoKSctPUB-")
abi.next_abi_call_base64URL_decode(
    "TU9CWS1ESUNLOwoKb3IsIFRIRSBXSEFMRS4KCgpCeSBIZXJtYW4gTWVsdmlsbGU="
)
abi.next_abi_call_base64URL_decode("CiBfIF9fIF8KLyB8Li58IFwKXC8gfHwgXC8KIHxfJydffA==")
abi.next_abi_call_base64URL_decode(
    "Cl8uLi5fICAgICAgICAgCiggIiAgXD4gICAgICAgIAogIFwgIFw-ICAgICAgIAogICBcICBcPiAgICAgIAogICAgXCAgXD5fX18gICAgICAgXiAKICstLyAgKy0gICAgIFxfX19fL3wKICAgfCAgQnJvbnR5ICAvLS0tLSsKICAgIFwgICAvIFwgIC8gCiAgICB8IC8gICAgXHwgCiAgICB8fCAgICAgfHwgCiAgIEMuLyAgICBDLi8="
)
# Standard base 64
abi.next_abi_call_base64Std_decode("YWJjMTIzIT8kKiYoKSctPUB+")


executed_methods, summary = abi.execute_all_methods()
summary_str = "\n\n\n".join(map(str, summary))
print(summary_str)

exit(1)
