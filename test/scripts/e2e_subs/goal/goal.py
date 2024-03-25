#!/usr/bin/env python

import base64
import glob
import os
import subprocess

import algosdk
import algosdk.transaction as txn
import algosdk.encoding as enc


def text(path):
    try:
        return open(path, "rt").read().strip()
    except FileNotFoundError:
        return None


def kv_to_dict(kv_list):
    return {
        base64.b64decode(kv["key"]): (
            kv["value"]["uint"]
            if kv["value"]["type"] == 2
            else base64.b64decode(kv["value"]["bytes"])
        )
        for kv in kv_list
    }


class Goal:
    """Goal offers the convenience of goal to Python.

    Python offers a much better programming environment than shell,
    but the `goal` command is so convenient that our e2e subs have
    been written in sh to take advantage of it.  On the other hand,
    goal offers responses in fairly ad-hoc ways, so we find ourselves
    grepping/awking out IDs, performing contortions around error
    responses, and so on.

    Using a Goal object, new e2e tests written in Python should be
    able to create and sign transactions conveniently, submit them,
    and obtain structured responses.  We should add methods as needed
    to resemble the command-line interfaces offered by goal (but
    hopefully even better, when it comes to transaction group creation
    and submission).

    """

    def __init__(
        self,
        name=None,
        *,
        algorand_data=None,
        algod_token=None,
        algod_address=None,
        kmd_token=None,
        kmd_address=None,
        autosend=None,
    ):
        self.algod = None
        self.kmd = None
        algodata = algorand_data or os.environ.get("ALGORAND_DATA")
        if algodata:
            self.algod = self.open_algod(algodata)
            self.kmd = self.open_kmd(algodata)

        if not self.algod:
            algod_token = algod_token or os.environ.get("ALGOD_TOKEN")
            algod_address = algod_address or os.environ.get("ALGOD_ADDRESS")
            if algod_token and algod_address:
                self.algod = self.open_algod(algod_token, algod_address)

        assert self.algod, "No datadir or creds for algod"

        if not self.kmd:
            kmd_token = kmd_token or os.environ.get("KMD_TOKEN")
            kmd_address = kmd_address or os.environ.get("KMD_ADDRESS")
            if kmd_token and kmd_address:
                self.kmd = self.open_kmd(kmd_token, kmd_address)

        if self.kmd:
            self.open_wallet(name)
        # internal wallets has address->sk mappings, so we can sign
        # txns easily, even without kmd.
        self.internal_wallet = {}

        self.autosend = autosend

    def open_algod(self, algodata, algod_address=None):
        if algod_address:
            algod_token = algodata
        else:
            algod_token = text(os.path.join(algodata, "algod.token"))
            net = text(os.path.join(algodata, "algod.net"))
            if not net:
                return None
            algod_address = "http://" + net
        return algosdk.v2client.algod.AlgodClient(algod_token, algod_address)

    def open_kmd(self, algodata, kmd_address=None):
        if kmd_address:
            kmd_token = algodata
        else:
            dir = sorted(glob.glob(os.path.join(algodata, "kmd-*")))[-1]
            if not dir:
                return None
            kmd_token = text(os.path.join(dir, "kmd.token"))
            net = text(os.path.join(dir, "kmd.net"))
            if not net:
                return None
            kmd_address = "http://" + net
        return algosdk.kmd.KMDClient(kmd_token, kmd_address)

    def open_wallet(self, name):
        if name:
            self.wallet_name = name
            wallet = None
            for w in self.kmd.list_wallets():
                if w["name"] == name:
                    wallet = w

            assert wallet, f"No wallet named '{name}'"
            self.handle = self.kmd.init_wallet_handle(wallet["id"], "")
            keys = self.kmd.list_keys(self.handle)
            assert len(keys) == 1
            self.account = keys[0]

    def sign(self, tx):
        # If already signed, do nothing (might be SignedTransaction,
        # LogicSigTransaction, MultisigTransaction)
        if not isinstance(tx, txn.Transaction):
            return tx
        # If we have the key in this object, sign directly
        sk = self.internal_wallet.get(tx.sender)
        if sk:
            return tx.sign(sk)
        # Ask KMD to sign.
        if not self.kmd:
            raise Exception(f"Unable to sign {tx}")
        try:
            return self.kmd.sign_transaction(self.handle, "", tx)
        except algosdk.error.KMDHTTPError:
            self.open_wallet(self.wallet_name)
            return self.kmd.sign_transaction(self.handle, "", tx)

    def sign_with_program(self, tx, program, args=None, delegator=None):
        if delegator:
            raise Exception("haven't implemented delgated logicsig yet")
        return txn.LogicSigTransaction(tx, txn.LogicSig(program, args))

    def send(self, tx, confirm=True):
        try:
            txid = self.algod.send_transaction(self.sign(tx))
            if not confirm:
                return txid, ""
            return self.confirm(txid), ""
        except algosdk.error.AlgodHTTPError as e:
            return (None, e)

    def send_details(self, tx):
        stx = self.sign(tx)
        headers = {"Content-Type": "application/x-binary",
                   "X-Algo-API-Token": self.algod.algod_token,
        }
        url = self.algod.algod_address + "/v2/transactions"
        return (url, headers, enc.msgpack_encode(stx))

    def curl_command(self, tx):
        (url, headers, b64data) = self.send_details(tx)
        H = " ".join(['-H "' + k + ':' + v + '"' for k,v in headers.items()])
        return f"echo {b64data} | base64 -d | curl -s {url} {H} --data-binary @-"

    def send_group(self, txns, confirm=True):
        # Need unsigned transactions to calculate the group This pulls
        # out the unsigned tx if tx is sigged, logicsigged or
        # multisigged
        utxns = [
            tx if isinstance(tx, txn.Transaction) else tx.transaction
            for tx in txns
        ]
        gid = txn.calculate_group_id(utxns)
        for tx in txns:
            if isinstance(tx, txn.Transaction):
                tx.group = gid
            else:
                tx.transaction.group = gid
        txids = [utxn.get_txid() for utxn in utxns]
        try:
            stxns = [self.sign(tx) for tx in txns]
            self.algod.send_transactions(stxns)
            if not confirm:
                return txids, None
            return [self.confirm(txid) for txid in txids], None
        except algosdk.error.AlgodHTTPError as e:
            return (txids, e)

    def status(self):
        return self.algod.status()

    def confirm(self, txid):
        """Wait for txid to be confirmed by the network."""
        last_round = self.status().get("last-round")
        txinfo = self.algod.pending_transaction_info(txid)
        while txinfo.get("confirmed-round", 0) < 1:
            last_round += 1
            self.algod.status_after_block(last_round)
            txinfo = self.algod.pending_transaction_info(txid)
        return txinfo

    def wait_for_block(self, block):
        """
        Utility function to wait until the given block has been confirmed
        """
        print(f"Waiting for block {block}.")
        s = self.algod.status()
        last_round = s["last-round"]
        while last_round < block:
            wait_block = min(block, last_round + 3)
            print(f" waiting for {last_round}...")
            s = self.algod.status_after_block(wait_block)
            last_round = s["last-round"]
        return s

    def new_account(self):
        key, addr = algosdk.account.generate_account()
        self.add_account(addr, key)
        return addr

    def add_account(self, address, key):
        assert len(address) == 58, address
        assert len(key) == 88, key
        self.internal_wallet[address] = key

    def finish(self, tx, send):
        if send is None:
            send = self.autosend
        if send:
            return self.send(tx, confirm=True)
        return tx

    def keyreg(self, sender, votekey=None, selkey=None, votefst=None,
               votelst=None, votekd=None, sprfkey=None,
               send=None, **kwargs):
        params = self.params(kwargs.pop("lifetime", 1000), kwargs.pop("fee", None))
        tx = txn.KeyregTxn(sender, params,
                           votekey, selkey, votefst, votelst, votekd, sprfkey=sprfkey,
                           **kwargs)
        return self.finish(tx, send)

    def pay(self, sender, receiver, amt: int, send=None, **kwargs):
        params = self.params(kwargs.pop("lifetime", 1000), kwargs.pop("fee", None))
        tx = txn.PaymentTxn(sender, params, receiver, amt, **kwargs)
        return self.finish(tx, send)

    def acfg(self, sender, send=None, **kwargs):
        params = self.params(kwargs.pop("lifetime", 1000), kwargs.pop("fee", None))
        tx = txn.AssetConfigTxn(
            sender, params, **kwargs, strict_empty_address_check=False
        )
        return self.finish(tx, send)

    def asset_create(self, sender, **kwargs):
        assert not kwargs.pop("index", None)
        return self.acfg(sender, **kwargs)

    def axfer(self, sender, receiver, amt: int, index: int, send=None, **kwargs):
        params = self.params(kwargs.pop("lifetime", 1000), kwargs.pop("fee", None))
        tx = txn.AssetTransferTxn(
            sender, params, receiver, amt, index, **kwargs
        )
        return self.finish(tx, send)

    def asset_optin(self, sender, index: int, **kwargs):
        assert not kwargs.pop("receiver", None)
        return self.axfer(sender, sender, 0, index, **kwargs)

    def afrz(self, sender, index: int, target, frozen, send=None, **kwargs):
        params = self.params(kwargs.pop("lifetime", 1000), kwargs.pop("fee", None))
        tx = txn.AssetFreezeTxn(sender, params, index, target, frozen, **kwargs)
        return self.finish(tx, send)

    def coerce_schema(self, values):
        if not values:
            return None
        if isinstance(values, txn.StateSchema):
            return values
        return txn.StateSchema(num_uints=values[0], num_byte_slices=values[1])


    def params(self, lifetime=None, fee=None):
        params = self.algod.suggested_params()
        if lifetime is not None:
            params.last = params.first + lifetime
        if fee is not None:
            params.flat_fee = True
            params.fee = fee
        return params

    def appl(self, sender, index: int, on_complete=txn.OnComplete.NoOpOC,
             send=None, **kwargs):
        params = self.params(kwargs.pop("lifetime", 1000), kwargs.pop("fee", None))
        local_schema = self.coerce_schema(kwargs.pop("local_schema", None))
        global_schema = self.coerce_schema(kwargs.pop("global_schema", None))
        tx = txn.ApplicationCallTxn(
            sender,
            params,
            index,
            on_complete,
            local_schema=local_schema,
            global_schema=global_schema,
            **kwargs,
        )
        return self.finish(tx, send)

    def app_create(
        self,
        sender,
        approval_program,
        clear_program=None,
        on_complete=txn.OnComplete.NoOpOC,
        **kwargs,
    ):
        assert not kwargs.pop("index", None)
        if not clear_program:
            approve = f"#pragma version {approval_program[0]}\nint 1"
            clear_program = self.assemble(approve)
        return self.appl(
            sender,
            0,
            on_complete=on_complete,
            approval_program=approval_program,
            clear_program=clear_program,
            **kwargs,
        )

    def app_optin(self, sender, index: int, **kwargs):
        assert not kwargs.pop("on_complete", None)
        return self.appl(sender, index, on_complete=txn.OnComplete.OptInOC, **kwargs)

    def app_call(self, sender, index: int, **kwargs):
        return self.appl(sender, index, **kwargs)

    def balance(self, account, asa=None):
        if asa:
            return self.holding(account, asa)[0]
        info = self.algod.account_info(account)
        return info["amount"]

    def min_balance(self, account):
        info = self.algod.account_info(account)
        return info["min-balance"]

    def holding(self, account, asa):
        info = self.algod.account_info(account)
        for asset in info["assets"]:
            if asset["asset-id"] == asa:
                return (asset["amount"], asset["is-frozen"])
        raise Exception("not opted in")

    def assemble(self, source):
        try:
            with open(source, "rb") as f:
                source = f.read()
        except OSError:
            source = source.encode("utf-8")

        # CI runs with Python 3.6, which does not have capture_output.
        # proc = subprocess.run(["goal", "clerk", "compile", "-"],
        #                       input=source, capture_output=True)
        try:
            proc = subprocess.run(
                ["goal", "clerk", "compile", "-"],
                input=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert proc.returncode == 0, proc.stderr.decode()
            return proc.stdout
        except FileNotFoundError:  # no goal
            return self.assemble_with_rest(source.decode())

    def assemble_with_rest(self, source):
        compile_response = self.algod.compile(source)
        return base64.b64decode(compile_response["result"])

    def app_info(self, index: int) -> dict:
        return self.algod.application_info(index)["params"]

    def app_read(self, index: int, user=None) -> dict:
        if user:
            info = self.algod.account_info(user)
            for ls in info["apps-local-state"]:
                if ls["id"] == index:
                    return kv_to_dict(ls["key-value"])
            raise Exception("not opted in")
        return kv_to_dict(self.app_info(index).get("global-state", []))

    def logic_address(self, bytecode: bytes):
        return enc.encode_address(enc.checksum(b"Program" + bytecode))

    def app_address(self, app_id: int):
        return enc.encode_address(enc.checksum(b"appID" + (app_id).to_bytes(8, "big")))
