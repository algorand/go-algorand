#!/usr/bin/env python

import base64
import glob
import os
import subprocess

import algosdk
import algosdk.future.transaction as txn
import algosdk.encoding as enc


def text(path):
    return open(path, "rt").read().strip()


def kv_to_dict(kv_list):
    return {base64.b64decode(kv['key']):
            (kv['value']['uint'] if kv['value']['type'] == 2
             else base64.b64decode(kv['value']['bytes']))
            for kv in kv_list}


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

    def __init__(self, name=None):
        algodata = os.environ["ALGORAND_DATA"]
        self.algod = self.open_algod(algodata)
        self.kmd = self.open_kmd(algodata)
        self.open_wallet(name)
        # internal wallets has address->sk mappings, so we can sign
        # txns easily, without kmd.
        self.internal_wallet = {}

    def open_kmd(self, algodata):
        dir = sorted(glob.glob(os.path.join(algodata, "kmd-*")))[-1]
        token = text(os.path.join(dir, "kmd.token"))
        net = text(os.path.join(dir, "kmd.net"))
        return algosdk.kmd.KMDClient(token, "http://" + net)

    def open_algod(self, algodata):
        token = text(os.path.join(algodata, "algod.token"))
        net = text(os.path.join(algodata, "algod.net"))
        return algosdk.v2client.algod.AlgodClient(token, "http://" + net)

    def open_wallet(self, name):
        if name:
            self.wallet_name = name
            wallet = None
            for w in self.kmd.list_wallets():
                if w['name'] == name:
                    wallet = w

            assert wallet, f"No wallet named '{name}'"
            self.handle = self.kmd.init_wallet_handle(wallet['id'], '')
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
        try:
            return self.kmd.sign_transaction(self.handle, '', tx)
        except algosdk.error.KMDHTTPError:
            self.open_wallet(self.wallet_name)
            return self.kmd.sign_transaction(self.handle, '', tx)

    def sign_with_program(self, tx, program, delegator=None):
        if delegator:
            raise Exception("haven't implemented delgated logicsig yet")
        return txn.LogicSigTransaction(tx, txn.LogicSig(program))

    def send(self, tx, confirm=True):
        try:
            txid = self.algod.send_transaction(self.sign(tx))
            if not confirm:
                return txid, ""
            return self.confirm(txid), ""
        except algosdk.error.AlgodHTTPError as e:
            return (None, str(e))

    def send_group(self, txns, confirm=True):
        # Need unsigned transactions to calculate the group
        utxns = [tx.transaction
                 if isinstance(tx, txn.SignedTransaction) else tx
                 for tx in txns]
        gid = txn.calculate_group_id(utxns)
        for tx in txns:
            if isinstance(tx, txn.SignedTransaction):
                tx.transaction.group = gid
            else:
                tx.group = gid
        try:
            stxns = [self.sign(tx) for tx in txns]
            txid = self.algod.send_transactions(stxns)
            if not confirm:
                return txid, ""
            return self.confirm(txid), ""
        except algosdk.error.AlgodHTTPError as e:
            return (None, str(e))

    def confirm(self, txid):
        """Wait for txid to be confirmed by the network."""
        last_round = self.algod.status().get("last-round")
        txinfo = self.algod.pending_transaction_info(txid)
        while txinfo.get("confirmed-round", 0) < 1:
            last_round += 1
            self.algod.status_after_block(last_round)
            txinfo = self.algod.pending_transaction_info(txid)
        return txinfo

    def new_account(self):
        sk, pk = algosdk.account.generate_account()
        self.internal_wallet[pk] = sk
        return pk

    def pay(self, sender, receiver, amt: int, **kwargs):
        params = self.algod.suggested_params()
        return txn.PaymentTxn(sender, params, receiver, amt, **kwargs)

    def acfg(self, sender, **kwargs):
        params = self.algod.suggested_params()
        return txn.AssetConfigTxn(sender, params, **kwargs,
                                  strict_empty_address_check=False)

    def asset_create(self, sender, **kwargs):
        assert not kwargs.pop("index", None)
        return self.acfg(sender, **kwargs)

    def axfer(self, sender, receiver, amt: int, index: int, **kwargs):
        params = self.algod.suggested_params()
        return txn.AssetTransferTxn(sender, params, receiver, amt, index,
                                    **kwargs)

    def afrz(self, sender, index: int, target, frozen, **kwargs):
        params = self.algod.suggested_params()
        return txn.AssetFreezeTxn(sender, params, index, target, frozen,
                                  **kwargs)

    def coerce_schema(self, values):
        if not values:
            return None
        if isinstance(values, txn.StateSchema):
            return values
        return txn.StateSchema(num_uints=values[0], num_byte_slices=values[1])

    def appl(self, sender, index: int, on_complete=txn.OnComplete.NoOpOC, **kwargs):
        params = self.algod.suggested_params()
        local_schema = self.coerce_schema(kwargs.pop("local_schema", None))
        global_schema = self.coerce_schema(kwargs.pop("global_schema", None))
        return txn.ApplicationCallTxn(sender, params, index, on_complete,
                                      local_schema=local_schema,
                                      global_schema=global_schema,
                                      **kwargs)

    def app_create(self, sender, approval_program, clear_program=None,
                   on_complete=txn.OnComplete.NoOpOC, **kwargs):
        assert not kwargs.pop("index", None)
        if not clear_program:
            clear_program = self.assemble("#pragma version 2\nint 1")
        return self.appl(sender, 0, on_complete=on_complete,
                         approval_program=approval_program,
                         clear_program=clear_program,
                         **kwargs)

    def app_optin(self, sender, index: int, **kwargs):
        assert not kwargs.pop("on_complete", None)
        return self.appl(sender, index, on_complete=txn.OnComplete.OptInOC,
                         **kwargs)

    def app_call(self, sender, index: int, **kwargs):
        return self.appl(sender, index, **kwargs)

    def balance(self, account, asa=None):
        if asa:
            return self.holding(account, asa)[0]
        info = self.algod.account_info(account)
        return info['amount']

    def holding(self, account, asa):
        info = self.algod.account_info(account)
        for asset in info['assets']:
            if asset['asset-id'] == asa:
                return (asset['amount'], asset['is-frozen'])
        raise Exception("not opted in")

    def assemble(self, source):
        try:
            with open(source, "rb") as f:
                source = f.read()
        except FileNotFoundError:
            source = source.encode('utf-8')

        # CI runs with Python 3.6, which does not have capture_output.
        # proc = subprocess.run(["goal", "clerk", "compile", "-"],
        #                       input=source, capture_output=True)
        proc = subprocess.run(["goal", "clerk", "compile", "-"],
                              input=source,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        assert proc.returncode == 0, proc.stderr.decode()
        return proc.stdout

    def app_info(self, index: int) -> dict:
        return self.algod.application_info(index)['params']

    def app_read(self, index: int, user=None) -> dict:
        if user:
            info = self.algod.account_info(user)
            for ls in info['apps-local-state']:
                if ls['id'] == index:
                    return kv_to_dict(ls['key-value'])
            raise Exception("not opted in")
        return kv_to_dict(self.app_info(index).get('global-state', []))

    def logic_address(self, bytecode: bytes):
        return enc.encode_address(enc.checksum(b'Program' +
                                               bytecode))

    def app_address(self, app_id: int):
        return enc.encode_address(enc.checksum(b'appID' +
                                               (app_id).to_bytes(8, 'big')))
