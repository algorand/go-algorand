import json
from subprocess import call
from typing import Callable, Dict, List, Union, Tuple
from pathlib import Path
import types

from goal import Goal, text

import algosdk.atomic_transaction_composer as atc
import algosdk.abi as abi
import algosdk.future.transaction as txn


class AtomicABI:
    CALL_TWICE_ERROR = "Cannot execute this Atomic ABI twice. Instantiate a new object to execute again."

    def __init__(
        self,
        goal: Goal,
        app_id: int,
        contract_abi_json: Union[Path, str],
        caller_acct: str,
        sp: txn.SuggestedParams = None,
    ):
        """
        Note: app_id will over-write whatever app_id was defined in `contract_abi_json`

        Also, we're assuming a single caller_account which is also the signer for all the transactions.
        """
        self.goal = goal
        self.app_id = app_id
        self.contract_abi_json = contract_abi_json  # for cloning only
        self.caller_acct = caller_acct
        self.sp = sp

        assert (
            self.app_id and self.app_id > 0
        ), f"must have already created the app but have app_id {self.app_id}"

        assert (
            self.caller_acct in self.goal.internal_wallet
        ), "aborting AtomicABI - will not be able to transact without signing authority"

        # try very hard to parse the ABI contract
        self.contract_abi_json_path: str = None
        cajson = text(contract_abi_json)
        if cajson:
            self.contract_abi_json_path = contract_abi_json
        else:
            cajson = contract_abi_json
        cadict = json.loads(cajson)
        cadict["appId"] = self.app_id
        self.contract: abi.Contract = abi.Contract.from_json(json.dumps(cadict))

        self.sp = sp
        assert (
            self.caller_acct
        ), "aborting AtomicABI - cannot execute without a caller_acct"
        self.signer = self.get_atxn_signer()

        self.method_args: List[list] = []
        self.sigs2selector: Dict[str, str] = {}
        self.handle2meth: Dict[str, dict] = {}

        self.execution_results: atc.AtomicTransactionResponse = None
        self.execution_summaries: List[MethodCallSummary] = None

        self.atomic_transaction_composer = atc.AtomicTransactionComposer()

        for abi_meth in self.contract.methods:
            handle, meth_name, meth = self._attach_dynamic_method_call(
                abi_meth.name, self._amc_factory(abi_meth)
            )
            signature = abi_meth.get_signature()
            selector = "0x" + abi_meth.get_selector().hex()
            self.sigs2selector[signature] = selector
            self.handle2meth[handle] = {
                "signature": signature,
                "selector": selector,
                "abi_meth": abi_meth,
                "adder_meth_name": meth_name,
                "adder_meth": meth,
            }

    @classmethod
    def factory(cls, obj, caller_acct: str = None):
        return cls(
            obj.goal,
            obj.app_id,
            obj.contract_abi_json,
            caller_acct if caller_acct else obj.caller_acct,
            sp=obj.sp,
        )

    def clone(self, caller_acct: str = None):
        return self.factory(self, caller_acct=caller_acct)

    def execute_atomic_group(
        self, wait_rounds: int = 5
    ) -> Tuple[atc.AtomicTransactionResponse, List["MethodCallSummary"]]:
        assert self.execution_results is None, self.CALL_TWICE_ERROR

        self.execution_results = self.atomic_transaction_composer.execute(
            self.goal.algod, wait_rounds
        )
        self.execution_summaries = self._build_summaries()
        return self.execution_results, self.execution_summaries

    def execute_singleton(
        self,
        method_handle: str,
        method_args: list,
        wait_rounds: int = 5,
        sp: txn.SuggestedParams = None,
        on_complete: txn.OnComplete = txn.OnComplete.NoOpOC,
        note: bytes = None,
        lease: bytes = None,
        rekey_to: str = None,
    ) -> Tuple[atc.AtomicTransactionResponse, "MethodCallSummary"]:
        assert self.execution_results is None, self.CALL_TWICE_ERROR
        abi_meth = self.handle2meth[method_handle]["abi_meth"]
        self.add_method_call(
            abi_meth,
            method_args,
            sp=sp,
            on_complete=on_complete,
            note=note,
            lease=lease,
            rekey_to=rekey_to,
        )
        _, s = self.execute_atomic_group(wait_rounds=wait_rounds)
        return s[0].result.return_value

    def dump_selectors(self) -> str:
        return json.dumps(self.sigs2selector, indent=4, sort_keys=True)

    def _build_summaries(self) -> List["MethodCallSummary"]:
        assert (
            self.execution_results
        ), "Cannot summarize before calling 'execute_atomic_group()'"
        summaries = []
        i = 0
        for meth in self.atomic_transaction_composer.method_dict.values():
            summaries.append(
                MethodCallSummary(
                    meth,
                    self.method_args[i],
                    self.execution_results.abi_results[i],
                )
            )
            i += 1
        return summaries

    @staticmethod
    def _amc_factory(abi_meth: abi.method.Method):
        def func(
            self,
            *args,
            sp: txn.SuggestedParams = None,
            on_complete: txn.OnComplete = txn.OnComplete.NoOpOC,
            note: bytes = None,
            lease: bytes = None,
            rekey_to: str = None,
        ):
            return self.add_method_call(
                abi_meth,
                method_args=args,
                sp=sp,
                on_complete=on_complete,
                note=note,
                lease=lease,
                rekey_to=rekey_to,
            )

        return func

    def get_suggested_params(self) -> txn.SuggestedParams:
        if not self.sp:
            self.sp = self.goal.algod.suggested_params()

        return self.sp

    def get_atxn_signer(self, caller_acct: str = None) -> atc.AccountTransactionSigner:
        if not caller_acct:
            caller_acct = self.caller_acct
        sk = self.goal.internal_wallet.get(caller_acct)
        if not sk:
            raise Exception("Cannot create AccountTransactionSigner")
        # TODO: handle querying kmd in the case that sk isn't in the internal wallet

        return atc.AccountTransactionSigner(sk)

    def get_txn_with_signer(
        self, txn: txn.Transaction, signer: atc.TransactionSigner = None
    ) -> atc.TransactionWithSigner:
        if not signer:
            signer = self.signer

        return atc.TransactionWithSigner(txn, signer)

    def add_method_call(
        self,
        method: abi.method.Method,
        method_args: list = [],
        sp: txn.SuggestedParams = None,
        on_complete: txn.OnComplete = txn.OnComplete.NoOpOC,
        note: bytes = None,
        lease: bytes = None,
        rekey_to: str = None,
    ) -> "AtomicABI":
        if not sp:
            sp = self.get_suggested_params()

        self.atomic_transaction_composer.add_method_call(
            self.app_id,
            method,
            self.caller_acct,
            sp,
            self.signer,
            method_args=method_args,
            on_complete=on_complete,
            note=note,
            lease=lease,
            rekey_to=rekey_to,
        )

        self.method_args.append(method_args)

        return self

    def _attach_dynamic_method_call(self, name: str, func: Callable) -> None:
        """
        For an abi method such as "factorial(uint64)uint64"
        this allows usages such as:
        >>> abi.next_abi_call_factorial(5)
        which will delegate to AtomicTransactionComposer with
        atc.add_method_call(app_id, abi_factorial_method, ...)
        """
        meth = types.MethodType(func, self)
        meth_name = self.abi_composer_name(name)
        setattr(self, meth_name, meth)
        return name, meth_name, meth

    @classmethod
    def abi_composer_name(cls, method_name: str) -> str:
        return f"next_abi_call_{method_name}"


class MethodCallSummary:
    def __init__(self, method: abi.Method, args: list, result: atc.ABIResult):
        self.method = method
        self.args = args
        self.result = result

    def __str__(self) -> str:
        return f"""SELECTOR<<<0x{self.method.get_selector().hex()}>>>
{self.method.get_signature()}: {self.args} 
    ->
{self.result.return_value}"""
