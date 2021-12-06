import json
from typing import Callable, List, Union, Tuple
from pathlib import Path
import types

from goal import Goal, text

import algosdk.atomic_transaction_composer as atc
import algosdk.abi as abi
import algosdk.future.transaction as txn


class AtomicABI:
    def __init__(
        self,
        goal: Goal,
        app_id: int,
        contract_abi_json: Union[Path, str],
        sender: str,
        signer: atc.TransactionSigner = None,
        sp: txn.SuggestedParams = None,
    ):
        """
        Note: app_id will over-write whatever app_id was defined in `contract_abi_json`

        Also, I'm assuming a single signer for all the methods in the atomic transaction.
        """
        self.goal = goal
        self.app_id = app_id
        self.contract_abi_json_path: str = None

        self.method_args: List[list] = []
        self.execution_results: atc.AtomicTransactionResponse = None
        self.execution_summaries: List[MethodCallSummary] = None

        # try very hard to parse the ABI contract
        cajson = text(contract_abi_json)
        if cajson:
            self.contract_abi_json_path = contract_abi_json
        else:
            cajson = contract_abi_json
        cadict = json.loads(cajson)
        cadict["appId"] = self.app_id
        self.contract: abi.Contract = abi.Contract.from_json(json.dumps(cadict))

        self.sender = sender
        self.sp = sp
        self.signer = signer

        if not self.signer:
            # gonna just try and get the signer from the sender
            self.signer = self.get_atxn_signer(sender)

        self.atomic_transaction_composer = atc.AtomicTransactionComposer()

        for abi_meth in self.contract.methods:
            self._attach_dynamic_method_call(abi_meth.name, self._factory(abi_meth))

    def execute_all_methods(
        self, wait_rounds: int = 5
    ) -> Tuple[atc.AtomicTransactionResponse, List["MethodCallSummary"]]:
        assert (
            self.execution_results is None
        ), "Cannot execute this Atomic ABI twice. Instantiate a new object to execute again."
        self.execution_results = self.atomic_transaction_composer.execute(
            self.goal.algod, wait_rounds
        )

        self.execution_summaries = self._build_summaries()
        return self.execution_results, self.execution_summaries

    def _build_summaries(self) -> List["MethodCallSummary"]:
        assert (
            self.execution_results
        ), "Cannot summarize before calling 'execute_all_methods()'"
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
    def _factory(abi_meth: abi.method.Method):
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

    def get_atxn_signer(self, sender: str = None) -> atc.AccountTransactionSigner:
        if not sender:
            sender = self.sender
        sk = self.goal.internal_wallet.get(sender)
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
            self.sender,
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
        setattr(self, self.abi_composer_name(name), meth)

    @classmethod
    def abi_composer_name(cls, method_name: str) -> str:
        return f"next_abi_call_{method_name}"


class MethodCallSummary:
    def __init__(self, method: abi.Method, args: list, result: atc.ABIResult):
        self.method = method
        self.args = args
        self.result = result

    def __str__(self) -> str:
        return (
            f"{self.method.get_signature()}: {self.args} -> {self.result.return_value}"
        )
