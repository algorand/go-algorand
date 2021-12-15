import json
from os import confstr_names
from unittest.mock import Mock, patch

import algosdk.atomic_transaction_composer as atc

from .atomic_abi import AtomicABI


contract = {
    "name": "demo-abi",
    "appId": None,
    "methods": [
        {
            "name": "add",
            "desc": "Add 2 integers",
            "args": [{"type": "uint64"}, {"type": "uint64"}],
            "returns": {"type": "uint64"},
        },
        {
            "name": "sub",
            "desc": "Subtract 2 integers",
            "args": [{"type": "uint64"}, {"type": "uint64"}],
            "returns": {"type": "uint64"},
        },
        {
            "name": "mul",
            "desc": "Multiply 2 integers",
            "args": [{"type": "uint64"}, {"type": "uint64"}],
            "returns": {"type": "uint64"},
        },
        {
            "name": "div",
            "desc": "Divide 2 integers, throw away the remainder",
            "args": [{"type": "uint64"}, {"type": "uint64"}],
            "returns": {"type": "uint64"},
        },
        {
            "name": "qrem",
            "desc": "Divide 2 integers, return both the quotient and remainder",
            "args": [{"type": "uint64"}, {"type": "uint64"}],
            "returns": {"type": "(uint64,uint64)"},
        },
        {
            "name": "reverse",
            "desc": "Reverses a string",
            "args": [{"type": "string"}],
            "returns": {"type": "string"},
        },
        {
            "name": "txntest",
            "desc": "just check it",
            "args": [{"type": "uint64"}, {"type": "pay"}, {"type": "uint64"}],
            "returns": {"type": "uint64"},
        },
        {
            "name": "concat_strings",
            "desc": "concat some strings",
            "args": [{"type": "string[]"}],
            "returns": {"type": "string"},
        },
        {
            "name": "manyargs",
            "desc": "Try to send 20 arguments",
            "args": [
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
                {"type": "uint64"},
            ],
            "returns": {"type": "uint64"},
        },
        {
            "name": "_optIn",
            "desc": "just opt in",
            "args": [{"type": "uint64"}],
            "returns": {"type": "uint64"},
        },
        {
            "name": "_closeOut",
            "desc": "just close out",
            "args": [{"type": "uint64"}],
            "returns": {"type": "uint64"},
        },
    ],
}


def test_fixture():
    num_methods = len(contract["methods"])
    assert num_methods == 11
    assert json.loads(json.dumps(contract))["appId"] is None


def test_init(init_only=False):
    goal = Mock()
    caller_account = "mega whale"
    sk = Mock()
    goal.internal_wallet = {caller_account: sk}

    app_id = 42
    contract_abi_json = json.dumps(contract)
    sp = Mock()
    abi = AtomicABI(goal, app_id, contract_abi_json, caller_account, sp=sp)
    if init_only:
        return abi

    assert abi.app_id == app_id
    assert abi.caller_acct == caller_account
    assert abi.sp == sp

    assert abi.contract_abi_json == contract_abi_json
    assert abi.contract.name == "demo-abi"
    assert abi.contract.app_id == app_id

    assert abi.signer.private_key == sk
    num_methods = len(contract["methods"])
    assert num_methods == len(abi.contract.methods)


def test_dynamic_methods():
    abi = test_init(init_only=True)
    for meth in contract["methods"]:
        name = meth["name"]
        adder_meth_name = abi.abi_composer_name(name)
        assert getattr(abi, adder_meth_name, None)

        run_now_method_name = abi.run_now_method_name(name)
        assert getattr(abi, run_now_method_name, None)
