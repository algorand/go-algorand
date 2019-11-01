#!/usr/bin/env python3

import argparse
import os

specs_templates = {
    "dynamic-fee": "place a transaction with an unspecified fee",
    "delegate-key-registration": "delegate key-registration authority to some key",

    "periodic-payment-escrow": "open an escrow for periodic payments",
    "limit-order": "open a limit order to exchange algos for an asset",
    "atomic-swap": "open an escrow for a cross-chain hash-locked atomic swap",
    "split": "open an escrow for splitting money between different accounts",
}

specs_args = {
    "TMPL_FEE": "maximum fee used by any single transaction",
    "TMPL_OWN": "owner of the escrow account",
    "TMPL_ASSET": "name of the transferred asset",
    "TMPL_MINTRD": "the minimum amount to be traded away",
    "TMPL_DUR": "the amount of time any transaction is available",
    "TMPL_PERIOD": "the time between any pair of operations",
    "TMPL_RCV": "the receiver of the payments",
    "TMPL_AMT": "the maximum amount of money that may be withdrawn from the account",
    "TMPL_CLS": "the address to close the transaction to",
    "TMPL_X": "string to use for the transaction lease (defaults to \"tmpl\")",
    "TMPL_RATN": "fraction of money to be paid to the first recipient: numerator",
    "TMPL_RATD": "fraction of money to be paid to the first recipient: denominator",
    "TMPL_SWAPN": "limit order exchange rate (for N algos, want rate * N coin): numerator",
    "TMPL_SWAPD": "limit order exchange rate (for N algos, want rate * N coin): denominator",
    "TMPL_RCV1": "first recipient of the split payment",
    "TMPL_RCV2": "second recipient of the split payment",
    "TMPL_MINPAY": "minimum amount to be paid out of the account",
    "TMPL_HASHFN": "hash function used to implement the swap",
    "TMPL_TIMEOUT": "round at which the escrow times out",
    "TMPL_EXPIRE": "round at which the delegate logic expires",
    "TMPL_ESC": "owner to whom to refund the escrow funds",
    "TMPL_HASHIMG": "intended hash image which unlocks the escrow",
    "TMPL_FV": "first valid round of the transaction",
    "TMPL_LV": "last valid round of the transaction",
    "TMPL_AUTH": "key authorized with delegation authority",
}

template_dir = "templates"
template_token_pfx = "TMPL_"

templates = {}

ext = ".teal.tmpl"
for tname in os.listdir(template_dir):
    if tname.endswith(ext):
        templates[tname[:-len(ext)]] = tname

def tokens_of(template_name):
    tokens = {}
    with open(os.path.join(template_dir, templates[template_name])) as f:
        for line in f:
            for token in line.strip().split(' '):
                if token.startswith(template_token_pfx):
                    tokens[token] = True
    return tokens

def cmd_arg(token):
    return token.replace("TMPL_", "").lower()

descr = "Fill a TEAL template with arguments."

parser = argparse.ArgumentParser(description=descr)
subparsers = parser.add_subparsers(dest="tname")
for spec in specs_templates:
    subparser = subparsers.add_parser(spec, help=specs_templates[spec].strip())
    for token in tokens_of(spec):
        subparser.add_argument("--" + cmd_arg(token), help=specs_args[token].strip(), required=True)

args = parser.parse_args()

with open(os.path.join(template_dir, templates[args.tname])) as f:
    asm = f.read()

for token in tokens_of(args.tname):
    asm = asm.replace(token, vars(args)[cmd_arg(token)])

print(asm)
