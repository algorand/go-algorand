#!/usr/bin/env python

import re
import subprocess

# Various types must match between go-algorand and go-algorand-sdk so
# that serialized datastructures will match. This script extracts
# those types from the go-algorand source, and patches a
# go-algorand-sdk repo that it expects to find as a sibling of the
# current repo.

def extract_between(filename, start_pattern, stop_pattern=None):
    """
    Extracts and returns the portion of a file between the first occurrence of
    start_pattern and the first subsequent occurrence of stop_pattern.

    Args:
        filename (str): Path to the input file.
        start_pattern (str): The start delimiter.
        stop_pattern (str): The stop delimiter.

    Returns:
        str: Extracted content between the two patterns. Empty string if not found.
    """
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    start_idx = content.find(start_pattern)
    if start_idx == -1:
        return ""

    start_idx += len(start_pattern)
    stop_idx = len(content)
    if stop_pattern:
        stop_idx = content.find(stop_pattern, start_idx)
    if stop_idx == -1:
        raise ValueError("Stop pattern not found in "+filename)

    return content[start_idx:stop_idx]

def replace_between(filename, content, start_pattern, stop_pattern=None):
    """
    Replaces the content in `filename` between `start_pattern` and `stop_pattern` with `content`.

    Args:
        filename (str): Path to the file to modify.
        content (str): New content to insert.
        start_pattern (str): Delimiter indicating where replacement should start.
        stop_pattern (str): Delimiter indicating where replacement should stop.
    """
    with open(filename, 'r', encoding='utf-8') as f:
        original = f.read()

    start_idx = original.find(start_pattern)
    if start_idx == -1:
        raise ValueError(f"Start pattern '{start_pattern}' not found in {filename}")

    start_idx += len(start_pattern)
    stop_idx = len(original)
    if stop_pattern:
        stop_idx = original.find(stop_pattern, start_idx)
    if stop_idx == -1:
        raise ValueError("Stop pattern not found in "+filename)

    updated = original[:start_idx] + content + original[stop_idx:]

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(updated)

def find_line(filename, s):
    """
    Returns the line from `filename` that contains `s`
    Args:
        filename (str): Path to the file to modify.
        s (str): Name of the substring to look for
    """
    with open(filename, 'r', encoding='utf-8') as f:
        original = f.read()

    start_idx = original.find(s)
    if start_idx == -1:
        return ""
    stop_idx = original.find("\n", start_idx)

    return original[start_idx:stop_idx]

SDK="../go-algorand-sdk/"

def sdkize(input):
    # allocbounds are not used by the SDK. It's confusing to leave them in.
    input = re.sub(",(allocbound|maxtotalbytes)=.*\"", '"', input)
    input = re.sub("^\\s*//msgp:(allocbound|sort|ignore).*\n", '', input, flags=re.MULTILINE)

    # protocol.ConsensusVersion and protocolConsensusVxx constants are
    # the only things that stays in the protocol package. So we "hide"
    # them from the replacements below, then switch it back
    input = input.replace("protocol.ConsensusV", "protocolConsensusV")
    input = input.replace("protocol.ConsensusFuture", "protocolConsensusFuture")

    # All types are in the same package in the SDK
    input = re.sub(r'(basics|crypto|committee|transactions|protocol)\.\b', r'', input)

    # and go back...
    input = input.replace("protocolConsensusV", "protocol.ConsensusV")
    input = input.replace("protocolConsensusFuture", "protocol.ConsensusFuture")

    # keyreg
    input = input.replace("OneTimeSignatureVerifier", "VotePK")
    input = input.replace("VRFVerifier", "VRFPK")
    input = input.replace("merklesignature.Commitment", "MerkleVerifier")
    # appl - Someone had the bright idea to change the names of these fields (and the type) in the SDK.
    input = input.replace("Boxes []BoxRef", "BoxReferences []BoxReference")
    input = re.sub("Box\\s+BoxRef", "Box BoxReference", input)

    # transaction - for some reason, ApplicationCallTxnFields is wrapped in this nothing-burger
    input = input.replace("ApplicationCallTxnFields", "ApplicationFields")

    # These are "string" in the SDK, even though we actually have
    # `protocol.ConsensusVersion` available.  Who knows?
    for field in ["UpgradePropose", "CurrentProtocol", "NextProtocol"]:
        input = re.sub(field+"\\s+protocol.ConsensusVersion", field+" string", input)

    return input

def export(src, dst, start, stop=None):
    x = extract_between(src, start, stop)
    x = sdkize(x)
    replace_between(SDK+dst, x, start, stop)
    subprocess.run(["gofmt", "-w", SDK+dst])

def export_type(name, src, dst):
    export_thing("type {thing} ", name, src, dst)

def export_var(name, src, dst):
    export_thing("var {thing} ", name, src, dst)

def export_func(name, src, dst):
    export_thing("func {thing}(", name, src, dst)

def export_thing(pattern, name, src, dst):
    start = pattern.format(thing=name)
    line = find_line(src, start)
    if line == "":
        raise ValueError(f"Unable to find {name} in {src}")
    src_stop = "\n}\n" if line.endswith("{") else "\n"
    x = extract_between(src, start, src_stop)
    x = sdkize(x)
    if dst.endswith(".go"):     # explicit dst
        dst = f"{SDK}{dst}"
    else:
        dst = f"{SDK}types/{dst}.go"

    line = find_line(dst, start)
    if line == "":
        raise ValueError(f"Unable to find {name} in {dst}  If it's new, add a dummy version to place it.")
    dst_stop = "\n}\n" if line.endswith("{") else "\n"
    # Allow a struct to replace a one-line type def by adding } to extracted text
    if "}" in src_stop and "}" not in dst_stop:
        x += "\n}"
    replace_between(dst, x, start, dst_stop)

    subprocess.run(["gofmt", "-w", dst])

if __name__ == "__main__":
    # Replace the entire file, after "import" (basically just relicense it)
    export("protocol/consensus.go", "protocol/consensus.go", "import")

    src = "config/consensus.go"
    dst = "protocol/config/consensus.go"
    export_type("ConsensusParams", src, dst)
    export_type("ProposerPayoutRules", src, dst)
    export_type("BonusPlan", src, dst)
    export_type("PaysetCommitType", src, dst)
    export_type("ConsensusProtocols", src, dst)
    export_var("Consensus", src, dst)
    export_func("initConsensusProtocols", src, dst)
    export_type("Global", src, dst)
    export_var("Protocol", src, dst)
    # do _not_ export init(), since go-algorand sets bounds, SDK does not

    # Common transaction types
    export_type("Header", "data/transactions/transaction.go", "transaction")
    export_type("Transaction", "data/transactions/transaction.go", "transaction")
    export_type("SignedTxn", "data/transactions/signedtxn.go", "transaction")

    # The transaction types themselves
    #  payment
    export_type("PaymentTxnFields", "data/transactions/payment.go", "transaction")
    #  keyreg
    export_type("KeyregTxnFields", "data/transactions/keyreg.go", "transaction")
    #  assets
    export_type("AssetConfigTxnFields", "data/transactions/asset.go", "transaction")
    export_type("AssetTransferTxnFields", "data/transactions/asset.go", "transaction")
    export_type("AssetFreezeTxnFields", "data/transactions/asset.go", "transaction")
    export_type("AssetIndex", "data/basics/userBalance.go", "asset")
    export_type("AssetParams", "data/basics/userBalance.go", "asset")
    #   apps
    export_type("ApplicationCallTxnFields", "data/transactions/application.go", "applications")
    export_type("ResourceRef", "data/transactions/application.go", "applications")
    # Don't export this, since it was greatly modified in the SDK. We'll just stick to the manual definition.
    # export_type("BoxRef", "data/transactions/application.go", "applications")
    export_type("HoldingRef", "data/transactions/application.go", "applications")
    export_type("LocalsRef", "data/transactions/application.go", "applications")
    export_type("AppIndex", "data/basics/userBalance.go", "applications")

    # Block
    export_type("BlockHeader", "data/bookkeeping/block.go", "block")
    export_type("TxnCommitments", "data/bookkeeping/block.go", "block")
    export_type("ParticipationUpdates", "data/bookkeeping/block.go", "block")
    export_type("RewardsState", "data/bookkeeping/block.go", "block")
    export_type("UpgradeVote", "data/bookkeeping/block.go", "block")
    export_type("UpgradeState", "data/bookkeeping/block.go", "block")
    export_type("StateProofTrackingData", "data/bookkeeping/block.go", "block")
    export_type("Block", "data/bookkeeping/block.go", "block")
    export_type("Payset", "data/transactions/payset.go", "block")
    export_type("SignedTxnInBlock", "data/transactions/signedtxn.go", "block")
    export_type("SignedTxnWithAD", "data/transactions/signedtxn.go", "block")
    export_type("ApplyData", "data/transactions/transaction.go", "block")
    export_type("EvalDelta", "data/transactions/teal.go", "block")
    export_type("StateDelta", "data/basics/teal.go", "block")
    export_type("ValueDelta", "data/basics/teal.go", "block")
    export_type("DeltaAction", "data/basics/teal.go", "block")

    # StateDelta.  Eventually need to deal with all types from ledgercore.StateDelta down
    export_type("AppParams", "data/basics/userBalance.go", "statedelta")
    export_type("TealKeyValue", "data/basics/teal.go", "statedelta")
    export_type("TealValue", "data/basics/teal.go", "statedelta")
