#!/usr/bin/env python

import re
import subprocess

# Various types must match between go-algorand and go-algorand-sdk so
# that serialized datastructures will match. This script extracts
# those types from the go-algorand source, and patches a
# go-algorand-sdk repo that it expects to find as a sibling of the
# current repo.

def _find_line(content, s):
    """Returns the line from content that contains s, or "" if not found."""
    start_idx = content.find(s)
    if start_idx == -1:
        return ""
    stop_idx = content.find("\n", start_idx)
    if stop_idx == -1:
        stop_idx = len(content)
    return content[start_idx:stop_idx]

def _extract_comment(content, start_pattern):
    """Walk backward from start_pattern collecting consecutive // comment lines.
    Returns them as a string with trailing newline, or "" if none found.
    Blank lines or non-comment lines terminate the walk."""
    idx = content.find(start_pattern)
    if idx == -1:
        return ""
    before = content[:idx]
    if before.endswith("\n"):
        before = before[:-1]
    lines = before.split("\n")

    comment_lines = []
    for line in reversed(lines):
        stripped = line.strip()
        if stripped.startswith("//"):
            comment_lines.append(line)
        else:
            break

    if not comment_lines:
        return ""
    comment_lines.reverse()
    return "\n".join(comment_lines) + "\n"

def _extract_body(content, start_pattern, stop_pattern=None):
    """Extract text between start_pattern and stop_pattern in content."""
    start_idx = content.find(start_pattern)
    if start_idx == -1:
        return ""
    start_idx += len(start_pattern)
    stop_idx = len(content)
    if stop_pattern:
        stop_idx = content.find(stop_pattern, start_idx)
    if stop_idx == -1:
        raise ValueError("Stop pattern not found")
    return content[start_idx:stop_idx]

def extract_between(filename, start_pattern, stop_pattern=None):
    """Reads file once and returns (body, doc_comment) tuple."""
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    body = _extract_body(content, start_pattern, stop_pattern)
    comment = _extract_comment(content, start_pattern)
    return body, comment

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
    x, _ = extract_between(src, start, stop)
    x = sdkize(x)
    replace_between(SDK+dst, x, start, stop)
    subprocess.run(["gofmt", "-w", SDK+dst])

def export_type(name, src, dst, comment=True):
    export_thing("type {thing} ", name, src, dst, comment=comment)

def export_var(name, src, dst, comment=True):
    export_thing("var {thing} ", name, src, dst, comment=comment)

def export_func(name, src, dst, comment=True):
    export_thing("func {thing}(", name, src, dst, comment=comment)

def export_thing(pattern, name, src, dst, comment=True):
    start = pattern.format(thing=name)

    with open(src, 'r', encoding='utf-8') as f:
        src_content = f.read()

    line = _find_line(src_content, start)
    if line == "":
        raise ValueError(f"Unable to find {name} in {src}")
    src_stop = "\n}\n" if line.endswith("{") else "\n"
    x = sdkize(_extract_body(src_content, start, src_stop))
    if comment:
        # Only strip //msgp: directives from comments, not fully sdkize
        # because of renaming like ApplicationCallTxnFields -> ApplicationFields
        new_comment = re.sub("^\\s*//msgp:(allocbound|sort|ignore).*\n", '',
                             _extract_comment(src_content, start), flags=re.MULTILINE)
    else:
        new_comment = None  # sentinel: keep existing destination comment

    if dst.endswith(".go"):     # explicit dst
        dst = f"{SDK}{dst}"
    else:
        dst = f"{SDK}types/{dst}.go"

    with open(dst, 'r', encoding='utf-8') as f:
        original = f.read()

    line = _find_line(original, start)
    if line == "":
        # New type: append to end of destination file
        if new_comment is None:
            new_comment = ""
        closing = "\n}\n" if src_stop == "\n}\n" else "\n"
        updated = original.rstrip("\n") + "\n\n" + new_comment + start + x + closing
    else:
        dst_stop = "\n}\n" if line.endswith("{") else "\n"
        # Allow a struct to replace a one-line type def by adding } to extracted text
        if "}" in src_stop and "}" not in dst_stop:
            x += "\n}"

        old_comment = _extract_comment(original, start)

        # When comment=False, preserve the existing destination comment
        if new_comment is None:
            new_comment = old_comment

        old_start_idx = original.find(start)
        old_body_end = original.find(dst_stop, old_start_idx + len(start))
        if old_body_end == -1:
            raise ValueError("Stop pattern not found in " + dst)
        old_body_end += len(dst_stop)

        # Include old comment in the region to replace
        if old_comment:
            comment_start = original.find(old_comment, old_start_idx - len(old_comment) - 1)
            if comment_start != -1 and comment_start < old_start_idx:
                old_start_idx = comment_start

        updated = original[:old_start_idx] + new_comment + start + x + dst_stop + original[old_body_end:]

    # Write destination once
    with open(dst, 'w', encoding='utf-8') as f:
        f.write(updated)

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
    export_func("(cp ConsensusProtocols) DeepCopy", src, dst)
    export_func("(cp ConsensusProtocols) Merge", src, dst)
    export_type("Global", src, dst)
    export_var("Protocol", src, dst)
    # do _not_ export init(), since go-algorand sets bounds, SDK does not

    # Custom Consensus Functions
    src = "config/config.go"
    dst = "protocol/config/config.go"
    export_func("SaveConfigurableConsensus", src, dst)
    export_func("PreloadConfigurableConsensusProtocols", src, dst)
    export_func("LoadConfigurableConsensusProtocols", src, dst)
    # do not export SetConfigurableConsensusProtocols(), since go-algorand sets bounds, SDK does not

    # Common transaction types
    export_type("Header", "data/transactions/transaction.go", "transaction")
    export_type("Transaction", "data/transactions/transaction.go", "transaction")
    export_type("SignedTxn", "data/transactions/signedtxn.go", "transaction", comment=False)

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
    export_type("Micros", "data/basics/units.go", "block")

    # StateDelta.  Eventually need to deal with all types from ledgercore.StateDelta down
    export_type("AppParams", "data/basics/userBalance.go", "statedelta")
    export_type("TealKeyValue", "data/basics/teal.go", "statedelta")
    export_type("TealValue", "data/basics/teal.go", "statedelta")
