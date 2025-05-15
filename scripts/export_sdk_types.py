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
        raise ValueError("Start pattern not found")

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
    input = re.sub(",allocbound=.*\"", '"', input)

    # All types are in the same package in the SDK
    input = input.replace("basics.", "")
    input = input.replace("crypto.", "")
    input = input.replace("protocol.", "")

    # keyreg
    input = input.replace("OneTimeSignatureVerifier", "VotePK")
    input = input.replace("VRFVerifier", "VRFPK")
    input = input.replace("merklesignature.Commitment", "MerkleVerifier")
    # appl - Someone had the bright idea to change the name of this field (and type) in the SDK.
    input = input.replace("Boxes []BoxRef", "BoxReferences []BoxReference")

    # transaction - for some reason, ApplicationCallTxnFields is wrapped in this nothing-burger
    input = input.replace("ApplicationCallTxnFields", "ApplicationFields")

    return input

def export(src, dst, start, stop):
    x = extract_between(src, start, stop)
    x = sdkize(x)
    replace_between(SDK+dst, x, start, stop)
    subprocess.run(["gofmt", "-w", SDK+dst])


if __name__ == "__main__":
    # Replace the entire file, starting with "type ConsensusParams"
    consensus = extract_between("config/consensus.go", "type ConsensusParams")
    replace_between(SDK+"protocol/config/consensus.go", consensus, "type ConsensusParams")

    # Common tranbsaction types
    export("data/transactions/transaction.go", "types/transaction.go",
           "type Header ", "\n}")
    export("data/transactions/transaction.go", "types/transaction.go",
           "type Transaction ", "\n}")
    export("data/transactions/signedtxn.go", "types/transaction.go",
           "type SignedTxn ", "\n}")

    # The transaction types
    export("data/transactions/payment.go", "types/transaction.go",
           "type PaymentTxnFields ", "\n}")
    export("data/transactions/keyreg.go", "types/transaction.go",
           "type KeyregTxnFields ", "\n}")

    export("data/transactions/asset.go", "types/transaction.go",
           "type AssetConfigTxnFields ", "\n}")
    export("data/transactions/asset.go", "types/transaction.go",
           "type AssetTransferTxnFields ", "\n}")
    export("data/transactions/asset.go", "types/transaction.go",
           "type AssetFreezeTxnFields ", "\n}")

    export("data/transactions/application.go", "types/applications.go",
           "type ApplicationCallTxnFields ", "\n}")

    # StateDelta.  Eventually need to deal with all types from ledgercore.StateDelta down
    export("data/basics/userBalance.go", "types/statedelta.go",
           "type AppParams ", "\n}")
