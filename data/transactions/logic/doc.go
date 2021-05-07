// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package logic

import (
	"fmt"

	"github.com/algorand/go-algorand/protocol"
)

// short description of every op
var opDocByName = map[string]string{
	"err":               "Error. Panic immediately. This is primarily a fencepost against accidental zero bytes getting compiled into programs.",
	"sha256":            "SHA256 hash of value X, yields [32]byte",
	"keccak256":         "Keccak256 hash of value X, yields [32]byte",
	"sha512_256":        "SHA512_256 hash of value X, yields [32]byte",
	"ed25519verify":     "for (data A, signature B, pubkey C) verify the signature of (\"ProgData\" || program_hash || data) against the pubkey => {0 or 1}",
	"+":                 "A plus B. Panic on overflow.",
	"-":                 "A minus B. Panic if B > A.",
	"/":                 "A divided by B. Panic if B == 0.",
	"*":                 "A times B. Panic on overflow.",
	"<":                 "A less than B => {0 or 1}",
	">":                 "A greater than B => {0 or 1}",
	"<=":                "A less than or equal to B => {0 or 1}",
	">=":                "A greater than or equal to B => {0 or 1}",
	"&&":                "A is not zero and B is not zero => {0 or 1}",
	"||":                "A is not zero or B is not zero => {0 or 1}",
	"==":                "A is equal to B => {0 or 1}",
	"!=":                "A is not equal to B => {0 or 1}",
	"!":                 "X == 0 yields 1; else 0",
	"len":               "yields length of byte value X",
	"itob":              "converts uint64 X to big endian bytes",
	"btoi":              "converts bytes X as big endian to uint64",
	"%":                 "A modulo B. Panic if B == 0.",
	"|":                 "A bitwise-or B",
	"&":                 "A bitwise-and B",
	"^":                 "A bitwise-xor B",
	"~":                 "bitwise invert value X",
	"shl":               "A times 2^B, modulo 2^64",
	"shr":               "A divided by 2^B",
	"sqrt":              "The largest integer X such that X^2 <= A",
	"log2":              "The largest integer X such that 2^X <= A",
	"exp":               "A raised to the Bth power. Panic if A == B == 0 and on overflow",
	"expw":              "A raised to the Bth power as a 128-bit long result as low (top) and high uint64 values on the stack. Panic if A == B == 0 or if the results exceeds 2^128-1",
	"mulw":              "A times B out to 128-bit long result as low (top) and high uint64 values on the stack",
	"addw":              "A plus B out to 128-bit long result as sum (top) and carry-bit uint64 values on the stack",
	"divmodw":           "Pop four uint64 values.  The deepest two are interpreted as a uint128 dividend (deepest value is high word), the top two are interpreted as a uint128 divisor.  Four uint64 values are pushed to the stack. The deepest two are the quotient (deeper value is the high uint64). The top two are the remainder, low bits on top.",
	"intcblock":         "prepare block of uint64 constants for use by intc",
	"intc":              "push Ith constant from intcblock to stack",
	"intc_0":            "push constant 0 from intcblock to stack",
	"intc_1":            "push constant 1 from intcblock to stack",
	"intc_2":            "push constant 2 from intcblock to stack",
	"intc_3":            "push constant 3 from intcblock to stack",
	"pushint":           "push immediate UINT to the stack as an integer",
	"bytecblock":        "prepare block of byte-array constants for use by bytec",
	"bytec":             "push Ith constant from bytecblock to stack",
	"bytec_0":           "push constant 0 from bytecblock to stack",
	"bytec_1":           "push constant 1 from bytecblock to stack",
	"bytec_2":           "push constant 2 from bytecblock to stack",
	"bytec_3":           "push constant 3 from bytecblock to stack",
	"pushbytes":         "push the following program bytes to the stack",
	"arg":               "push Nth LogicSig argument to stack",
	"arg_0":             "push LogicSig argument 0 to stack",
	"arg_1":             "push LogicSig argument 1 to stack",
	"arg_2":             "push LogicSig argument 2 to stack",
	"arg_3":             "push LogicSig argument 3 to stack",
	"txn":               "push field F of current transaction to stack",
	"gtxn":              "push field F of the Tth transaction in the current group",
	"gtxns":             "push field F of the Ath transaction in the current group",
	"txna":              "push Ith value of the array field F of the current transaction",
	"gtxna":             "push Ith value of the array field F from the Tth transaction in the current group",
	"gtxnsa":            "push Ith value of the array field F from the Ath transaction in the current group",
	"global":            "push value from globals to stack",
	"load":              "copy a value from scratch space to the stack",
	"store":             "pop a value from the stack and store to scratch space",
	"bnz":               "branch to TARGET if value X is not zero",
	"bz":                "branch to TARGET if value X is zero",
	"b":                 "branch unconditionally to TARGET",
	"return":            "use last value on stack as success value; end",
	"pop":               "discard value X from stack",
	"dup":               "duplicate last value on stack",
	"dup2":              "duplicate two last values on stack: A, B -> A, B, A, B",
	"dig":               "push the Nth value from the top of the stack. dig 0 is equivalent to dup",
	"swap":              "swaps two last values on stack: A, B -> B, A",
	"select":            "selects one of two values based on top-of-stack: A, B, C -> (if C != 0 then B else A)",
	"concat":            "pop two byte-arrays A and B and join them, push the result",
	"substring":         "pop a byte-array A. For immediate values in 0..255 S and E: extract a range of bytes from A starting at S up to but not including E, push the substring result. If E < S, or either is larger than the array length, the program fails",
	"substring3":        "pop a byte-array A and two integers B and C. Extract a range of bytes from A starting at B up to but not including C, push the substring result. If C < B, or either is larger than the array length, the program fails",
	"getbit":            "pop a target A (integer or byte-array), and index B. Push the Bth bit of A.",
	"setbit":            "pop a target A, index B, and bit C. Set the Bth bit of A to C, and push the result",
	"getbyte":           "pop a byte-array A and integer B. Extract the Bth byte of A and push it as an integer",
	"setbyte":           "pop a byte-array A, integer B, and small integer C (between 0..255). Set the Bth byte of A to C, and push the result",
	"balance":           "get balance for the requested account specified by Txn.Accounts[A] in microalgos. A is specified as an account index in the Accounts field of the ApplicationCall transaction, zero index means the sender. The balance is observed after the effects of previous transactions in the group, and after the fee for the current transaction is deducted.",
	"min_balance":       "get minimum required balance for the requested account specified by Txn.Accounts[A] in microalgos. A is specified as an account index in the Accounts field of the ApplicationCall transaction, zero index means the sender. Required balance is affected by [ASA](https://developer.algorand.org/docs/features/asa/#assets-overview) and [App](https://developer.algorand.org/docs/features/asc1/stateful/#minimum-balance-requirement-for-a-smart-contract) usage. When creating or opting into an app, the minimum balance grows before the app code runs, therefore the increase is visible there. When deleting or closing out, the minimum balance decreases after the app executes.",
	"app_opted_in":      "check if account specified by Txn.Accounts[A] opted in for the application B => {0 or 1}",
	"app_local_get":     "read from account specified by Txn.Accounts[A] from local state of the current application key B => value",
	"app_local_get_ex":  "read from account specified by Txn.Accounts[A] from local state of the application B key C => [*... stack*, value, 0 or 1]",
	"app_global_get":    "read key A from global state of a current application => value",
	"app_global_get_ex": "read from application Txn.ForeignApps[A] global state key B => [*... stack*, value, 0 or 1]. A is specified as an account index in the ForeignApps field of the ApplicationCall transaction, zero index means this app",
	"app_local_put":     "write to account specified by Txn.Accounts[A] to local state of a current application key B with value C",
	"app_global_put":    "write key A and value B to global state of the current application",
	"app_local_del":     "delete from account specified by Txn.Accounts[A] local state key B of the current application",
	"app_global_del":    "delete key A from a global state of the current application",
	"asset_holding_get": "read from account specified by Txn.Accounts[A] and asset B holding field X (imm arg) => {0 or 1 (top), value}",
	"asset_params_get":  "read from asset Txn.ForeignAssets[A] params field X (imm arg) => {0 or 1 (top), value}",
	"assert":            "immediately fail unless value X is a non-zero number",
	"callsub":           "branch unconditionally to TARGET, saving the next instruction on the call stack",
	"retsub":            "pop the top instruction from the call stack and branch to it",

	"b+":  "A plus B, where A and B are byteslices interpreted as big-endian unsigned integers",
	"b-":  "A minus B, where A and B are byteslices interpreted as big-endian unsigned integers. Panic on underflow.",
	"b/":  "A divided by B, where A and B are byteslices interpreted as big-endian unsigned integers. Panic if B is zero.",
	"b*":  "A times B, where A and B are byteslices interpreted as big-endian unsigned integers.",
	"b<":  "A is less than B, where A and B are byteslices interpreted as big-endian unsigned integers => { 0 or 1}",
	"b>":  "A is greater than B, where A and B are byteslices interpreted as big-endian unsigned integers => { 0 or 1}",
	"b<=": "A is less than or equal to B, where A and B are byteslices interpreted as big-endian unsigned integers => { 0 or 1}",
	"b>=": "A is greater than or equal to B, where A and B are byteslices interpreted as big-endian unsigned integers => { 0 or 1}",
	"b==": "A is equals to B, where A and B are byteslices interpreted as big-endian unsigned integers => { 0 or 1}",
	"b!=": "A is not equal to B, where A and B are byteslices interpreted as big-endian unsigned integers => { 0 or 1}",
	"b%":  "A modulo B, where A and B are byteslices interpreted as big-endian unsigned integers. Panic if B is zero.",
	"b|":  "A bitwise-or B, where A and B are byteslices interpreted as big-endian unsigned integers.",
	"b&":  "A bitwise-and B, where A and B are byteslices interpreted as big-endian unsigned integers.",
	"b^":  "A bitwise-xor B, where A and B are byteslices interpreted as big-endian unsigned integers.",
}

// OpDoc returns a description of the op
func OpDoc(opName string) string {
	return opDocByName[opName]
}

var opcodeImmediateNotes = map[string]string{
	"intcblock":         "{varuint length} [{varuint value}, ...]",
	"intc":              "{uint8 int constant index}",
	"pushint":           "{varuint int}",
	"bytecblock":        "{varuint length} [({varuint value length} bytes), ...]",
	"bytec":             "{uint8 byte constant index}",
	"pushbytes":         "{varuint length} {bytes}",
	"arg":               "{uint8 arg index N}",
	"txn":               "{uint8 transaction field index}",
	"gtxn":              "{uint8 transaction group index} {uint8 transaction field index}",
	"gtxns":             "{uint8 transaction field index}",
	"txna":              "{uint8 transaction field index} {uint8 transaction field array index}",
	"gtxna":             "{uint8 transaction group index} {uint8 transaction field index} {uint8 transaction field array index}",
	"gtxnsa":            "{uint8 transaction field index} {uint8 transaction field array index}",
	"global":            "{uint8 global field index}",
	"bnz":               "{int16 branch offset, big endian. (negative offsets are illegal before v4)}",
	"bz":                "{int16 branch offset, big endian. (negative offsets are illegal before v4)}",
	"b":                 "{int16 branch offset, big endian. (negative offsets are illegal before v4)}",
	"load":              "{uint8 position in scratch space to load from}",
	"store":             "{uint8 position in scratch space to store to}",
	"substring":         "{uint8 start position} {uint8 end position}",
	"dig":               "{uint8 depth}",
	"asset_holding_get": "{uint8 asset holding field index}",
	"asset_params_get":  "{uint8 asset params field index}",
}

// OpImmediateNote returns a short string about immediate data which follows the op byte
func OpImmediateNote(opName string) string {
	return opcodeImmediateNotes[opName]
}

// further documentation on the function of the opcode
var opDocExtras = map[string]string{
	"ed25519verify":     "The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack.",
	"bnz":               "The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be well aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Branch offsets are limited to forward branches only, 0-0x7fff until v4. v4 treats offset as a signed 16 bit integer allowing for backward branches and looping.\n\nAt LogicSigVersion 2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before LogicSigVersion 2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)",
	"bz":                "See `bnz` for details on how branches work. `bz` inverts the behavior of `bnz`.",
	"b":                 "See `bnz` for details on how branches work. `b` always jumps to the offset.",
	"callsub":           "The call stack is separate from the data stack. Only `callsub` and `retsub` manipulate it.`",
	"retsub":            "The call stack is separate from the data stack. Only `callsub` and `retsub` manipulate it.`",
	"intcblock":         "`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack. Subsequent calls to `intcblock` reset and replace the integer constants available to the script.",
	"bytecblock":        "`bytecblock` loads the following program bytes into an array of byte-array constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack. Subsequent calls to `bytecblock` reset and replace the bytes constants available to the script.",
	"*":                 "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `mulw`.",
	"+":                 "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `addw`.",
	"/":                 "`divmodw` is available to divide the two-element values produced by `mulw` and `addw`.",
	"txn":               "FirstValidTime causes the program to fail. The field is reserved for future use.",
	"gtxn":              "for notes on transaction fields available, see `txn`. If this transaction is _i_ in the group, `gtxn i field` is equivalent to `txn field`.",
	"gtxns":             "for notes on transaction fields available, see `txn`. If top of stack is _i_, `gtxns field` is equivalent to `gtxn _i_ field`. gtxns exists so that _i_ can be calculated, often based on the index of the current transaction.",
	"btoi":              "`btoi` panics if the input is longer than 8 bytes.",
	"concat":            "`concat` panics if the result would be greater than 4096 bytes.",
	"pushbytes":         "pushbytes args are not added to the bytecblock during assembly processes",
	"pushint":           "pushint args are not added to the intcblock during assembly processes",
	"getbit":            "see explanation of bit ordering in setbit",
	"setbit":            "bit indexing begins with low-order bits in integers. Setting bit 4 to 1 on the integer 0 yields 16 (`int 0x0010`, or 2^4). Indexing begins in the first bytes of a byte-string (as seen in getbyte and substring). Setting bits 0 through 11 to 1 in a 4 byte-array of 0s yields `byte 0xfff00000`",
	"app_opted_in":      "params: account index, application id (top of the stack on opcode entry). Return: 1 if opted in and 0 otherwise.",
	"app_local_get":     "params: account index, state key. Return: value. The value is zero (of type uint64) if the key does not exist.",
	"app_local_get_ex":  "params: account index, application id, state key. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.",
	"app_global_get_ex": "params: application index, state key. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.",
	"app_global_get":    "params: state key. Return: value. The value is zero (of type uint64) if the key does not exist.",
	"app_local_put":     "params: account index, state key, value.",
	"app_local_del":     "params: account index, state key.\n\nDeleting a key which is already absent has no effect on the application local state. (In particular, it does _not_ cause the program to fail.)",
	"app_global_del":    "params: state key.\n\nDeleting a key which is already absent has no effect on the application global state. (In particular, it does _not_ cause the program to fail.)",
	"asset_holding_get": "params: account index, asset id. Return: did_exist flag (1 if exist and 0 otherwise), value.",
	"asset_params_get":  "params: txn.ForeignAssets offset. Return: did_exist flag (1 if exist and 0 otherwise), value.",
}

// OpDocExtra returns extra documentation text about an op
func OpDocExtra(opName string) string {
	return opDocExtras[opName]
}

// OpGroups is groupings of ops for documentation purposes.
var OpGroups = map[string][]string{
	"Arithmetic":           {"sha256", "keccak256", "sha512_256", "ed25519verify", "+", "-", "/", "*", "<", ">", "<=", ">=", "&&", "||", "shl", "shr", "sqrt", "log2", "exp", "==", "!=", "!", "len", "itob", "btoi", "%", "|", "&", "^", "~", "mulw", "addw", "divmodw", "expw", "getbit", "setbit", "getbyte", "setbyte", "concat", "substring", "substring3"},
	"Byteslice Arithmetic": {"b+", "b-", "b/", "b*", "b<", "b>", "b<=", "b>=", "b==", "b!=", "b%", "b|", "b&", "b^"},
	"Loading Values":       {"intcblock", "intc", "intc_0", "intc_1", "intc_2", "intc_3", "pushint", "bytecblock", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3", "pushbytes", "arg", "arg_0", "arg_1", "arg_2", "arg_3", "txn", "gtxn", "txna", "gtxna", "gtxns", "gtxnsa", "global", "load", "store"},
	"Flow Control":         {"err", "bnz", "bz", "b", "return", "pop", "dup", "dup2", "dig", "swap", "select", "assert", "callsub", "retsub"},
	"State Access":         {"balance", "min_balance", "app_opted_in", "app_local_get", "app_local_get_ex", "app_global_get", "app_global_get_ex", "app_local_put", "app_global_put", "app_local_del", "app_global_del", "asset_holding_get", "asset_params_get"},
}

// OpCost indicates the cost of an operation over the range of
// LogicVersions from From to To.
type OpCost struct {
	From int
	To   int
	Cost int
}

// OpAllCosts returns an array of the cost score for an op by version.
// Each entry indicates the cost over a range of versions, so if the
// cost has remained constant, there is only one result, otherwise
// each entry shows the cost for a consecutive range of versions,
// inclusive.
func OpAllCosts(opName string) []OpCost {
	var costs []OpCost
	for v := 1; v <= LogicVersion; v++ {
		cost := OpsByName[v][opName].Details.Cost
		if cost == 0 {
			continue
		}
		if costs == nil || cost != costs[len(costs)-1].Cost {
			costs = append(costs, OpCost{v, v, cost})
		} else {
			costs[len(costs)-1].To = v
		}
	}

	return costs
}

// TypeNameDescriptions contains extra description about a low level
// protocol transaction Type string, and provide a friendlier type
// constant name in assembler.
var TypeNameDescriptions = map[string]string{
	string(protocol.UnknownTx):         "Unknown type. Invalid transaction",
	string(protocol.PaymentTx):         "Payment",
	string(protocol.KeyRegistrationTx): "KeyRegistration",
	string(protocol.AssetConfigTx):     "AssetConfig",
	string(protocol.AssetTransferTx):   "AssetTransfer",
	string(protocol.AssetFreezeTx):     "AssetFreeze",
	string(protocol.ApplicationCallTx): "ApplicationCall",
}

var onCompletionDescriptions = map[OnCompletionConstType]string{
	NoOp:              "Only execute the `ApprovalProgram` associated with this application ID, with no additional effects.",
	OptIn:             "Before executing the `ApprovalProgram`, allocate local state for this application into the sender's account data.",
	CloseOut:          "After executing the `ApprovalProgram`, clear any local state for this application out of the sender's account data.",
	ClearState:        "Don't execute the `ApprovalProgram`, and instead execute the `ClearStateProgram` (which may not reject this transaction). Additionally, clear any local state for this application out of the sender's account data as in `CloseOutOC`.",
	UpdateApplication: "After executing the `ApprovalProgram`, replace the `ApprovalProgram` and `ClearStateProgram` associated with this application ID with the programs specified in this transaction.",
	DeleteApplication: "After executing the `ApprovalProgram`, delete the application parameters from the account data of the application's creator.",
}

// OnCompletionDescription returns extra description about OnCompletion constants
func OnCompletionDescription(value uint64) string {
	desc, ok := onCompletionDescriptions[OnCompletionConstType(value)]
	if ok {
		return desc
	}
	return "invalid constant value"
}

// OnCompletionPreamble describes what the OnCompletion constants represent.
const OnCompletionPreamble = "An application transaction must indicate the action to be taken following the execution of its approvalProgram or clearStateProgram. The constants below describe the available actions."

var txnFieldDocs = map[string]string{
	"Sender":           "32 byte address",
	"Fee":              "micro-Algos",
	"FirstValid":       "round number",
	"FirstValidTime":   "Causes program to fail; reserved for future use",
	"LastValid":        "round number",
	"Receiver":         "32 byte address",
	"Amount":           "micro-Algos",
	"CloseRemainderTo": "32 byte address",
	"VotePK":           "32 byte address",
	"SelectionPK":      "32 byte address",
	//"VoteFirst": "",
	//"VoteLast": "",
	"TypeEnum":                 "See table below",
	"XferAsset":                "Asset ID",
	"AssetAmount":              "value in Asset's units",
	"AssetSender":              "32 byte address. Causes clawback of all value of asset from AssetSender if Sender is the Clawback address of the asset.",
	"AssetReceiver":            "32 byte address",
	"AssetCloseTo":             "32 byte address",
	"GroupIndex":               "Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1",
	"TxID":                     "The computed ID for this transaction. 32 bytes.",
	"ApplicationID":            "ApplicationID from ApplicationCall transaction",
	"OnCompletion":             "ApplicationCall transaction on completion action",
	"ApplicationArgs":          "Arguments passed to the application in the ApplicationCall transaction",
	"NumAppArgs":               "Number of ApplicationArgs",
	"Accounts":                 "Accounts listed in the ApplicationCall transaction",
	"NumAccounts":              "Number of Accounts",
	"Assets":                   "Foreign Assets listed in the ApplicationCall transaction",
	"NumAssets":                "Number of Assets",
	"Applications":             "Foreign Apps listed in the ApplicationCall transaction",
	"NumApplications":          "Number of Applications",
	"GlobalNumUint":            "Number of global state integers in ApplicationCall",
	"GlobalNumByteSlice":       "Number of global state byteslices in ApplicationCall",
	"LocalNumUint":             "Number of local state integers in ApplicationCall",
	"LocalNumByteSlice":        "Number of local state byteslices in ApplicationCall",
	"ApprovalProgram":          "Approval program",
	"ClearStateProgram":        "Clear state program",
	"RekeyTo":                  "32 byte Sender's new AuthAddr",
	"ConfigAsset":              "Asset ID in asset config transaction",
	"ConfigAssetTotal":         "Total number of units of this asset created",
	"ConfigAssetDecimals":      "Number of digits to display after the decimal place when displaying the asset",
	"ConfigAssetDefaultFrozen": "Whether the asset's slots are frozen by default or not, 0 or 1",
	"ConfigAssetUnitName":      "Unit name of the asset",
	"ConfigAssetName":          "The asset name",
	"ConfigAssetURL":           "URL",
	"ConfigAssetMetadataHash":  "32 byte commitment to some unspecified asset metadata",
	"ConfigAssetManager":       "32 byte address",
	"ConfigAssetReserve":       "32 byte address",
	"ConfigAssetFreeze":        "32 byte address",
	"ConfigAssetClawback":      "32 byte address",
	"FreezeAsset":              "Asset ID being frozen or un-frozen",
	"FreezeAssetAccount":       "32 byte address of the account whose asset slot is being frozen or un-frozen",
	"FreezeAssetFrozen":        "The new frozen value, 0 or 1",
}

// TxnFieldDocs are notes on fields available by `txn` and `gtxn` with extra versioning info if any
func TxnFieldDocs() map[string]string {
	return fieldsDocWithExtra(txnFieldDocs, txnFieldSpecByName)
}

var globalFieldDocs = map[string]string{
	"MinTxnFee":            "micro Algos",
	"MinBalance":           "micro Algos",
	"MaxTxnLife":           "rounds",
	"ZeroAddress":          "32 byte address of all zero bytes",
	"GroupSize":            "Number of transactions in this atomic transaction group. At least 1",
	"LogicSigVersion":      "Maximum supported TEAL version",
	"Round":                "Current round number",
	"LatestTimestamp":      "Last confirmed block UNIX timestamp. Fails if negative",
	"CurrentApplicationID": "ID of current application executing. Fails if no such application is executing",
	"CreatorAddress":       "Address of the creator of the current application. Fails if no such application is executing",
}

// GlobalFieldDocs are notes on fields available in `global` with extra versioning info if any
func GlobalFieldDocs() map[string]string {
	return fieldsDocWithExtra(globalFieldDocs, globalFieldSpecByName)
}

type extractor interface {
	getExtraFor(string) string
}

func fieldsDocWithExtra(source map[string]string, ex extractor) map[string]string {
	result := make(map[string]string, len(source))
	for name, doc := range source {
		if extra := ex.getExtraFor(name); len(extra) > 0 {
			if len(doc) == 0 {
				doc = extra
			} else {
				sep := ". "
				if doc[len(doc)-1] == '.' {
					sep = " "
				}
				doc = fmt.Sprintf("%s%s%s", doc, sep, extra)
			}
		}
		result[name] = doc
	}
	return result
}

// AssetHoldingFieldDocs are notes on fields available in `asset_holding_get`
var AssetHoldingFieldDocs = map[string]string{
	"AssetBalance": "Amount of the asset unit held by this account",
	"AssetFrozen":  "Is the asset frozen or not",
}

// AssetParamsFieldDocs are notes on fields available in `asset_params_get`
var AssetParamsFieldDocs = map[string]string{
	"AssetTotal":         "Total number of units of this asset",
	"AssetDecimals":      "See AssetParams.Decimals",
	"AssetDefaultFrozen": "Frozen by default or not",
	"AssetUnitName":      "Asset unit name",
	"AssetName":          "Asset name",
	"AssetURL":           "URL with additional info about the asset",
	"AssetMetadataHash":  "Arbitrary commitment",
	"AssetManager":       "Manager commitment",
	"AssetReserve":       "Reserve address",
	"AssetFreeze":        "Freeze address",
	"AssetClawback":      "Clawback address",
}
