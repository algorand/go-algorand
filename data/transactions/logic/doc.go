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

type stringString struct {
	a string
	b string
}

func stringStringListToMap(they []stringString) map[string]string {
	out := make(map[string]string, len(they))
	for _, v := range they {
		out[v.a] = v.b
	}
	return out
}

// short description of every op
var opDocList = []stringString{
	{"err", "Error. Panic immediately. This is primarily a fencepost against accidental zero bytes getting compiled into programs."},
	{"sha256", "SHA256 hash of value X, yields [32]byte"},
	{"keccak256", "Keccak256 hash of value X, yields [32]byte"},
	{"sha512_256", "SHA512_256 hash of value X, yields [32]byte"},
	{"ed25519verify", "for (data A, signature B, pubkey C) verify the signature of (\"ProgData\" || program_hash || data) against the pubkey => {0 or 1}"},
	{"+", "A plus B. Panic on overflow."},
	{"-", "A minus B. Panic if B > A."},
	{"/", "A divided by B. Panic if B == 0."},
	{"*", "A times B. Panic on overflow."},
	{"<", "A less than B => {0 or 1}"},
	{">", "A greater than B => {0 or 1}"},
	{"<=", "A less than or equal to B => {0 or 1}"},
	{">=", "A greater than or equal to B => {0 or 1}"},
	{"&&", "A is not zero and B is not zero => {0 or 1}"},
	{"||", "A is not zero or B is not zero => {0 or 1}"},
	{"==", "A is equal to B => {0 or 1}"},
	{"!=", "A is not equal to B => {0 or 1}"},
	{"!", "X == 0 yields 1; else 0"},
	{"len", "yields length of byte value X"},
	{"itob", "converts uint64 X to big endian bytes"},
	{"btoi", "converts bytes X as big endian to uint64"},
	{"%", "A modulo B. Panic if B == 0."},
	{"|", "A bitwise-or B"},
	{"&", "A bitwise-and B"},
	{"^", "A bitwise-xor B"},
	{"~", "bitwise invert value X"},
	{"mulw", "A times B out to 128-bit long result as low (top) and high uint64 values on the stack"},
	{"addw", "A plus B out to 128-bit long result as sum (top) and carry-bit uint64 values on the stack"},
	{"intcblock", "load block of uint64 constants"},
	{"intc", "push value from uint64 constants to stack by index into constants"},
	{"intc_0", "push constant 0 from intcblock to stack"},
	{"intc_1", "push constant 1 from intcblock to stack"},
	{"intc_2", "push constant 2 from intcblock to stack"},
	{"intc_3", "push constant 3 from intcblock to stack"},
	{"bytecblock", "load block of byte-array constants"},
	{"bytec", "push bytes constant to stack by index into constants"},
	{"bytec_0", "push constant 0 from bytecblock to stack"},
	{"bytec_1", "push constant 1 from bytecblock to stack"},
	{"bytec_2", "push constant 2 from bytecblock to stack"},
	{"bytec_3", "push constant 3 from bytecblock to stack"},
	{"arg", "push Args[N] value to stack by index"},
	{"arg_0", "push Args[0] to stack"},
	{"arg_1", "push Args[1] to stack"},
	{"arg_2", "push Args[2] to stack"},
	{"arg_3", "push Args[3] to stack"},
	{"txn", "push field from current transaction to stack"},
	{"gtxn", "push field to the stack from a transaction in the current transaction group"},
	{"stxn", "push field to the stack from transaction A in the current group"},
	{"txna", "push value from an array field from current transaction to stack"},
	{"gtxna", "push value from an array field from a transaction in the current transaction group"},
	{"stxna", "pusha value from an array field from transaction A in the current group"},
	{"global", "push value from globals to stack"},
	{"load", "copy a value from scratch space to the stack"},
	{"store", "pop a value from the stack and store to scratch space"},
	{"bnz", "branch if value X is not zero"},
	{"bz", "branch if value X is zero"},
	{"b", "branch unconditionally to offset"},
	{"return", "use last value on stack as success value; end"},
	{"pop", "discard value X from stack"},
	{"dup", "duplicate last value on stack"},
	{"dup2", "duplicate two last values on stack: A, B -> A, B, A, B"},
	{"dig", "duplicate value N from the top of stack"},
	{"swap", "swaps two last values on stack: A, B -> B, A"},
	{"select", "selects one of two values to retain: A, B, C -> A ? B : C"},
	{"concat", "pop two byte strings A and B and join them, push the result"},
	{"substring", "pop a byte string X. For immediate values in 0..255 M and N: extract a range of bytes from it starting at M up to but not including N, push the substring result. If N < M, or either is larger than the string length, the program fails"},
	{"substring3", "pop a byte string A and two integers B and C. Extract a range of bytes from A starting at B up to but not including C, push the substring result. If C < B, or either is larger than the string length, the program fails"},
	{"getbit", "pop an integer A (between 0..63) and integer B. Extract the Ath bit of B and push it. A==0 is lowest order bit."},
	{"setbit", "pop a bit A, integer B (between 0..63), and integer C. Set the Bth bit of C to A, and push the result"},
	{"getbyte", "pop an integer A and string B. Extract the Ath byte of B and push it as an integer"},
	{"setbyte", "pop a small integer A (between (0..255), and integer B, and string C. Set the Bth byte of C to A, and push the result"},
	{"balance", "get balance for the requested account specified by Txn.Accounts[A] in microalgos. A is specified as an account index in the Accounts field of the ApplicationCall transaction, zero index means the sender"},
	{"min_balance", "get minimum balance for the requested account specified by Txn.Accounts[A] in microalgos. A is specified as an account index in the Accounts field of the ApplicationCall transaction, zero index means the sender"},
	{"app_opted_in", "check if account specified by Txn.Accounts[A] opted in for the application B => {0 or 1}"},
	{"app_local_get", "read from account specified by Txn.Accounts[A] from local state of the current application key B => value"},
	{"app_local_get_ex", "read from account specified by Txn.Accounts[A] from local state of the application B key C => {0 or 1 (top), value}"},
	{"app_global_get", "read key A from global state of a current application => value"},
	{"app_global_get_ex", "read from application Txn.ForeignApps[A] global state key B => {0 or 1 (top), value}. A is specified as an account index in the ForeignApps field of the ApplicationCall transaction, zero index means this app"},
	{"app_local_put", "write to account specified by Txn.Accounts[A] to local state of a current application key B with value C"},
	{"app_global_put", "write key A and value B to global state of the current application"},
	{"app_local_del", "delete from account specified by Txn.Accounts[A] local state key B of the current application"},
	{"app_global_del", "delete key A from a global state of the current application"},
	{"asset_holding_get", "read from account specified by Txn.Accounts[A] and asset B holding field X (imm arg) => {0 or 1 (top), value}"},
	{"asset_params_get", "read from asset Txn.ForeignAssets[A] params field X (imm arg) => {0 or 1 (top), value}"},
	{"assert", "immediately fail unless value X is a non-zero number"},
}

var opDocByName map[string]string

// OpDoc returns a description of the op
func OpDoc(opName string) string {
	if opDocByName == nil {
		opDocByName = stringStringListToMap(opDocList)
	}
	return opDocByName[opName]
}

// notes on immediate bytes following the opcode
var opcodeImmediateNoteList = []stringString{
	{"intcblock", "{varuint length} [{varuint value}, ...]"},
	{"intc", "{uint8 int constant index}"},
	{"bytecblock", "{varuint length} [({varuint value length} bytes), ...]"},
	{"bytec", "{uint8 byte constant index}"},
	{"arg", "{uint8 arg index N}"},
	{"txn", "{uint8 transaction field index}"},
	{"gtxn", "{uint8 transaction group index}{uint8 transaction field index}"},
	{"stxn", "{uint8 transaction field index}"},
	{"txna", "{uint8 transaction field index}{uint8 transaction field array index}"},
	{"gtxna", "{uint8 transaction group index}{uint8 transaction field index}{uint8 transaction field array index}"},
	{"stxna", "{uint8 transaction field index}{uint8 transaction field array index}"},
	{"global", "{uint8 global field index}"},
	{"bnz", "{0..0x7fff forward branch offset, big endian}"},
	{"bz", "{0..0x7fff forward branch offset, big endian}"},
	{"b", "{0..0x7fff forward branch offset, big endian}"},
	{"load", "{uint8 position in scratch space to load from}"},
	{"store", "{uint8 position in scratch space to store to}"},
	{"substring", "{uint8 start position}{uint8 end position}"},
	{"dig", "{uint8 depth}"},
	{"asset_holding_get", "{uint8 asset holding field index}"},
	{"asset_params_get", "{uint8 asset params field index}"},
}
var opcodeImmediateNotes map[string]string

// OpImmediateNote returns a short string about immediate data which follows the op byte
func OpImmediateNote(opName string) string {
	if opcodeImmediateNotes == nil {
		opcodeImmediateNotes = stringStringListToMap(opcodeImmediateNoteList)
	}
	return opcodeImmediateNotes[opName]
}

// further documentation on the function of the opcode
var opDocExtraList = []stringString{
	{"ed25519verify", "The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack."},
	{"bnz", "The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be well aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Branch offsets are currently limited to forward branches only, 0-0x7fff. A future expansion might make this a signed 16 bit integer allowing for backward branches and looping.\n\nAt LogicSigVersion 2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before LogicSigVersion 2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)"},
	{"bz", "See `bnz` for details on how branches work. `bz` inverts the behavior of `bnz`."},
	{"b", "See `bnz` for details on how branches work. `b` always jumps to the offset."},
	{"intcblock", "`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack. Subsequent calls to `intcblock` reset and replace the integer constants available to the script."},
	{"bytecblock", "`bytecblock` loads the following program bytes into an array of byte string constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack. Subsequent calls to `bytecblock` reset and replace the bytes constants available to the script."},
	{"*", "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `mulw`."},
	{"+", "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `addw`."},
	{"txn", "FirstValidTime causes the program to fail. The field is reserved for future use."},
	{"gtxn", "for notes on transaction fields available, see `txn`. If this transaction is _i_ in the group, `gtxn i field` is equivalent to `txn field`."},
	{"stxn", "for notes on transaction fields available, see `txn`. If top of stack is _i_, `stxn field` is equivalent to `gtxn _i_ field`."},
	{"btoi", "`btoi` panics if the input is longer than 8 bytes."},
	{"concat", "`concat` panics if the result would be greater than 4096 bytes."},
	{"app_opted_in", "params: account index, application id (top of the stack on opcode entry). Return: 1 if opted in and 0 otherwise."},
	{"app_local_get", "params: account index, state key. Return: value. The value is zero if the key does not exist."},
	{"app_local_get_ex", "params: account index, application id, state key. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value."},
	{"app_global_get_ex", "params: application index, state key. Return: value. Application index is"},
	{"app_global_get", "params: state key. Return: value. The value is zero if the key does not exist."},
	{"app_local_put", "params: account index, state key, value."},
	{"app_local_del", "params: account index, state key.\n\nDeleting a key which is already absent has no effect on the application local state. (In particular, it does _not_ cause the program to fail.)"},
	{"app_global_del", "params: state key.\n\nDeleting a key which is already absent has no effect on the application global state. (In particular, it does _not_ cause the program to fail.)"},
	{"asset_holding_get", "params: account index, asset id. Return: did_exist flag (1 if exist and 0 otherwise), value."},
	{"asset_params_get", "params: txn.ForeignAssets offset. Return: did_exist flag (1 if exist and 0 otherwise), value."},
}

var opDocExtras map[string]string

// OpDocExtra returns extra documentation text about an op
func OpDocExtra(opName string) string {
	if opDocExtras == nil {
		opDocExtras = stringStringListToMap(opDocExtraList)
	}
	return opDocExtras[opName]
}

// OpGroup is a grouping of ops for documentation purposes.
// e.g. "Arithmetic", ["+", "-", ...]
type OpGroup struct {
	GroupName string
	Ops       []string
}

// OpGroupList is groupings of ops for documentation purposes.
var OpGroupList = []OpGroup{
	{"Arithmetic", []string{"sha256", "keccak256", "sha512_256", "ed25519verify", "+", "-", "/", "*", "<", ">", "<=", ">=", "&&", "||", "==", "!=", "!", "len", "itob", "btoi", "%", "|", "&", "^", "~", "mulw", "addw", "getbit", "setbit", "getbyte", "setbyte", "concat", "substring", "substring3"}},
	{"Loading Values", []string{"intcblock", "intc", "intc_0", "intc_1", "intc_2", "intc_3", "bytecblock", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3", "arg", "arg_0", "arg_1", "arg_2", "arg_3", "txn", "gtxn", "txna", "gtxna", "stxn", "stxna", "global", "load", "store"}},
	{"Flow Control", []string{"err", "bnz", "bz", "b", "return", "pop", "dup", "dup2", "dig", "swap", "select", "assert"}},
	{"State Access", []string{"balance", "min_balance", "app_opted_in", "app_local_get", "app_local_get_ex", "app_global_get", "app_global_get_ex", "app_local_put", "app_global_put", "app_local_del", "app_global_del", "asset_holding_get", "asset_params_get"}},
}

// OpCost returns the relative cost score for an op
func OpCost(opName string) int {
	return opsByName[LogicVersion][opName].opSize.cost
}

// OpAllCosts returns an array of the relative cost score for an op by version.
// If all the costs are the same the array is single entry
// otherwise it has costs by op version
func OpAllCosts(opName string) []int {
	cost := opsByName[LogicVersion][opName].opSize.cost
	costs := make([]int, LogicVersion+1)
	isDifferent := false
	for v := 1; v <= LogicVersion; v++ {
		costs[v] = opsByName[v][opName].opSize.cost
		if costs[v] > 0 && costs[v] != cost {
			isDifferent = true
		}
	}
	if !isDifferent {
		return []int{cost}
	}

	return costs
}

// OpSize returns the number of bytes for an op. 0 for variable.
func OpSize(opName string) int {
	return opsByName[LogicVersion][opName].opSize.size
}

// see assembler.go TxnTypeNames
// also used to parse symbolic constants for `int`
var typeEnumDescriptions = []stringString{
	{string(protocol.UnknownTx), "Unknown type. Invalid transaction"},
	{string(protocol.PaymentTx), "Payment"},
	{string(protocol.KeyRegistrationTx), "KeyRegistration"},
	{string(protocol.AssetConfigTx), "AssetConfig"},
	{string(protocol.AssetTransferTx), "AssetTransfer"},
	{string(protocol.AssetFreezeTx), "AssetFreeze"},
	{string(protocol.ApplicationCallTx), "ApplicationCall"},
}

// TypeNameDescription returns extra description about a low level protocol transaction Type string
func TypeNameDescription(typeName string) string {
	for _, ted := range typeEnumDescriptions {
		if typeName == ted.a {
			return ted.b
		}
	}
	return "invalid type name"
}

// see assembler.go TxnTypeNames
// also used to parse symbolic constants for `int`
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

var txnFieldDocList = []stringString{
	{"Sender", "32 byte address"},
	{"Fee", "micro-Algos"},
	{"FirstValid", "round number"},
	{"FirstValidTime", "Causes program to fail; reserved for future use"},
	{"LastValid", "round number"},
	{"Receiver", "32 byte address"},
	{"Amount", "micro-Algos"},
	{"CloseRemainderTo", "32 byte address"},
	{"VotePK", "32 byte address"},
	{"SelectionPK", "32 byte address"},
	//{"VoteFirst", ""},
	//{"VoteLast", ""},
	{"TypeEnum", "See table below"},
	{"XferAsset", "Asset ID"},
	{"AssetAmount", "value in Asset's units"},
	{"AssetSender", "32 byte address. Causes clawback of all value of asset from AssetSender if Sender is the Clawback address of the asset."},
	{"AssetReceiver", "32 byte address"},
	{"AssetCloseTo", "32 byte address"},
	{"GroupIndex", "Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1"},
	{"TxID", "The computed ID for this transaction. 32 bytes."},
	{"ApplicationID", "ApplicationID from ApplicationCall transaction"},
	{"OnCompletion", "ApplicationCall transaction on completion action"},
	{"ApplicationArgs", "Arguments passed to the application in the ApplicationCall transaction"},
	{"NumAppArgs", "Number of ApplicationArgs"},
	{"Accounts", "Accounts listed in the ApplicationCall transaction"},
	{"NumAccounts", "Number of Accounts"},
	{"ForeignAssets", "Foreign Assets listed in the ApplicationCall transaction"},
	{"NumForeignAssets", "Number of Assets"},
	{"ForeignApps", "Foreign Apps listed in the ApplicationCall transaction"},
	{"NumForeignApps", "Number of Applications"},
	{"GlobalStateInts", "Number of global state integers in ApplicationCall"},
	{"GlobalStateByteslices", "Number of global state byteslices in ApplicationCall"},
	{"LocalStateInts", "Number of local state integers in ApplicationCall"},
	{"LocalStateByteslices", "Number of local state byteslices in ApplicationCall"},
	{"ApprovalProgram", "Approval program"},
	{"ClearStateProgram", "Clear state program"},
	{"RekeyTo", "32 byte Sender's new AuthAddr"},
	{"ConfigAsset", "Asset ID in asset config transaction"},
	{"ConfigAssetTotal", "Total number of units of this asset created"},
	{"ConfigAssetDecimals", "Number of digits to display after the decimal place when displaying the asset"},
	{"ConfigAssetDefaultFrozen", "Whether the asset's slots are frozen by default or not, 0 or 1"},
	{"ConfigAssetUnitName", "Unit name of the asset"},
	{"ConfigAssetName", "The asset name"},
	{"ConfigAssetURL", "URL"},
	{"ConfigAssetMetadataHash", "32 byte commitment to some unspecified asset metadata"},
	{"ConfigAssetManager", "32 byte address"},
	{"ConfigAssetReserve", "32 byte address"},
	{"ConfigAssetFreeze", "32 byte address"},
	{"ConfigAssetClawback", "32 byte address"},
	{"FreezeAsset", "Asset ID being frozen or un-frozen"},
	{"FreezeAssetAccount", "32 byte address of the account whose asset slot is being frozen or un-frozen"},
	{"FreezeAssetFrozen", "The new frozen value, 0 or 1"},
}

// TxnFieldDocs are notes on fields available by `txn` and `gtxn`
var txnFieldDocs map[string]string

// TxnFieldDocs are notes on fields available by `txn` and `gtxn` with extra versioning info if any
func TxnFieldDocs() map[string]string {
	return fieldsDocWithExtra(txnFieldDocs, txnFieldSpecByName)
}

var globalFieldDocList = []stringString{
	{"MinTxnFee", "micro Algos"},
	{"MinBalance", "micro Algos"},
	{"MaxTxnLife", "rounds"},
	{"ZeroAddress", "32 byte address of all zero bytes"},
	{"GroupSize", "Number of transactions in this atomic transaction group. At least 1"},
	{"LogicSigVersion", "Maximum supported TEAL version"},
	{"Round", "Current round number"},
	{"LatestTimestamp", "Last confirmed block UNIX timestamp. Fails if negative"},
	{"CurrentApplicationID", "ID of current application executing. Fails if no such application is executing"},
	{"CreatorAddress", "Address of the creator of the current application. Fails if no such application is executing"},
}

// globalFieldDocs are notes on fields available in `global`
var globalFieldDocs map[string]string

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

var assetHoldingFieldDocList = []stringString{
	{"AssetBalance", "Amount of the asset unit held by this account"},
	{"AssetFrozen", "Is the asset frozen or not"},
}

// AssetHoldingFieldDocs are notes on fields available in `asset_holding_get`
var AssetHoldingFieldDocs map[string]string

var assetParamsFieldDocList = []stringString{
	{"AssetTotal", "Total number of units of this asset"},
	{"AssetDecimals", "See AssetParams.Decimals"},
	{"AssetDefaultFrozen", "Frozen by default or not"},
	{"AssetUnitName", "Asset unit name"},
	{"AssetName", "Asset name"},
	{"AssetURL", "URL with additional info about the asset"},
	{"AssetMetadataHash", "Arbitrary commitment"},
	{"AssetManager", "Manager commitment"},
	{"AssetReserve", "Reserve address"},
	{"AssetFreeze", "Freeze address"},
	{"AssetClawback", "Clawback address"},
}

// AssetParamsFieldDocs are notes on fields available in `asset_params_get`
var AssetParamsFieldDocs map[string]string

func init() {
	txnFieldDocs = stringStringListToMap(txnFieldDocList)
	globalFieldDocs = stringStringListToMap(globalFieldDocList)
	AssetHoldingFieldDocs = stringStringListToMap(assetHoldingFieldDocList)
	AssetParamsFieldDocs = stringStringListToMap(assetParamsFieldDocList)
}
