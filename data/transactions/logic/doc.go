// Copyright (C) 2019-2022 Algorand, Inc.
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
	"github.com/algorand/go-algorand/protocol"
)

// short description of every op
var opDocByName = map[string]string{
	"err":                 "Fail immediately.",
	"sha256":              "SHA256 hash of value A, yields [32]byte",
	"keccak256":           "Keccak256 hash of value A, yields [32]byte",
	"sha512_256":          "SHA512_256 hash of value A, yields [32]byte",
	"sha3_256":            "SHA3_256 hash of value A, yields [32]byte",
	"ed25519verify":       "for (data A, signature B, pubkey C) verify the signature of (\"ProgData\" || program_hash || data) against the pubkey => {0 or 1}",
	"ed25519verify_bare":  "for (data A, signature B, pubkey C) verify the signature of the data against the pubkey => {0 or 1}",
	"ecdsa_verify":        "for (data A, signature B, C and pubkey D, E) verify the signature of the data against the pubkey => {0 or 1}",
	"ecdsa_pk_decompress": "decompress pubkey A into components X, Y",
	"ecdsa_pk_recover":    "for (data A, recovery id B, signature C, D) recover a public key",
	"bn256_add":           "for (curve points A and B) return the curve point A + B",
	"bn256_scalar_mul":    "for (curve point A, scalar K) return the curve point KA",
	"bn256_pairing":       "for (points in G1 group G1s, points in G2 group G2s), return whether they are paired => {0 or 1}",

	"+":       "A plus B. Fail on overflow.",
	"-":       "A minus B. Fail if B > A.",
	"/":       "A divided by B (truncated division). Fail if B == 0.",
	"*":       "A times B. Fail on overflow.",
	"<":       "A less than B => {0 or 1}",
	">":       "A greater than B => {0 or 1}",
	"<=":      "A less than or equal to B => {0 or 1}",
	">=":      "A greater than or equal to B => {0 or 1}",
	"&&":      "A is not zero and B is not zero => {0 or 1}",
	"||":      "A is not zero or B is not zero => {0 or 1}",
	"==":      "A is equal to B => {0 or 1}",
	"!=":      "A is not equal to B => {0 or 1}",
	"!":       "A == 0 yields 1; else 0",
	"len":     "yields length of byte value A",
	"itob":    "converts uint64 A to big-endian byte array, always of length 8",
	"btoi":    "converts big-endian byte array A to uint64. Fails if len(A) > 8. Padded by leading 0s if len(A) < 8.",
	"%":       "A modulo B. Fail if B == 0.",
	"|":       "A bitwise-or B",
	"&":       "A bitwise-and B",
	"^":       "A bitwise-xor B",
	"~":       "bitwise invert value A",
	"shl":     "A times 2^B, modulo 2^64",
	"shr":     "A divided by 2^B",
	"sqrt":    "The largest integer I such that I^2 <= A",
	"bitlen":  "The highest set bit in A. If A is a byte-array, it is interpreted as a big-endian unsigned integer. bitlen of 0 is 0, bitlen of 8 is 4",
	"exp":     "A raised to the Bth power. Fail if A == B == 0 and on overflow",
	"expw":    "A raised to the Bth power as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low. Fail if A == B == 0 or if the results exceeds 2^128-1",
	"mulw":    "A times B as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low",
	"addw":    "A plus B as a 128-bit result. X is the carry-bit, Y is the low-order 64 bits.",
	"divw":    "A,B / C. Fail if C == 0 or if result overflows.",
	"divmodw": "W,X = (A,B / C,D); Y,Z = (A,B modulo C,D)",

	"intcblock":  "prepare block of uint64 constants for use by intc",
	"intc":       "Ith constant from intcblock",
	"intc_0":     "constant 0 from intcblock",
	"intc_1":     "constant 1 from intcblock",
	"intc_2":     "constant 2 from intcblock",
	"intc_3":     "constant 3 from intcblock",
	"pushint":    "immediate UINT",
	"bytecblock": "prepare block of byte-array constants for use by bytec",
	"bytec":      "Ith constant from bytecblock",
	"bytec_0":    "constant 0 from bytecblock",
	"bytec_1":    "constant 1 from bytecblock",
	"bytec_2":    "constant 2 from bytecblock",
	"bytec_3":    "constant 3 from bytecblock",
	"pushbytes":  "immediate BYTES",

	"bzero":   "zero filled byte-array of length A",
	"arg":     "Nth LogicSig argument",
	"arg_0":   "LogicSig argument 0",
	"arg_1":   "LogicSig argument 1",
	"arg_2":   "LogicSig argument 2",
	"arg_3":   "LogicSig argument 3",
	"args":    "Ath LogicSig argument",
	"txn":     "field F of current transaction",
	"gtxn":    "field F of the Tth transaction in the current group",
	"gtxns":   "field F of the Ath transaction in the current group",
	"txna":    "Ith value of the array field F of the current transaction",
	"gtxna":   "Ith value of the array field F from the Tth transaction in the current group",
	"gtxnsa":  "Ith value of the array field F from the Ath transaction in the current group",
	"txnas":   "Ath value of the array field F of the current transaction",
	"gtxnas":  "Ath value of the array field F from the Tth transaction in the current group",
	"gtxnsas": "Bth value of the array field F from the Ath transaction in the current group",
	"itxn":    "field F of the last inner transaction",
	"itxna":   "Ith value of the array field F of the last inner transaction",
	"itxnas":  "Ath value of the array field F of the last inner transaction",
	"gitxn":   "field F of the Tth transaction in the last inner group submitted",
	"gitxna":  "Ith value of the array field F from the Tth transaction in the last inner group submitted",
	"gitxnas": "Ath value of the array field F from the Tth transaction in the last inner group submitted",

	"global":  "global field F",
	"load":    "Ith scratch space value. All scratch spaces are 0 at program start.",
	"store":   "store A to the Ith scratch space",
	"loads":   "Ath scratch space value.  All scratch spaces are 0 at program start.",
	"stores":  "store B to the Ath scratch space",
	"gload":   "Ith scratch space value of the Tth transaction in the current group",
	"gloads":  "Ith scratch space value of the Ath transaction in the current group",
	"gloadss": "Bth scratch space value of the Ath transaction in the current group",
	"gaid":    "ID of the asset or application created in the Tth transaction of the current group",
	"gaids":   "ID of the asset or application created in the Ath transaction of the current group",

	"json_ref": "return key B's value from a [valid](jsonspec.md) utf-8 encoded json object A",

	"bnz":     "branch to TARGET if value A is not zero",
	"bz":      "branch to TARGET if value A is zero",
	"b":       "branch unconditionally to TARGET",
	"return":  "use A as success value; end",
	"pop":     "discard A",
	"dup":     "duplicate A",
	"dup2":    "duplicate A and B",
	"dig":     "Nth value from the top of the stack. dig 0 is equivalent to dup",
	"cover":   "remove top of stack, and place it deeper in the stack such that N elements are above it. Fails if stack depth <= N.",
	"uncover": "remove the value at depth N in the stack and shift above items down so the Nth deep value is on top of the stack. Fails if stack depth <= N.",
	"swap":    "swaps A and B on stack",
	"select":  "selects one of two values based on top-of-stack: B if C != 0, else A",

	"concat":         "join A and B",
	"substring":      "A range of bytes from A starting at S up to but not including E. If E < S, or either is larger than the array length, the program fails",
	"substring3":     "A range of bytes from A starting at B up to but not including C. If C < B, or either is larger than the array length, the program fails",
	"getbit":         "Bth bit of (byte-array or integer) A. If B is greater than or equal to the bit length of the value (8*byte length), the program fails",
	"setbit":         "Copy of (byte-array or integer) A, with the Bth bit set to (0 or 1) C. If B is greater than or equal to the bit length of the value (8*byte length), the program fails",
	"getbyte":        "Bth byte of A, as an integer. If B is greater than or equal to the array length, the program fails",
	"setbyte":        "Copy of A with the Bth byte set to small integer (between 0..255) C. If B is greater than or equal to the array length, the program fails",
	"extract":        "A range of bytes from A starting at S up to but not including S+L. If L is 0, then extract to the end of the string. If S or S+L is larger than the array length, the program fails",
	"extract3":       "A range of bytes from A starting at B up to but not including B+C. If B+C is larger than the array length, the program fails",
	"extract_uint16": "A uint16 formed from a range of big-endian bytes from A starting at B up to but not including B+2. If B+2 is larger than the array length, the program fails",
	"extract_uint32": "A uint32 formed from a range of big-endian bytes from A starting at B up to but not including B+4. If B+4 is larger than the array length, the program fails",
	"extract_uint64": "A uint64 formed from a range of big-endian bytes from A starting at B up to but not including B+8. If B+8 is larger than the array length, the program fails",
	"base64_decode":  "decode A which was base64-encoded using _encoding_ E. Fail if A is not base64 encoded with encoding E",

	"balance":           "get balance for account A, in microalgos. The balance is observed after the effects of previous transactions in the group, and after the fee for the current transaction is deducted.",
	"min_balance":       "get minimum required balance for account A, in microalgos. Required balance is affected by [ASA](https://developer.algorand.org/docs/features/asa/#assets-overview) and [App](https://developer.algorand.org/docs/features/asc1/stateful/#minimum-balance-requirement-for-a-smart-contract) usage. When creating or opting into an app, the minimum balance grows before the app code runs, therefore the increase is visible there. When deleting or closing out, the minimum balance decreases after the app executes.",
	"app_opted_in":      "1 if account A is opted in to application B, else 0",
	"app_local_get":     "local state of the key B in the current application in account A",
	"app_local_get_ex":  "X is the local state of application B, key C in account A. Y is 1 if key existed, else 0",
	"app_global_get":    "global state of the key A in the current application",
	"app_global_get_ex": "X is the global state of application A, key B. Y is 1 if key existed, else 0",
	"app_local_put":     "write C to key B in account A's local state of the current application",
	"app_global_put":    "write B to key A in the global state of the current application",
	"app_local_del":     "delete key B from account A's local state of the current application",
	"app_global_del":    "delete key A from the global state of the current application",
	"asset_holding_get": "X is field F from account A's holding of asset B. Y is 1 if A is opted into B, else 0",
	"asset_params_get":  "X is field F from asset A. Y is 1 if A exists, else 0",
	"app_params_get":    "X is field F from app A. Y is 1 if A exists, else 0",
	"acct_params_get":   "X is field F from account A. Y is 1 if A owns positive algos, else 0",
	"assert":            "immediately fail unless A is a non-zero number",
	"callsub":           "branch unconditionally to TARGET, saving the next instruction on the call stack",
	"retsub":            "pop the top instruction from the call stack and branch to it",

	"b+":  "A plus B. A and B are interpreted as big-endian unsigned integers",
	"b-":  "A minus B. A and B are interpreted as big-endian unsigned integers. Fail on underflow.",
	"b/":  "A divided by B (truncated division). A and B are interpreted as big-endian unsigned integers. Fail if B is zero.",
	"b*":  "A times B. A and B are interpreted as big-endian unsigned integers.",
	"b<":  "1 if A is less than B, else 0. A and B are interpreted as big-endian unsigned integers",
	"b>":  "1 if A is greater than B, else 0. A and B are interpreted as big-endian unsigned integers",
	"b<=": "1 if A is less than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers",
	"b>=": "1 if A is greater than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers",
	"b==": "1 if A is equal to B, else 0. A and B are interpreted as big-endian unsigned integers",
	"b!=": "0 if A is equal to B, else 1. A and B are interpreted as big-endian unsigned integers",
	"b%":  "A modulo B. A and B are interpreted as big-endian unsigned integers. Fail if B is zero.",
	"b|":  "A bitwise-or B. A and B are zero-left extended to the greater of their lengths",
	"b&":  "A bitwise-and B. A and B are zero-left extended to the greater of their lengths",
	"b^":  "A bitwise-xor B. A and B are zero-left extended to the greater of their lengths",
	"b~":  "A with all bits inverted",

	"bsqrt": "The largest integer I such that I^2 <= A. A and I are interpreted as big-endian unsigned integers",

	"log":         "write A to log state of the current application",
	"itxn_begin":  "begin preparation of a new inner transaction in a new transaction group",
	"itxn_next":   "begin preparation of a new inner transaction in the same transaction group",
	"itxn_field":  "set field F of the current inner transaction to A",
	"itxn_submit": "execute the current inner transaction group. Fail if executing this group would exceed the inner transaction limit, or if any transaction in the group fails.",
}

// OpDoc returns a description of the op
func OpDoc(opName string) string {
	return opDocByName[opName]
}

var opcodeImmediateNotes = map[string]string{
	"intcblock":  "{varuint length} [{varuint value}, ...]",
	"intc":       "{uint8 int constant index}",
	"pushint":    "{varuint int}",
	"bytecblock": "{varuint length} [({varuint value length} bytes), ...]",
	"bytec":      "{uint8 byte constant index}",
	"pushbytes":  "{varuint length} {bytes}",

	"arg":    "{uint8 arg index N}",
	"global": "{uint8 global field index}",

	"txn":     "{uint8 transaction field index}",
	"gtxn":    "{uint8 transaction group index} {uint8 transaction field index}",
	"gtxns":   "{uint8 transaction field index}",
	"txna":    "{uint8 transaction field index} {uint8 transaction field array index}",
	"gtxna":   "{uint8 transaction group index} {uint8 transaction field index} {uint8 transaction field array index}",
	"gtxnsa":  "{uint8 transaction field index} {uint8 transaction field array index}",
	"txnas":   "{uint8 transaction field index}",
	"gtxnas":  "{uint8 transaction group index} {uint8 transaction field index}",
	"gtxnsas": "{uint8 transaction field index}",

	"bnz":     "{int16 branch offset, big-endian}",
	"bz":      "{int16 branch offset, big-endian}",
	"b":       "{int16 branch offset, big-endian}",
	"callsub": "{int16 branch offset, big-endian}",

	"load":   "{uint8 position in scratch space to load from}",
	"store":  "{uint8 position in scratch space to store to}",
	"gload":  "{uint8 transaction group index} {uint8 position in scratch space to load from}",
	"gloads": "{uint8 position in scratch space to load from}",
	"gaid":   "{uint8 transaction group index}",

	"substring": "{uint8 start position} {uint8 end position}",
	"extract":   "{uint8 start position} {uint8 length}",
	"dig":       "{uint8 depth}",
	"cover":     "{uint8 depth}",
	"uncover":   "{uint8 depth}",

	"asset_holding_get": "{uint8 asset holding field index}",
	"asset_params_get":  "{uint8 asset params field index}",
	"app_params_get":    "{uint8 app params field index}",
	"acct_params_get":   "{uint8 account params field index}",

	"itxn_field": "{uint8 transaction field index}",
	"itxn":       "{uint8 transaction field index}",
	"itxna":      "{uint8 transaction field index} {uint8 transaction field array index}",
	"itxnas":     "{uint8 transaction field index}",
	"gitxn":      "{uint8 transaction group index} {uint8 transaction field index}",
	"gitxna":     "{uint8 transaction group index} {uint8 transaction field index} {uint8 transaction field array index}",
	"gitxnas":    "{uint8 transaction group index} {uint8 transaction field index}",

	"ecdsa_verify":        "{uint8 curve index}",
	"ecdsa_pk_decompress": "{uint8 curve index}",
	"ecdsa_pk_recover":    "{uint8 curve index}",

	"base64_decode": "{uint8 encoding index}",
	"json_ref":      "{string return type}",
}

// OpImmediateNote returns a short string about immediate data which follows the op byte
func OpImmediateNote(opName string) string {
	return opcodeImmediateNotes[opName]
}

// further documentation on the function of the opcode
var opDocExtras = map[string]string{
	"ed25519verify":       "The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack.",
	"ecdsa_verify":        "The 32 byte Y-component of a public key is the last element on the stack, preceded by X-component of a pubkey, preceded by S and R components of a signature, preceded by the data that is fifth element on the stack. All values are big-endian encoded. The signed data must be 32 bytes long, and signatures in lower-S form are only accepted.",
	"ecdsa_pk_decompress": "The 33 byte public key in a compressed form to be decompressed into X and Y (top) components. All values are big-endian encoded.",
	"ecdsa_pk_recover":    "S (top) and R elements of a signature, recovery id and data (bottom) are expected on the stack and used to deriver a public key. All values are big-endian encoded. The signed data must be 32 bytes long.",
	"bn256_add":           "A, B are curve points in G1 group. Each point consists of (X, Y) where X and Y are 256 bit integers, big-endian encoded. The encoded point is 64 bytes from concatenation of 32 byte X and 32 byte Y.",
	"bn256_scalar_mul":    "A is a curve point in G1 Group and encoded as described in `bn256_add`. Scalar K is a big-endian encoded big integer that has no padding zeros.",
	"bn256_pairing":       "G1s are encoded by the concatenation of encoded G1 points, as described in `bn256_add`. G2s are encoded by the concatenation of encoded G2 points. Each G2 is in form (XA0+i*XA1, YA0+i*YA1) and encoded by big-endian field element XA0, XA1, YA0 and YA1 in sequence.",
	"bnz":                 "The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Starting at v4, the offset is treated as a signed 16 bit integer allowing for backward branches and looping. In prior version (v1 to v3), branch offsets are limited to forward branches only, 0-0x7fff.\n\nAt v2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before v2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)",
	"bz":                  "See `bnz` for details on how branches work. `bz` inverts the behavior of `bnz`.",
	"b":                   "See `bnz` for details on how branches work. `b` always jumps to the offset.",
	"callsub":             "The call stack is separate from the data stack. Only `callsub` and `retsub` manipulate it.",
	"retsub":              "The call stack is separate from the data stack. Only `callsub` and `retsub` manipulate it.",
	"intcblock":           "`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack. Subsequent calls to `intcblock` reset and replace the integer constants available to the script.",
	"bytecblock":          "`bytecblock` loads the following program bytes into an array of byte-array constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack. Subsequent calls to `bytecblock` reset and replace the bytes constants available to the script.",
	"*":                   "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `mulw`.",
	"+":                   "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `addw`.",
	"/":                   "`divmodw` is available to divide the two-element values produced by `mulw` and `addw`.",
	"bitlen":              "bitlen interprets arrays as big-endian integers, unlike setbit/getbit",
	"divw":                "The notation A,B indicates that A and B are interpreted as a uint128 value, with A as the high uint64 and B the low.",
	"divmodw":             "The notation J,K indicates that two uint64 values J and K are interpreted as a uint128 value, with J as the high uint64 and K the low.",
	"txn":                 "FirstValidTime causes the program to fail. The field is reserved for future use.",
	"gtxn":                "for notes on transaction fields available, see `txn`. If this transaction is _i_ in the group, `gtxn i field` is equivalent to `txn field`.",
	"gtxns":               "for notes on transaction fields available, see `txn`. If top of stack is _i_, `gtxns field` is equivalent to `gtxn _i_ field`. gtxns exists so that _i_ can be calculated, often based on the index of the current transaction.",
	"gload":               "`gload` fails unless the requested transaction is an ApplicationCall and T < GroupIndex.",
	"gloads":              "`gloads` fails unless the requested transaction is an ApplicationCall and A < GroupIndex.",
	"gaid":                "`gaid` fails unless the requested transaction created an asset or application and T < GroupIndex.",
	"gaids":               "`gaids` fails unless the requested transaction created an asset or application and A < GroupIndex.",
	"btoi":                "`btoi` fails if the input is longer than 8 bytes.",
	"concat":              "`concat` fails if the result would be greater than 4096 bytes.",
	"pushbytes":           "pushbytes args are not added to the bytecblock during assembly processes",
	"pushint":             "pushint args are not added to the intcblock during assembly processes",
	"getbit":              "see explanation of bit ordering in setbit",
	"setbit":              "When A is a uint64, index 0 is the least significant bit. Setting bit 3 to 1 on the integer 0 yields 8, or 2^3. When A is a byte array, index 0 is the leftmost bit of the leftmost byte. Setting bits 0 through 11 to 1 in a 4-byte-array of 0s yields the byte array 0xfff00000. Setting bit 3 to 1 on the 1-byte-array 0x00 yields the byte array 0x10.",
	"balance":             "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.",
	"min_balance":         "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.",
	"app_opted_in":        "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: 1 if opted in and 0 otherwise.",
	"app_local_get":       "params: Txn.Accounts offset (or, since v4, an _available_ account address), state key. Return: value. The value is zero (of type uint64) if the key does not exist.",
	"app_local_get_ex":    "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.",
	"app_global_get_ex":   "params: Txn.ForeignApps offset (or, since v4, an _available_ application id), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.",
	"app_global_get":      "params: state key. Return: value. The value is zero (of type uint64) if the key does not exist.",
	"app_local_put":       "params: Txn.Accounts offset (or, since v4, an _available_ account address), state key, value.",
	"app_local_del":       "params: Txn.Accounts offset (or, since v4, an _available_ account address), state key.\n\nDeleting a key which is already absent has no effect on the application local state. (In particular, it does _not_ cause the program to fail.)",
	"app_global_del":      "params: state key.\n\nDeleting a key which is already absent has no effect on the application global state. (In particular, it does _not_ cause the program to fail.)",
	"asset_holding_get":   "params: Txn.Accounts offset (or, since v4, an _available_ address), asset id (or, since v4, a Txn.ForeignAssets offset). Return: did_exist flag (1 if the asset existed and 0 otherwise), value.",
	"asset_params_get":    "params: Txn.ForeignAssets offset (or, since v4, an _available_ asset id. Return: did_exist flag (1 if the asset existed and 0 otherwise), value.",
	"app_params_get":      "params: Txn.ForeignApps offset or an _available_ app id. Return: did_exist flag (1 if the application existed and 0 otherwise), value.",
	"log":                 "`log` fails if called more than MaxLogCalls times in a program, or if the sum of logged bytes exceeds 1024 bytes.",
	"itxn_begin":          "`itxn_begin` initializes Sender to the application address; Fee to the minimum allowable, taking into account MinTxnFee and credit from overpaying in earlier transactions; FirstValid/LastValid to the values in the invoking transaction, and all other fields to zero or empty values.",
	"itxn_next":           "`itxn_next` initializes the transaction exactly as `itxn_begin` does",
	"itxn_field":          "`itxn_field` fails if A is of the wrong type for F, including a byte array of the wrong size for use as an address when F is an address field. `itxn_field` also fails if A is an account, asset, or app that is not _available_, or an attempt is made extend an array field beyond the limit imposed by consensus parameters. (Addresses set into asset params of acfg transactions need not be _available_.)",
	"itxn_submit":         "`itxn_submit` resets the current transaction so that it can not be resubmitted. A new `itxn_begin` is required to prepare another inner transaction.",
	"base64_decode":       "Decodes A using the base64 encoding E. Specify the encoding with an immediate arg either as URL and Filename Safe (`URLEncoding`) or Standard (`StdEncoding`). See <a href=\"https://rfc-editor.org/rfc/rfc4648.html#section-4\">RFC 4648</a> (sections 4 and 5). It is assumed that the encoding ends with the exact number of `=` padding characters as required by the RFC. When padding occurs, any unused pad bits in the encoding must be set to zero or the decoding will fail. The special cases of `\\n` and `\\r` are allowed but completely ignored. An error will result when attempting to decode a string with a character that is not in the encoding alphabet or not one of `=`, `\\r`, or `\\n`.",
	"json_ref":            "specify the return type with an immediate arg either as JSONUint64 or JSONString or JSONObject.",
}

// OpDocExtra returns extra documentation text about an op
func OpDocExtra(opName string) string {
	return opDocExtras[opName]
}

// OpGroups is groupings of ops for documentation purposes. The order
// here is the order args opcodes are presented, so place related
// opcodes consecutively, even if their opcode values are not.
var OpGroups = map[string][]string{
	"Arithmetic":              {"sha256", "keccak256", "sha512_256", "sha3_256", "ed25519verify", "ed25519verify_bare", "ecdsa_verify", "ecdsa_pk_recover", "ecdsa_pk_decompress", "bn256_add", "bn256_scalar_mul", "bn256_pairing", "+", "-", "/", "*", "<", ">", "<=", ">=", "&&", "||", "shl", "shr", "sqrt", "bitlen", "exp", "==", "!=", "!", "len", "itob", "btoi", "%", "|", "&", "^", "~", "mulw", "addw", "divw", "divmodw", "expw", "getbit", "setbit", "getbyte", "setbyte", "concat"},
	"Byte Array Manipulation": {"substring", "substring3", "extract", "extract3", "extract_uint16", "extract_uint32", "extract_uint64", "base64_decode", "json_ref"},
	"Byte Array Arithmetic":   {"b+", "b-", "b/", "b*", "b<", "b>", "b<=", "b>=", "b==", "b!=", "b%", "bsqrt"},
	"Byte Array Logic":        {"b|", "b&", "b^", "b~"},
	"Loading Values":          {"intcblock", "intc", "intc_0", "intc_1", "intc_2", "intc_3", "pushint", "bytecblock", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3", "pushbytes", "bzero", "arg", "arg_0", "arg_1", "arg_2", "arg_3", "args", "txn", "gtxn", "txna", "txnas", "gtxna", "gtxnas", "gtxns", "gtxnsa", "gtxnsas", "global", "load", "loads", "store", "stores", "gload", "gloads", "gloadss", "gaid", "gaids"},
	"Flow Control":            {"err", "bnz", "bz", "b", "return", "pop", "dup", "dup2", "dig", "cover", "uncover", "swap", "select", "assert", "callsub", "retsub"},
	"State Access":            {"balance", "min_balance", "app_opted_in", "app_local_get", "app_local_get_ex", "app_global_get", "app_global_get_ex", "app_local_put", "app_global_put", "app_local_del", "app_global_del", "asset_holding_get", "asset_params_get", "app_params_get", "acct_params_get", "log"},
	"Inner Transactions":      {"itxn_begin", "itxn_next", "itxn_field", "itxn_submit", "itxn", "itxna", "itxnas", "gitxn", "gitxna", "gitxnas"},
}

// VerCost indicates the cost of an operation over the range of
// LogicVersions from From to To.
type VerCost struct {
	From int
	To   int
	// Cost is a human readable string to describe costs. Simple opcodes are
	// just an integer, but some opcodes have field or stack dependencies.
	Cost string
}

// OpAllCosts returns an array of the cost of an op by version.  Each entry
// indicates the cost over a range of versions, so if the cost has remained
// constant, there is only one result, otherwise each entry shows the cost for a
// consecutive range of versions, inclusive.
func OpAllCosts(opName string) []VerCost {
	var costs []VerCost
	for v := 1; v <= LogicVersion; v++ {
		spec, ok := OpsByName[v][opName]
		if !ok {
			continue
		}
		cost := spec.OpDetails.docCost()
		if costs == nil || cost != costs[len(costs)-1].Cost {
			costs = append(costs, VerCost{v, v, cost})
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

func addExtra(original string, extra string) string {
	if len(original) == 0 {
		return extra
	}
	if len(extra) == 0 {
		return original
	}
	sep := ". "
	if original[len(original)-1] == '.' {
		sep = " "
	}
	return original + sep + extra
}
