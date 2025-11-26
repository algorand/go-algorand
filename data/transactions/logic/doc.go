// Copyright (C) 2019-2025 Algorand, Inc.
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
	"strings"

	"github.com/algorand/go-algorand/protocol"
)

// OpDesc contains the human readable descriptions of opcodes and their
// immediate arguments.
type OpDesc struct {
	Short      string
	Extra      string
	Immediates []string
}

var opDescByName = map[string]OpDesc{
	"err": {"Fail immediately.", "", nil},

	"sha256":     {"SHA256 hash of value A, yields [32]byte", "", nil},
	"keccak256":  {"Keccak256 hash of value A, yields [32]byte", "", nil},
	"sha512_256": {"SHA512_256 hash of value A, yields [32]byte", "", nil},
	"sha3_256":   {"SHA3_256 hash of value A, yields [32]byte", "", nil},
	"sha512":     {"SHA512 of value A, yields [64]byte", "", nil},

	"sumhash512":    {"sumhash512 of value A, yields [64]byte", "", nil},
	"falcon_verify": {"for (data A, compressed-format signature B, pubkey C) verify the signature of data against the pubkey => {0 or 1}", "", nil},

	"mimc": {"MiMC hash of scalars A, using curve and parameters specified by configuration C", "" +
		"A is a list of concatenated 32 byte big-endian unsigned integer scalars.  Fail if A's length is not a multiple of 32 or any element exceeds the curve modulus.\n\n" +
		"The MiMC hash function has known collisions since any input which is a multiple of the elliptic curve modulus will hash to the same value. " +
		"MiMC is thus not a general purpose hash function, but meant to be used in zero knowledge applications to match a zk-circuit implementation.",
		[]string{"configuration index"},
	},

	"ed25519verify":       {"for (data A, signature B, pubkey C) verify the signature of (\"ProgData\" || program_hash || data) against the pubkey => {0 or 1}", "The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack.", nil},
	"ed25519verify_bare":  {"for (data A, signature B, pubkey C) verify the signature of the data against the pubkey => {0 or 1}", "", nil},
	"ecdsa_verify":        {"for (data A, signature B, C and pubkey D, E) verify the signature of the data against the pubkey => {0 or 1}", "The 32 byte Y-component of a public key is the last element on the stack, preceded by X-component of a pubkey, preceded by S and R components of a signature, preceded by the data that is fifth element on the stack. All values are big-endian encoded. The signed data must be 32 bytes long, and signatures in lower-S form are only accepted.", []string{"curve index"}},
	"ecdsa_pk_decompress": {"decompress pubkey A into components X, Y", "The 33 byte public key in a compressed form to be decompressed into X and Y (top) components. All values are big-endian encoded.", []string{"curve index"}},
	"ecdsa_pk_recover":    {"for (data A, recovery id B, signature C, D) recover a public key", "S (top) and R elements of a signature, recovery id and data (bottom) are expected on the stack and used to deriver a public key. All values are big-endian encoded. The signed data must be 32 bytes long.", []string{"curve index"}},

	"ec_add": {"for curve points A and B, return the curve point A + B", "" +
		"A and B are curve points in affine representation: field element X concatenated with field element Y. " +
		"Field element `Z` is encoded as follows.\n" +
		"For the base field elements (Fp), `Z` is encoded as a big-endian number and must be lower than the field modulus.\n" +
		"For the quadratic field extension (Fp2), `Z` is encoded as the concatenation of the individual encoding of the coefficients. " +
		"For an Fp2 element of the form `Z = Z0 + Z1 i`, where `i` is a formal quadratic non-residue, the encoding of Z is the concatenation of the encoding of `Z0` and `Z1` in this order. (`Z0` and `Z1` must be less than the field modulus).\n\n" +
		"The point at infinity is encoded as `(X,Y) = (0,0)`.\n" +
		"Groups G1 and G2 are denoted additively.\n\n" +
		"Fails if A or B is not in G.\n" +
		"A and/or B are allowed to be the point at infinity.\n" +
		"Does _not_ check if A and B are in the main prime-order subgroup.",
		[]string{"curve index"},
	},
	"ec_scalar_mul": {"for curve point A and scalar B, return the curve point BA, the point A multiplied by the scalar B.",
		"A is a curve point encoded and checked as described in `ec_add`. Scalar B is interpreted as a big-endian unsigned integer. Fails if B exceeds 32 bytes.",
		[]string{"curve index"},
	},
	"ec_pairing_check": {"1 if the product of the pairing of each point in A with its respective point in B is equal to the identity element of the target group Gt, else 0",
		"A and B are concatenated points, encoded and checked as described in `ec_add`. A contains points of the group G, B contains points of the associated group (G2 if G is G1, and vice versa). Fails if A and B have a different number of points, or if any point is not in its described group or outside the main prime-order subgroup - a stronger condition than other opcodes. AVM values are limited to 4096 bytes, so `ec_pairing_check` is limited by the size of the points in the groups being operated upon.",
		[]string{"curve index"},
	},
	"ec_multi_scalar_mul": {"for curve points A and scalars B, return curve point B0A0 + B1A1 + B2A2 + ... + BnAn",
		"A is a list of concatenated points, encoded and checked as described in `ec_add`. B is a list of concatenated scalars which, unlike ec_scalar_mul, must all be exactly 32 bytes long.\nThe name `ec_multi_scalar_mul` was chosen to reflect common usage, but a more consistent name would be `ec_multi_scalar_mul`. AVM values are limited to 4096 bytes, so `ec_multi_scalar_mul` is limited by the size of the points in the group being operated upon.",
		[]string{"curve index"},
	},
	"ec_subgroup_check": {"1 if A is in the main prime-order subgroup of G (including the point at infinity) else 0. Program fails if A is not in G at all.", "", []string{"curve index"}},
	"ec_map_to": {"maps field element A to group G", "" +
		"BN254 points are mapped by the SVDW map. BLS12-381 points are mapped by the SSWU map.\n" +
		"G1 element inputs are base field elements and G2 element inputs are quadratic field elements, with nearly the same encoding rules (for field elements) as defined in `ec_add`. There is one difference of encoding rule: G1 element inputs do not need to be 0-padded if they fit in less than 32 bytes for BN254 and less than 48 bytes for BLS12-381. (As usual, the empty byte array represents 0.) G2 elements inputs need to be always have the required size.",
		[]string{"curve index"},
	},

	"+":  {"A plus B. Fail on overflow.", "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `addw`.", nil},
	"-":  {"A minus B. Fail if B > A.", "", nil},
	"/":  {"A divided by B (truncated division). Fail if B == 0.", "`divmodw` is available to divide the two-element values produced by `mulw` and `addw`.", nil},
	"*":  {"A times B. Fail on overflow.", "Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `mulw`.", nil},
	"<":  {"A less than B => {0 or 1}", "", nil},
	">":  {"A greater than B => {0 or 1}", "", nil},
	"<=": {"A less than or equal to B => {0 or 1}", "", nil},
	">=": {"A greater than or equal to B => {0 or 1}", "", nil},
	"&&": {"A is not zero and B is not zero => {0 or 1}", "", nil},
	"||": {"A is not zero or B is not zero => {0 or 1}", "", nil},
	"==": {"A is equal to B => {0 or 1}", "", nil},
	"!=": {"A is not equal to B => {0 or 1}", "", nil},
	"!":  {"A == 0 yields 1; else 0", "", nil},

	"len":  {"yields length of byte value A", "", nil},
	"itob": {"converts uint64 A to big-endian byte array, always of length 8", "", nil},
	"btoi": {"converts big-endian byte array A to uint64. Fails if len(A) > 8. Padded by leading 0s if len(A) < 8.",
		"`btoi` fails if the input is longer than 8 bytes.", nil},

	"%":      {"A modulo B. Fail if B == 0.", "", nil},
	"|":      {"A bitwise-or B", "", nil},
	"&":      {"A bitwise-and B", "", nil},
	"^":      {"A bitwise-xor B", "", nil},
	"~":      {"bitwise invert value A", "", nil},
	"shl":    {"A times 2^B, modulo 2^64", "", nil},
	"shr":    {"A divided by 2^B", "", nil},
	"sqrt":   {"The largest integer I such that I^2 <= A", "", nil},
	"bitlen": {"The highest set bit in A. If A is a byte-array, it is interpreted as a big-endian unsigned integer. bitlen of 0 is 0, bitlen of 8 is 4", "bitlen interprets arrays as big-endian integers, unlike setbit/getbit", nil},
	"exp":    {"A raised to the Bth power. Fail if A == B == 0 and on overflow", "", nil},
	"expw":   {"A raised to the Bth power as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low. Fail if A == B == 0 or if the results exceeds 2^128-1", "", nil},
	"mulw":   {"A times B as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low", "", nil},
	"addw":   {"A plus B as a 128-bit result. X is the carry-bit, Y is the low-order 64 bits.", "", nil},
	"divw": {"A,B / C. Fail if C == 0 or if result overflows.",
		"The notation A,B indicates that A and B are interpreted as a uint128 value, with A as the high uint64 and B the low.", nil},
	"divmodw": {"W,X = (A,B / C,D); Y,Z = (A,B modulo C,D)",
		"The notation J,K indicates that two uint64 values J and K are interpreted as a uint128 value, with J as the high uint64 and K the low.", nil},

	"intcblock":  {"prepare block of uint64 constants for use by intc", "`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack. Subsequent calls to `intcblock` reset and replace the integer constants available to the script.", []string{"a block of int constant values"}},
	"intc":       {"Ith constant from intcblock", "", []string{"an index in the intcblock"}},
	"intc_0":     {"constant 0 from intcblock", "", nil},
	"intc_1":     {"constant 1 from intcblock", "", nil},
	"intc_2":     {"constant 2 from intcblock", "", nil},
	"intc_3":     {"constant 3 from intcblock", "", nil},
	"pushint":    {"immediate UINT", "pushint args are not added to the intcblock during assembly processes", []string{"an int constant"}},
	"pushints":   {"push sequence of immediate uints to stack in the order they appear (first uint being deepest)", "pushints args are not added to the intcblock during assembly processes", []string{"a list of int constants"}},
	"bytecblock": {"prepare block of byte-array constants for use by bytec", "`bytecblock` loads the following program bytes into an array of byte-array constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack. Subsequent calls to `bytecblock` reset and replace the bytes constants available to the script.", []string{"a block of byte constant values"}},
	"bytec":      {"Ith constant from bytecblock", "", []string{"an index in the bytecblock"}},
	"bytec_0":    {"constant 0 from bytecblock", "", nil},
	"bytec_1":    {"constant 1 from bytecblock", "", nil},
	"bytec_2":    {"constant 2 from bytecblock", "", nil},
	"bytec_3":    {"constant 3 from bytecblock", "", nil},
	"pushbytes":  {"immediate BYTES", "pushbytes args are not added to the bytecblock during assembly processes", []string{"a byte constant"}},
	"pushbytess": {"push sequences of immediate byte arrays to stack (first byte array being deepest)",
		"pushbytess args are not added to the bytecblock during assembly processes",
		[]string{"a list of byte constants"}},

	"bzero": {"zero filled byte-array of length A", "", nil},
	"arg":   {"Nth LogicSig argument", "", []string{"an arg index"}},
	"arg_0": {"LogicSig argument 0", "", nil},
	"arg_1": {"LogicSig argument 1", "", nil},
	"arg_2": {"LogicSig argument 2", "", nil},
	"arg_3": {"LogicSig argument 3", "", nil},
	"args":  {"Ath LogicSig argument", "", nil},

	"txn": {"field F of current transaction", "", []string{"transaction field index"}},
	"gtxn": {
		"field F of the Tth transaction in the current group",
		"for notes on transaction fields available, see `txn`. If this transaction is _i_ in the group, `gtxn i field` is equivalent to `txn field`.",
		[]string{"transaction group index", "transaction field index"},
	},
	"gtxns": {"field F of the Ath transaction in the current group",
		"for notes on transaction fields available, see `txn`. If top of stack is _i_, `gtxns field` is equivalent to `gtxn _i_ field`. gtxns exists so that _i_ can be calculated, often based on the index of the current transaction.",
		[]string{"transaction field index"},
	},
	"txna": {"Ith value of the array field F of the current transaction", "",
		[]string{"transaction field index", "transaction field array index"}},
	"gtxna": {"Ith value of the array field F from the Tth transaction in the current group", "",
		[]string{"transaction group index", "transaction field index", "transaction field array index"}},
	"gtxnsa": {"Ith value of the array field F from the Ath transaction in the current group", "",
		[]string{"transaction field index", "transaction field array index"}},
	"txnas": {"Ath value of the array field F of the current transaction", "",
		[]string{"transaction field index"}},
	"gtxnas": {"Ath value of the array field F from the Tth transaction in the current group", "",
		[]string{"transaction group index", "transaction field index"}},
	"gtxnsas": {"Bth value of the array field F from the Ath transaction in the current group", "",
		[]string{"transaction field index"}},
	"itxn": {"field F of the last inner transaction", "", []string{"transaction field index"}},
	"itxna": {"Ith value of the array field F of the last inner transaction", "",
		[]string{"transaction field index", "a transaction field array index"}},
	"itxnas": {"Ath value of the array field F of the last inner transaction", "",
		[]string{"transaction field index"}},
	"gitxn": {"field F of the Tth transaction in the last inner group submitted", "",
		[]string{"transaction group index", "transaction field index"}},
	"gitxna": {"Ith value of the array field F from the Tth transaction in the last inner group submitted", "",
		[]string{"transaction group index", "transaction field index", "transaction field array index"}},
	"gitxnas": {"Ath value of the array field F from the Tth transaction in the last inner group submitted", "",
		[]string{"transaction group index", "transaction field index"}},

	"global": {"global field F", "", []string{"a global field index"}},
	"load": {"Ith scratch space value. All scratch spaces are 0 at program start.", "",
		[]string{"position in scratch space to load from"}},
	"store": {"store A to the Ith scratch space", "",
		[]string{"position in scratch space to store to"}},
	"loads":  {"Ath scratch space value.  All scratch spaces are 0 at program start.", "", nil},
	"stores": {"store B to the Ath scratch space", "", nil},
	"gload": {"Ith scratch space value of the Tth transaction in the current group",
		"`gload` fails unless the requested transaction is an ApplicationCall and T < GroupIndex.",
		[]string{"transaction group index", "position in scratch space to load from"}},
	"gloads": {"Ith scratch space value of the Ath transaction in the current group",
		"`gloads` fails unless the requested transaction is an ApplicationCall and A < GroupIndex.",
		[]string{"position in scratch space to load from"},
	},
	"gloadss": {"Bth scratch space value of the Ath transaction in the current group", "", nil},
	"gaid": {"ID of the asset or application created in the Tth transaction of the current group",
		"`gaid` fails unless the requested transaction created an asset or application and T < GroupIndex.",
		[]string{"transaction group index"}},
	"gaids": {"ID of the asset or application created in the Ath transaction of the current group",
		"`gaids` fails unless the requested transaction created an asset or application and A < GroupIndex.", nil},

	"json_ref": {"key B's value, of type R, from a [valid](jsonspec.md) utf-8 encoded json object A",
		"*Warning*: Usage should be restricted to very rare use cases, as JSON decoding is expensive and quite limited. In addition, JSON objects are large and not optimized for size.\n\nAlmost all smart contracts should use simpler and smaller methods (such as the [ABI](https://arc.algorand.foundation/ARCs/arc-0004). This opcode should only be used in cases where JSON is only available option, e.g. when a third-party only signs JSON.",
		[]string{"return type index"}},

	"bnz":    {"branch to TARGET if value A is not zero", "The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Starting at v4, the offset is treated as a signed 16 bit integer allowing for backward branches and looping. In prior version (v1 to v3), branch offsets are limited to forward branches only, 0-0x7fff.\n\nAt v2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before v2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)", []string{"branch offset"}},
	"bz":     {"branch to TARGET if value A is zero", "See `bnz` for details on how branches work. `bz` inverts the behavior of `bnz`.", []string{"branch offset"}},
	"b":      {"branch unconditionally to TARGET", "See `bnz` for details on how branches work. `b` always jumps to the offset.", []string{"branch offset"}},
	"return": {"use A as success value; end", "", nil},

	"pop":     {"discard A", "", nil},
	"dup":     {"duplicate A", "", nil},
	"dup2":    {"duplicate A and B", "", nil},
	"dupn":    {"duplicate A, N times", "", []string{"copy count"}},
	"dig":     {"Nth value from the top of the stack. dig 0 is equivalent to dup", "", []string{"depth"}},
	"bury":    {"replace the Nth value from the top of the stack with A. bury 0 fails.", "", []string{"depth"}},
	"cover":   {"remove top of stack, and place it deeper in the stack such that N elements are above it. Fails if stack depth <= N.", "", []string{"depth"}},
	"uncover": {"remove the value at depth N in the stack and shift above items down so the Nth deep value is on top of the stack. Fails if stack depth <= N.", "", []string{"depth"}},
	"swap":    {"swaps A and B on stack", "", nil},
	"select":  {"selects one of two values based on top-of-stack: B if C != 0, else A", "", nil},

	"concat":         {"join A and B", "`concat` fails if the result would be greater than 4096 bytes.", nil},
	"substring":      {"A range of bytes from A starting at S up to but not including E. If E < S, or either is larger than the array length, the program fails", "", []string{"start position", "end position"}},
	"substring3":     {"A range of bytes from A starting at B up to but not including C. If C < B, or either is larger than the array length, the program fails", "", nil},
	"getbit":         {"Bth bit of (byte-array or integer) A. If B is greater than or equal to the bit length of the value (8*byte length), the program fails", "see explanation of bit ordering in setbit", nil},
	"setbit":         {"Copy of (byte-array or integer) A, with the Bth bit set to (0 or 1) C. If B is greater than or equal to the bit length of the value (8*byte length), the program fails", "When A is a uint64, index 0 is the least significant bit. Setting bit 3 to 1 on the integer 0 yields 8, or 2^3. When A is a byte array, index 0 is the leftmost bit of the leftmost byte. Setting bits 0 through 11 to 1 in a 4-byte-array of 0s yields the byte array 0xfff00000. Setting bit 3 to 1 on the 1-byte-array 0x00 yields the byte array 0x10.", nil},
	"getbyte":        {"Bth byte of A, as an integer. If B is greater than or equal to the array length, the program fails", "", nil},
	"setbyte":        {"Copy of A with the Bth byte set to small integer (between 0..255) C. If B is greater than or equal to the array length, the program fails", "", nil},
	"extract":        {"A range of bytes from A starting at S up to but not including S+L. If L is 0, then extract to the end of the string. If S or S+L is larger than the array length, the program fails", "", []string{"start position", "length"}},
	"extract3":       {"A range of bytes from A starting at B up to but not including B+C. If B+C is larger than the array length, the program fails", "", nil},
	"extract_uint16": {"A uint16 formed from a range of big-endian bytes from A starting at B up to but not including B+2. If B+2 is larger than the array length, the program fails", "", nil},
	"extract_uint32": {"A uint32 formed from a range of big-endian bytes from A starting at B up to but not including B+4. If B+4 is larger than the array length, the program fails", "", nil},
	"extract_uint64": {"A uint64 formed from a range of big-endian bytes from A starting at B up to but not including B+8. If B+8 is larger than the array length, the program fails", "", nil},
	"replace2":       {"Copy of A with the bytes starting at S replaced by the bytes of B. Fails if S+len(B) exceeds len(A)", "", []string{"start position"}},
	"replace3":       {"Copy of A with the bytes starting at B replaced by the bytes of C. Fails if B+len(C) exceeds len(A)", "", nil},

	"base64_decode": {"decode A which was base64-encoded using _encoding_ E. Fail if A is not base64 encoded with encoding E", "*Warning*: Usage should be restricted to very rare use cases. In almost all cases, smart contracts should directly handle non-encoded byte-strings.	This opcode should only be used in cases where base64 is the only available option, e.g. interoperability with a third-party that only signs base64 strings.\n\n Decodes A using the base64 encoding E. Specify the encoding with an immediate arg either as URL and Filename Safe (`URLEncoding`) or Standard (`StdEncoding`). See [RFC 4648 sections 4 and 5](https://rfc-editor.org/rfc/rfc4648.html#section-4). It is assumed that the encoding ends with the exact number of `=` padding characters as required by the RFC. When padding occurs, any unused pad bits in the encoding must be set to zero or the decoding will fail. The special cases of `\\n` and `\\r` are allowed but completely ignored. An error will result when attempting to decode a string with a character that is not in the encoding alphabet or not one of `=`, `\\r`, or `\\n`.", []string{"encoding index"}},

	"balance":           {"balance for account A, in microalgos. The balance is observed after the effects of previous transactions in the group, and after the fee for the current transaction is deducted. Changes caused by inner transactions are observable immediately following `itxn_submit`", "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.", nil},
	"min_balance":       {"minimum required balance for account A, in microalgos. Required balance is affected by ASA, App, and Box usage. When creating or opting into an app, the minimum balance grows before the app code runs, therefore the increase is visible there. When deleting or closing out, the minimum balance decreases after the app executes. Changes caused by inner transactions or box usage are observable immediately following the opcode effecting the change.", "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.", nil},
	"app_opted_in":      {"1 if account A is opted in to application B, else 0", "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: 1 if opted in and 0 otherwise.", nil},
	"app_local_get":     {"local state of the key B in the current application in account A", "params: Txn.Accounts offset (or, since v4, an _available_ account address), state key. Return: value. The value is zero (of type uint64) if the key does not exist.", nil},
	"app_local_get_ex":  {"X is the local state of application B, key C in account A. Y is 1 if key existed, else 0", "params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.", nil},
	"app_global_get":    {"global state of the key A in the current application", "params: state key. Return: value. The value is zero (of type uint64) if the key does not exist.", nil},
	"app_global_get_ex": {"X is the global state of application A, key B. Y is 1 if key existed, else 0", "params: Txn.ForeignApps offset (or, since v4, an _available_ application id), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.", nil},
	"app_local_put":     {"write C to key B in account A's local state of the current application", "params: Txn.Accounts offset (or, since v4, an _available_ account address), state key, value.", nil},
	"app_global_put":    {"write B to key A in the global state of the current application", "", nil},
	"app_local_del":     {"delete key B from account A's local state of the current application", "params: Txn.Accounts offset (or, since v4, an _available_ account address), state key.\n\nDeleting a key which is already absent has no effect on the application local state. (In particular, it does _not_ cause the program to fail.)", nil},
	"app_global_del":    {"delete key A from the global state of the current application", "params: state key.\n\nDeleting a key which is already absent has no effect on the application global state. (In particular, it does _not_ cause the program to fail.)", nil},
	"asset_holding_get": {"X is field F from account A's holding of asset B. Y is 1 if A is opted into B, else 0", "params: Txn.Accounts offset (or, since v4, an _available_ address), asset id (or, since v4, a Txn.ForeignAssets offset). Return: did_exist flag (1 if the asset existed and 0 otherwise), value.", []string{"asset holding field index"}},
	"asset_params_get":  {"X is field F from asset A. Y is 1 if A exists, else 0", "params: Txn.ForeignAssets offset (or, since v4, an _available_ asset id. Return: did_exist flag (1 if the asset existed and 0 otherwise), value.", []string{"asset params field index"}},
	"app_params_get":    {"X is field F from app A. Y is 1 if A exists, else 0", "params: Txn.ForeignApps offset or an _available_ app id. Return: did_exist flag (1 if the application existed and 0 otherwise), value.", []string{"app params field index"}},
	"acct_params_get":   {"X is field F from account A. Y is 1 if A owns positive algos, else 0", "", []string{"account params field index"}},
	"voter_params_get":  {"X is field F from online account A as of the balance round: 320 rounds before the current round. Y is 1 if A had positive algos online in the agreement round, else Y is 0 and X is a type specific zero-value", "", []string{"voter params field index"}},
	"online_stake":      {"the total online stake in the agreement round", "", nil},
	"assert":            {"immediately fail unless A is a non-zero number", "", nil},
	"callsub":           {"branch unconditionally to TARGET, saving the next instruction on the call stack", "The call stack is separate from the data stack. Only `callsub`, `retsub`, and `proto` manipulate it.", []string{"branch offset"}},
	"proto":             {"Prepare top call frame for a retsub that will assume A args and R return values.", "Fails unless the last instruction executed was a `callsub`.", []string{"number of arguments", "number of return values"}},
	"retsub":            {"pop the top instruction from the call stack and branch to it", "If the current frame was prepared by `proto A R`, `retsub` will remove the 'A' arguments from the stack, move the `R` return values down, and pop any stack locations above the relocated return values.", nil},

	"b+":  {"A plus B. A and B are interpreted as big-endian unsigned integers", "", nil},
	"b-":  {"A minus B. A and B are interpreted as big-endian unsigned integers. Fail on underflow.", "", nil},
	"b/":  {"A divided by B (truncated division). A and B are interpreted as big-endian unsigned integers. Fail if B is zero.", "", nil},
	"b*":  {"A times B. A and B are interpreted as big-endian unsigned integers.", "", nil},
	"b<":  {"1 if A is less than B, else 0. A and B are interpreted as big-endian unsigned integers", "", nil},
	"b>":  {"1 if A is greater than B, else 0. A and B are interpreted as big-endian unsigned integers", "", nil},
	"b<=": {"1 if A is less than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers", "", nil},
	"b>=": {"1 if A is greater than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers", "", nil},
	"b==": {"1 if A is equal to B, else 0. A and B are interpreted as big-endian unsigned integers", "", nil},
	"b!=": {"0 if A is equal to B, else 1. A and B are interpreted as big-endian unsigned integers", "", nil},
	"b%":  {"A modulo B. A and B are interpreted as big-endian unsigned integers. Fail if B is zero.", "", nil},
	"b|":  {"A bitwise-or B. A and B are zero-left extended to the greater of their lengths", "", nil},
	"b&":  {"A bitwise-and B. A and B are zero-left extended to the greater of their lengths", "", nil},
	"b^":  {"A bitwise-xor B. A and B are zero-left extended to the greater of their lengths", "", nil},
	"b~":  {"A with all bits inverted", "", nil},

	"bsqrt": {"The largest integer I such that I^2 <= A. A and I are interpreted as big-endian unsigned integers", "", nil},

	"log":         {"write A to log state of the current application", "`log` fails if called more than MaxLogCalls times in a program, or if the sum of logged bytes exceeds 1024 bytes.", nil},
	"itxn_begin":  {"begin preparation of a new inner transaction in a new transaction group", "`itxn_begin` initializes Sender to the application address; Fee to the minimum allowable, taking into account MinTxnFee and credit from overpaying in earlier transactions; FirstValid/LastValid to the values in the invoking transaction, and all other fields to zero or empty values.", nil},
	"itxn_next":   {"begin preparation of a new inner transaction in the same transaction group", "`itxn_next` initializes the transaction exactly as `itxn_begin` does", nil},
	"itxn_field":  {"set field F of the current inner transaction to A", "`itxn_field` fails if A is of the wrong type for F, including a byte array of the wrong size for use as an address when F is an address field. `itxn_field` also fails if A is an account, asset, or app that is not _available_, or an attempt is made extend an array field beyond the limit imposed by consensus parameters. (Addresses set into asset params of acfg transactions need not be _available_.)", []string{"transaction field index"}},
	"itxn_submit": {"execute the current inner transaction group. Fail if executing this group would exceed the inner transaction limit, or if any transaction in the group fails.", "`itxn_submit` resets the current transaction so that it can not be resubmitted. A new `itxn_begin` is required to prepare another inner transaction.", nil},

	"vrf_verify": {"Verify the proof B of message A against pubkey C. Returns vrf output and verification flag.", "`VrfAlgorand` is the VRF used in Algorand. It is ECVRF-ED25519-SHA512-Elligator2, specified in the IETF internet draft [draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/03/).", []string{" parameters index"}},
	"block":      {"field F of block A. Fail unless A falls between txn.LastValid-1002 and txn.FirstValid (exclusive)", "", []string{" block field index"}},

	"switch": {"branch to the Ath label. Continue at following instruction if index A exceeds the number of labels.", "", []string{"list of labels"}},
	"match":  {"given match cases from A[1] to A[N], branch to the Ith label where A[I] = B. Continue to the following instruction if no matches are found.", "`match` consumes N+1 values from the stack. Let the top stack value be B. The following N values represent an ordered list of match cases/constants (A), where the first value (A[0]) is the deepest in the stack. The immediate arguments are an ordered list of N labels (T). `match` will branch to target T[I], where A[I] = B. If there are no matches then execution continues on to the next instruction.", []string{"list of labels"}},

	"frame_dig":  {"Nth (signed) value from the frame pointer.", "", []string{"frame slot"}},
	"frame_bury": {"replace the Nth (signed) value from the frame pointer in the stack with A", "", []string{"frame slot"}},
	"popn":       {"remove N values from the top of the stack", "", []string{"stack depth"}},

	"box_create":  {"create a box named A, of length B. Fail if the name A is empty or B exceeds 32,768. Returns 0 if A already existed, else 1", "Newly created boxes are filled with 0 bytes. `box_create` will fail if the referenced box already exists with a different size. Otherwise, existing boxes are unchanged by `box_create`.", nil},
	"box_extract": {"read C bytes from box A, starting at offset B. Fail if A does not exist, or the byte range is outside A's size.", "", nil},
	"box_replace": {"write byte-array C into box A, starting at offset B. Fail if A does not exist, or the byte range is outside A's size.", "", nil},
	"box_splice":  {"set box A to contain its previous bytes up to index B, followed by D, followed by the original bytes of A that began at index B+C.", "Boxes are of constant length. If C < len(D), then len(D)-C bytes will be removed from the end. If C > len(D), zero bytes will be appended to the end to reach the box length.", nil},
	"box_del":     {"delete box named A if it exists. Return 1 if A existed, 0 otherwise", "", nil},
	"box_len":     {"X is the length of box A if A exists, else 0. Y is 1 if A exists, else 0.", "", nil},
	"box_get":     {"X is the contents of box A if A exists, else ''. Y is 1 if A exists, else 0.", "For boxes that exceed 4,096 bytes, consider `box_create`, `box_extract`, and `box_replace`", nil},
	"box_put":     {"replaces the contents of box A with byte-array B. Fails if A exists and len(B) != len(box A). Creates A if it does not exist", "For boxes that exceed 4,096 bytes, consider `box_create`, `box_extract`, and `box_replace`", nil},
	"box_resize":  {"change the size of box named A to be of length B, adding zero bytes to end or removing bytes from the end, as needed. Fail if the name A is empty, A is not an existing box, or B exceeds 32,768.", "", nil},
}

// OpDoc returns a description of the op
func OpDoc(opName string) string {
	return opDescByName[opName].Short
}

// OpImmediateDetails contains information about the an immediate argument for
// a given opcode, combining OpSpec details with the extra note in
// the opcodeImmediateNotes map
type OpImmediateDetails struct {
	Comment   string `json:",omitempty"`
	Encoding  string `json:",omitempty"`
	Name      string `json:",omitempty"`
	Reference string `json:",omitempty"`
}

// OpImmediateDetailsFromSpec provides a slice of OpImmediateDetails
// for a given OpSpec
func OpImmediateDetailsFromSpec(spec OpSpec) []OpImmediateDetails {
	argNotes := opDescByName[spec.Name].Immediates
	if len(argNotes) == 0 {
		return nil
	}

	details := make([]OpImmediateDetails, len(spec.Immediates))
	for idx, imm := range spec.Immediates {
		details[idx] = OpImmediateDetails{
			Name:     strings.ToTitle(imm.Name),
			Comment:  argNotes[idx],
			Encoding: imm.kind.String(),
		}

		if imm.Group != nil {
			details[idx].Reference = imm.Group.Name
		}
	}

	return details
}

// OpDocExtra returns extra documentation text about an op
func OpDocExtra(opName string) string {
	return opDescByName[opName].Extra
}

// OpGroups is groupings of ops for documentation purposes. The order
// here is the order args opcodes are presented, so place related
// opcodes consecutively, even if their opcode values are not.
var OpGroups = map[string][]string{
	"Arithmetic":              {"+", "-", "/", "*", "<", ">", "<=", ">=", "&&", "||", "shl", "shr", "sqrt", "bitlen", "exp", "==", "!=", "!", "itob", "btoi", "%", "|", "&", "^", "~", "mulw", "addw", "divw", "divmodw", "expw"},
	"Byte Array Manipulation": {"getbit", "setbit", "getbyte", "setbyte", "concat", "len", "substring", "substring3", "extract", "extract3", "extract_uint16", "extract_uint32", "extract_uint64", "replace2", "replace3", "base64_decode", "json_ref"},
	"Byte Array Arithmetic":   {"b+", "b-", "b/", "b*", "b<", "b>", "b<=", "b>=", "b==", "b!=", "b%", "bsqrt"},
	"Byte Array Logic":        {"b|", "b&", "b^", "b~"},
	"Cryptography":            {"sha256", "keccak256", "sha512_256", "sha3_256", "sha512", "sumhash512", "falcon_verify", "ed25519verify", "ed25519verify_bare", "ecdsa_verify", "ecdsa_pk_recover", "ecdsa_pk_decompress", "vrf_verify", "ec_add", "ec_scalar_mul", "ec_pairing_check", "ec_multi_scalar_mul", "ec_subgroup_check", "ec_map_to", "mimc"},
	"Loading Values":          {"intcblock", "intc", "intc_0", "intc_1", "intc_2", "intc_3", "pushint", "pushints", "bytecblock", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3", "pushbytes", "pushbytess", "bzero", "arg", "arg_0", "arg_1", "arg_2", "arg_3", "args", "txn", "gtxn", "txna", "txnas", "gtxna", "gtxnas", "gtxns", "gtxnsa", "gtxnsas", "global", "load", "loads", "store", "stores", "gload", "gloads", "gloadss", "gaid", "gaids"},
	"Flow Control":            {"err", "bnz", "bz", "b", "return", "pop", "popn", "dup", "dup2", "dupn", "dig", "bury", "cover", "uncover", "frame_dig", "frame_bury", "swap", "select", "assert", "callsub", "proto", "retsub", "switch", "match"},
	"State Access":            {"balance", "min_balance", "app_opted_in", "app_local_get", "app_local_get_ex", "app_global_get", "app_global_get_ex", "app_local_put", "app_global_put", "app_local_del", "app_global_del", "asset_holding_get", "asset_params_get", "app_params_get", "acct_params_get", "voter_params_get", "online_stake", "log", "block"},
	"Box Access":              {"box_create", "box_extract", "box_replace", "box_splice", "box_del", "box_len", "box_get", "box_put", "box_resize"},
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
