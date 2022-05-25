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
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// LogicVersion defines default assembler and max eval versions
const LogicVersion = 7

// rekeyingEnabledVersion is the version of TEAL where RekeyTo functionality
// was enabled. This is important to remember so that old TEAL accounts cannot
// be maliciously or accidentally rekeyed. Do not edit!
const rekeyingEnabledVersion = 2

// appsEnabledVersion is the version of TEAL where ApplicationCall
// functionality was enabled. We use this to disallow v0 and v1 TEAL programs
// from being used with applications. Do not edit!
const appsEnabledVersion = 2

// backBranchEnabledVersion is the first version of TEAL where branches could
// go back (and cost accounting was done during execution)
const backBranchEnabledVersion = 4

// directRefEnabledVersion is the version of TEAL where opcodes
// that reference accounts, asas, and apps may do so directly, not requiring
// using an index into arrays.
const directRefEnabledVersion = 4

// innerAppsEnabledVersion is the version that allowed inner app calls.
const innerAppsEnabledVersion = 6

// txnEffectsVersion is first version that allowed txn opcode to access
// "effects" (ApplyData info)
const txnEffectsVersion = 6

// createdResourcesVersion is the first version that allows access to assets and
// applications that were created in the same group, despite them not being in
// the Foreign arrays.
const createdResourcesVersion = 6

// appAddressAvailableVersion is the first version that allows access to the
// accounts of applications that were provided in the foreign apps transaction
// field.
const appAddressAvailableVersion = 7

// EXPERIMENTAL. These should be revisited whenever a new LogiSigVersion is
// moved from vFuture to a new consensus version. If they remain unready, bump
// their version.
const fidoVersion = 7    // base64, json, secp256r1
const pairingVersion = 7 // bn256 opcodes. will add bls12-381, and unify the available opcodes.// experimental-

type linearCost struct {
	baseCost  int
	chunkCost int
	chunkSize int
}

// divideCeilUnsafely provides `math.Ceil` semantics using integer division.  The technique avoids slower floating point operations as suggested in https://stackoverflow.com/a/2745086.
// The method does _not_ check for divide-by-zero.
func divideCeilUnsafely(numerator int, denominator int) int {
	return (numerator + denominator - 1) / denominator
}

func (lc *linearCost) compute(stack []stackValue) int {
	cost := lc.baseCost
	if lc.chunkCost != 0 && lc.chunkSize != 0 {
		// Uses divideCeilUnsafely rather than (len/size) to match how Ethereum discretizes hashing costs.
		cost += divideCeilUnsafely(lc.chunkCost*len(stack[len(stack)-1].Bytes), lc.chunkSize)
	}
	return cost
}

func (lc *linearCost) docCost() string {
	if *lc == (linearCost{}) {
		return ""
	}
	if lc.chunkCost == 0 {
		return strconv.Itoa(lc.baseCost)
	}
	if lc.chunkSize == 1 {
		return fmt.Sprintf("%d + %d per byte", lc.baseCost, lc.chunkCost)
	}
	return fmt.Sprintf("%d + %d per %d bytes", lc.baseCost, lc.chunkCost, lc.chunkSize)
}

// OpDetails records details such as non-standard costs, immediate arguments, or
// dynamic layout controlled by a check function. These objects are mostly built
// with constructor functions, so it's cleaner to have defaults set here, rather
// than in line after line of OpSpecs.
type OpDetails struct {
	asm    asmFunc    // assemble the op
	check  checkFunc  // static check bytecode (and determine size)
	refine refineFunc // refine arg/return types based on ProgramKnowledge at assembly time

	Modes runMode // all modes that opcode can run in. i.e (cx.mode & Modes) != 0 allows

	FullCost   linearCost  // if non-zero, the cost of the opcode, no immediates matter
	Size       int         // if non-zero, the known size of opcode. if 0, check() determines.
	Immediates []immediate // details of each immediate arg to opcode
}

func (d *OpDetails) docCost() string {
	cost := d.FullCost.docCost()
	if cost != "" {
		return cost
	}
	found := false
	for _, imm := range d.Immediates {
		if imm.fieldCosts != nil {
			if found {
				panic("two cost dependent fields")
			}
			found = true
			group := imm.Group
			for _, name := range group.Names {
				fs, ok := group.SpecByName(name)
				if !ok {
					continue
				}
				cost += fmt.Sprintf(" %s=%d", name, imm.fieldCosts[fs.Field()])
			}
		}
	}
	return cost
}

// Cost computes the cost of the opcode, given details about how it is used,
// both static (the program, which can be used to find the immediate values
// supplied), and dynamic (the stack, which can be used to find the run-time
// arguments supplied). Cost is used at run-time. docCost returns similar
// information in human-reable form.
func (d *OpDetails) Cost(program []byte, pc int, stack []stackValue) int {
	cost := d.FullCost.compute(stack)
	if cost != 0 {
		return cost
	}
	for i := range d.Immediates {
		if d.Immediates[i].fieldCosts != nil {
			cost += d.Immediates[i].fieldCosts[program[pc+1+i]]
		}
	}
	return cost
}

func opDefault() OpDetails {
	return OpDetails{asmDefault, nil, nil, modeAny, linearCost{baseCost: 1}, 1, nil}
}

func constants(asm asmFunc, checker checkFunc, name string, kind immKind) OpDetails {
	return OpDetails{asm, checker, nil, modeAny, linearCost{baseCost: 1}, 0, []immediate{imm(name, kind)}}
}

func opBranch() OpDetails {
	d := opDefault()
	d.asm = asmBranch
	d.check = checkBranch
	d.Size = 3
	d.Immediates = []immediate{imm("target", immLabel)}
	return d
}

func assembler(asm asmFunc) OpDetails {
	d := opDefault()
	d.asm = asm
	return d
}

func (d OpDetails) assembler(asm asmFunc) OpDetails {
	clone := d
	clone.asm = asm
	return clone
}

func costly(cost int) OpDetails {
	d := opDefault()
	d.FullCost.baseCost = cost
	return d
}

func (d OpDetails) costs(cost int) OpDetails {
	clone := d
	clone.FullCost = linearCost{baseCost: cost}
	return clone
}

func only(m runMode) OpDetails {
	d := opDefault()
	d.Modes = m
	return d
}

func (d OpDetails) only(m runMode) OpDetails {
	clone := d
	clone.Modes = m
	return clone
}

func (d OpDetails) costByLength(initial, perChunk, chunkSize int) OpDetails {
	clone := d
	clone.FullCost = costByLength(initial, perChunk, chunkSize).FullCost
	return clone
}

func immediates(names ...string) OpDetails {
	d := opDefault()
	d.Size = len(names) + 1
	d.Immediates = make([]immediate, len(names))
	for i, name := range names {
		d.Immediates[i] = imm(name, immByte)
	}
	return d
}

func stacky(typer refineFunc, imms ...string) OpDetails {
	d := immediates(imms...)
	d.refine = typer
	return d
}

// field is used to create an opDetails for an opcode with a single field
func field(immediate string, group *FieldGroup) OpDetails {
	opd := immediates(immediate)
	opd.Immediates[0].Group = group
	return opd
}

// field is used to annotate an existing immediate with group info
func (d OpDetails) field(name string, group *FieldGroup) OpDetails {
	for i := range d.Immediates {
		if d.Immediates[i].Name == name {
			d.Immediates[i].Group = group
			return d
		}
	}
	panic(name)
}

func costByField(immediate string, group *FieldGroup, costs []int) OpDetails {
	opd := immediates(immediate).costs(0)
	opd.Immediates[0].Group = group
	fieldCosts := make([]int, 256)
	copy(fieldCosts, costs)
	opd.Immediates[0].fieldCosts = fieldCosts
	return opd
}

func costByLength(initial int, perChunk int, chunkSize int) OpDetails {
	if initial < 1 || perChunk <= 0 || chunkSize < 1 || chunkSize > maxStringSize {
		panic("bad cost configuration")
	}
	d := opDefault()
	d.FullCost = linearCost{initial, perChunk, chunkSize}
	return d
}

// immType describes the immediate arguments to an opcode
type immKind byte

const (
	immByte immKind = iota
	immLabel
	immInt
	immBytes
	immInts
	immBytess // "ss" not a typo.  Multiple "bytes"
)

type immediate struct {
	Name  string
	kind  immKind
	Group *FieldGroup

	// If non-nil, always 256 long, so cost can be checked before eval
	fieldCosts []int
}

func imm(name string, kind immKind) immediate {
	return immediate{name, kind, nil, nil}
}

type typedList struct {
	Types   StackTypes
	Effects string
}

// Proto describes the "stack behavior" of an opcode, what it pops as arguments
// and pushes onto the stack as return values.
type Proto struct {
	Arg    typedList // what gets popped from the stack
	Return typedList // what gets pushed to the stack
}

func proto(signature string, effects ...string) Proto {
	parts := strings.Split(signature, ":")
	if len(parts) != 2 {
		panic(signature)
	}
	var argEffect, retEffect string
	switch len(effects) {
	case 0:
		// will be generated
	case 1:
		retEffect = effects[0]
	case 2:
		argEffect = effects[0]
		retEffect = effects[1]
	default:
		panic(effects)
	}
	return Proto{
		Arg:    typedList{parseStackTypes(parts[0]), argEffect},
		Return: typedList{parseStackTypes(parts[1]), retEffect},
	}
}

// OpSpec defines an opcode
type OpSpec struct {
	Opcode byte
	Name   string
	op     evalFunc // evaluate the op
	Proto
	Version   uint64 // TEAL version opcode introduced
	OpDetails        // Special cost or bytecode layout considerations
}

// AlwaysExits is true iff the opcode always ends the program.
func (spec *OpSpec) AlwaysExits() bool {
	return len(spec.Return.Types) == 1 && spec.Return.Types[0] == StackNone
}

func (spec *OpSpec) deadens() bool {
	switch spec.Name {
	case "b", "callsub", "retsub", "err", "return":
		return true
	default:
		return false
	}
}

// OpSpecs is the table of operations that can be assembled and evaluated.
//
// Any changes should be reflected in README_in.md which serves as the language spec.
//
// Note: assembly can specialize an Any return type if known at
// assembly-time, with ops.returns()
var OpSpecs = []OpSpec{
	{0x00, "err", opErr, proto(":x"), 1, opDefault()},
	{0x01, "sha256", opSHA256, proto("b:b"), 1, costly(7)},
	{0x02, "keccak256", opKeccak256, proto("b:b"), 1, costly(26)},
	{0x03, "sha512_256", opSHA512_256, proto("b:b"), 1, costly(9)},

	// Cost of these opcodes increases in TEAL version 2 based on measured
	// performance. Should be able to run max hashes during stateful TEAL
	// and achieve reasonable TPS. Same opcode for different TEAL versions
	// is OK.
	{0x01, "sha256", opSHA256, proto("b:b"), 2, costly(35)},
	{0x02, "keccak256", opKeccak256, proto("b:b"), 2, costly(130)},
	{0x03, "sha512_256", opSHA512_256, proto("b:b"), 2, costly(45)},

	/*
		Tabling these changes until we offer unlimited global storage as there
		is currently a useful pattern that requires hashes on long slices to
		creating logicsigs in apps.

		{0x01, "sha256", opSHA256, proto("b:b"), unlimitedStorage, costByLength(12, 6, 8)},
		{0x02, "keccak256", opKeccak256, proto("b:b"), unlimitedStorage, costByLength(58, 4, 8)},
		{0x03, "sha512_256", opSHA512_256, proto("b:b"), 7, unlimitedStorage, costByLength(17, 5, 8)},
	*/

	{0x04, "ed25519verify", opEd25519Verify, proto("bbb:i"), 1, costly(1900).only(modeSig)},
	{0x04, "ed25519verify", opEd25519Verify, proto("bbb:i"), 5, costly(1900)},

	{0x05, "ecdsa_verify", opEcdsaVerify, proto("bbbbb:i"), 5, costByField("v", &EcdsaCurves, ecdsaVerifyCosts)},
	{0x06, "ecdsa_pk_decompress", opEcdsaPkDecompress, proto("b:bb"), 5, costByField("v", &EcdsaCurves, ecdsaDecompressCosts)},
	{0x07, "ecdsa_pk_recover", opEcdsaPkRecover, proto("bibb:bb"), 5, field("v", &EcdsaCurves).costs(2000)},

	{0x08, "+", opPlus, proto("ii:i"), 1, opDefault()},
	{0x09, "-", opMinus, proto("ii:i"), 1, opDefault()},
	{0x0a, "/", opDiv, proto("ii:i"), 1, opDefault()},
	{0x0b, "*", opMul, proto("ii:i"), 1, opDefault()},
	{0x0c, "<", opLt, proto("ii:i"), 1, opDefault()},
	{0x0d, ">", opGt, proto("ii:i"), 1, opDefault()},
	{0x0e, "<=", opLe, proto("ii:i"), 1, opDefault()},
	{0x0f, ">=", opGe, proto("ii:i"), 1, opDefault()},
	{0x10, "&&", opAnd, proto("ii:i"), 1, opDefault()},
	{0x11, "||", opOr, proto("ii:i"), 1, opDefault()},
	{0x12, "==", opEq, proto("aa:i"), 1, stacky(typeEquals)},
	{0x13, "!=", opNeq, proto("aa:i"), 1, stacky(typeEquals)},
	{0x14, "!", opNot, proto("i:i"), 1, opDefault()},
	{0x15, "len", opLen, proto("b:i"), 1, opDefault()},
	{0x16, "itob", opItob, proto("i:b"), 1, opDefault()},
	{0x17, "btoi", opBtoi, proto("b:i"), 1, opDefault()},
	{0x18, "%", opModulo, proto("ii:i"), 1, opDefault()},
	{0x19, "|", opBitOr, proto("ii:i"), 1, opDefault()},
	{0x1a, "&", opBitAnd, proto("ii:i"), 1, opDefault()},
	{0x1b, "^", opBitXor, proto("ii:i"), 1, opDefault()},
	{0x1c, "~", opBitNot, proto("i:i"), 1, opDefault()},
	{0x1d, "mulw", opMulw, proto("ii:ii"), 1, opDefault()},
	{0x1e, "addw", opAddw, proto("ii:ii"), 2, opDefault()},
	{0x1f, "divmodw", opDivModw, proto("iiii:iiii"), 4, costly(20)},

	{0x20, "intcblock", opIntConstBlock, proto(":"), 1, constants(asmIntCBlock, checkIntConstBlock, "uint ...", immInts)},
	{0x21, "intc", opIntConstLoad, proto(":i"), 1, immediates("i").assembler(asmIntC)},
	{0x22, "intc_0", opIntConst0, proto(":i"), 1, opDefault()},
	{0x23, "intc_1", opIntConst1, proto(":i"), 1, opDefault()},
	{0x24, "intc_2", opIntConst2, proto(":i"), 1, opDefault()},
	{0x25, "intc_3", opIntConst3, proto(":i"), 1, opDefault()},
	{0x26, "bytecblock", opByteConstBlock, proto(":"), 1, constants(asmByteCBlock, checkByteConstBlock, "bytes ...", immBytess)},
	{0x27, "bytec", opByteConstLoad, proto(":b"), 1, immediates("i").assembler(asmByteC)},
	{0x28, "bytec_0", opByteConst0, proto(":b"), 1, opDefault()},
	{0x29, "bytec_1", opByteConst1, proto(":b"), 1, opDefault()},
	{0x2a, "bytec_2", opByteConst2, proto(":b"), 1, opDefault()},
	{0x2b, "bytec_3", opByteConst3, proto(":b"), 1, opDefault()},
	{0x2c, "arg", opArg, proto(":b"), 1, immediates("n").only(modeSig).assembler(asmArg)},
	{0x2d, "arg_0", opArg0, proto(":b"), 1, only(modeSig)},
	{0x2e, "arg_1", opArg1, proto(":b"), 1, only(modeSig)},
	{0x2f, "arg_2", opArg2, proto(":b"), 1, only(modeSig)},
	{0x30, "arg_3", opArg3, proto(":b"), 1, only(modeSig)},
	{0x31, "txn", opTxn, proto(":a"), 1, field("f", &TxnScalarFields)},
	// It is ok to have the same opcode for different TEAL versions.
	// This 'txn' asm command supports additional argument in version 2 and
	// generates 'txna' opcode in that particular case
	{0x31, "txn", opTxn, proto(":a"), 2, field("f", &TxnFields).assembler(asmTxn2)},
	{0x32, "global", opGlobal, proto(":a"), 1, field("f", &GlobalFields)},
	{0x33, "gtxn", opGtxn, proto(":a"), 1, immediates("t", "f").field("f", &TxnScalarFields)},
	{0x33, "gtxn", opGtxn, proto(":a"), 2, immediates("t", "f").field("f", &TxnFields).assembler(asmGtxn2)},
	{0x34, "load", opLoad, proto(":a"), 1, immediates("i")},
	{0x35, "store", opStore, proto("a:"), 1, immediates("i")},
	{0x36, "txna", opTxna, proto(":a"), 2, immediates("f", "i").field("f", &TxnArrayFields)},
	{0x37, "gtxna", opGtxna, proto(":a"), 2, immediates("t", "f", "i").field("f", &TxnArrayFields)},
	// Like gtxn, but gets txn index from stack, rather than immediate arg
	{0x38, "gtxns", opGtxns, proto("i:a"), 3, immediates("f").field("f", &TxnFields).assembler(asmGtxns)},
	{0x39, "gtxnsa", opGtxnsa, proto("i:a"), 3, immediates("f", "i").field("f", &TxnArrayFields)},
	// Group scratch space access
	{0x3a, "gload", opGload, proto(":a"), 4, immediates("t", "i").only(modeApp)},
	{0x3b, "gloads", opGloads, proto("i:a"), 4, immediates("i").only(modeApp)},
	// Access creatable IDs (consider deprecating, as txn CreatedAssetID, CreatedApplicationID should be enough
	{0x3c, "gaid", opGaid, proto(":i"), 4, immediates("t").only(modeApp)},
	{0x3d, "gaids", opGaids, proto("i:i"), 4, only(modeApp)},

	// Like load/store, but scratch slot taken from TOS instead of immediate
	{0x3e, "loads", opLoads, proto("i:a"), 5, opDefault()},
	{0x3f, "stores", opStores, proto("ia:"), 5, opDefault()},

	{0x40, "bnz", opBnz, proto("i:"), 1, opBranch()},
	{0x41, "bz", opBz, proto("i:"), 2, opBranch()},
	{0x42, "b", opB, proto(":"), 2, opBranch()},
	{0x43, "return", opReturn, proto("i:x"), 2, opDefault()},
	{0x44, "assert", opAssert, proto("i:"), 3, opDefault()},
	{0x48, "pop", opPop, proto("a:"), 1, opDefault()},
	{0x49, "dup", opDup, proto("a:aa", "A, A"), 1, stacky(typeDup)},
	{0x4a, "dup2", opDup2, proto("aa:aaaa", "A, B, A, B"), 2, stacky(typeDupTwo)},
	// There must be at least one thing on the stack for dig, but
	// it would be nice if we did better checking than that.
	{0x4b, "dig", opDig, proto("a:aa", "A, [N items]", "A, [N items], A"), 3, stacky(typeDig, "n")},
	{0x4c, "swap", opSwap, proto("aa:aa", "B, A"), 3, stacky(typeSwap)},
	{0x4d, "select", opSelect, proto("aai:a", "A or B"), 3, stacky(typeSelect)},
	{0x4e, "cover", opCover, proto("a:a", "[N items], A", "A, [N items]"), 5, stacky(typeCover, "n")},
	{0x4f, "uncover", opUncover, proto("a:a", "A, [N items]", "[N items], A"), 5, stacky(typeUncover, "n")},

	// byteslice processing / StringOps
	{0x50, "concat", opConcat, proto("bb:b"), 2, opDefault()},
	{0x51, "substring", opSubstring, proto("b:b"), 2, immediates("s", "e").assembler(asmSubstring)},
	{0x52, "substring3", opSubstring3, proto("bii:b"), 2, opDefault()},
	{0x53, "getbit", opGetBit, proto("ai:i"), 3, opDefault()},
	{0x54, "setbit", opSetBit, proto("aii:a"), 3, stacky(typeSetBit)},
	{0x55, "getbyte", opGetByte, proto("bi:i"), 3, opDefault()},
	{0x56, "setbyte", opSetByte, proto("bii:b"), 3, opDefault()},
	{0x57, "extract", opExtract, proto("b:b"), 5, immediates("s", "l")},
	{0x58, "extract3", opExtract3, proto("bii:b"), 5, opDefault()},
	{0x59, "extract_uint16", opExtract16Bits, proto("bi:i"), 5, opDefault()},
	{0x5a, "extract_uint32", opExtract32Bits, proto("bi:i"), 5, opDefault()},
	{0x5b, "extract_uint64", opExtract64Bits, proto("bi:i"), 5, opDefault()},
	{0x5c, "base64_decode", opBase64Decode, proto("b:b"), fidoVersion, field("e", &Base64Encodings).costByLength(1, 1, 16)},
	{0x5d, "json_ref", opJSONRef, proto("bb:a"), fidoVersion, field("r", &JSONRefTypes)},

	{0x60, "balance", opBalance, proto("i:i"), 2, only(modeApp)},
	{0x60, "balance", opBalance, proto("a:i"), directRefEnabledVersion, only(modeApp)},
	{0x61, "app_opted_in", opAppOptedIn, proto("ii:i"), 2, only(modeApp)},
	{0x61, "app_opted_in", opAppOptedIn, proto("ai:i"), directRefEnabledVersion, only(modeApp)},
	{0x62, "app_local_get", opAppLocalGet, proto("ib:a"), 2, only(modeApp)},
	{0x62, "app_local_get", opAppLocalGet, proto("ab:a"), directRefEnabledVersion, only(modeApp)},
	{0x63, "app_local_get_ex", opAppLocalGetEx, proto("iib:ai"), 2, only(modeApp)},
	{0x63, "app_local_get_ex", opAppLocalGetEx, proto("aib:ai"), directRefEnabledVersion, only(modeApp)},
	{0x64, "app_global_get", opAppGlobalGet, proto("b:a"), 2, only(modeApp)},
	{0x65, "app_global_get_ex", opAppGlobalGetEx, proto("ib:ai"), 2, only(modeApp)},
	{0x66, "app_local_put", opAppLocalPut, proto("iba:"), 2, only(modeApp)},
	{0x66, "app_local_put", opAppLocalPut, proto("aba:"), directRefEnabledVersion, only(modeApp)},
	{0x67, "app_global_put", opAppGlobalPut, proto("ba:"), 2, only(modeApp)},
	{0x68, "app_local_del", opAppLocalDel, proto("ib:"), 2, only(modeApp)},
	{0x68, "app_local_del", opAppLocalDel, proto("ab:"), directRefEnabledVersion, only(modeApp)},
	{0x69, "app_global_del", opAppGlobalDel, proto("b:"), 2, only(modeApp)},

	{0x70, "asset_holding_get", opAssetHoldingGet, proto("ii:ai"), 2, field("f", &AssetHoldingFields).only(modeApp)},
	{0x70, "asset_holding_get", opAssetHoldingGet, proto("ai:ai"), directRefEnabledVersion, field("f", &AssetHoldingFields).only(modeApp)},
	{0x71, "asset_params_get", opAssetParamsGet, proto("i:ai"), 2, field("f", &AssetParamsFields).only(modeApp)},
	{0x72, "app_params_get", opAppParamsGet, proto("i:ai"), 5, field("f", &AppParamsFields).only(modeApp)},
	{0x73, "acct_params_get", opAcctParamsGet, proto("a:ai"), 6, field("f", &AcctParamsFields).only(modeApp)},

	{0x78, "min_balance", opMinBalance, proto("i:i"), 3, only(modeApp)},
	{0x78, "min_balance", opMinBalance, proto("a:i"), directRefEnabledVersion, only(modeApp)},

	// Immediate bytes and ints. Smaller code size for single use of constant.
	{0x80, "pushbytes", opPushBytes, proto(":b"), 3, constants(asmPushBytes, opPushBytes, "bytes", immBytes)},
	{0x81, "pushint", opPushInt, proto(":i"), 3, constants(asmPushInt, opPushInt, "uint", immInt)},

	{0x84, "ed25519verify_bare", opEd25519VerifyBare, proto("bbb:i"), 7, costly(1900)},

	// "Function oriented"
	{0x88, "callsub", opCallSub, proto(":"), 4, opBranch()},
	{0x89, "retsub", opRetSub, proto(":"), 4, opDefault()},
	// Leave a little room for indirect function calls, or similar

	// More math
	{0x90, "shl", opShiftLeft, proto("ii:i"), 4, opDefault()},
	{0x91, "shr", opShiftRight, proto("ii:i"), 4, opDefault()},
	{0x92, "sqrt", opSqrt, proto("i:i"), 4, costly(4)},
	{0x93, "bitlen", opBitLen, proto("a:i"), 4, opDefault()},
	{0x94, "exp", opExp, proto("ii:i"), 4, opDefault()},
	{0x95, "expw", opExpw, proto("ii:ii"), 4, costly(10)},
	{0x96, "bsqrt", opBytesSqrt, proto("b:b"), 6, costly(40)},
	{0x97, "divw", opDivw, proto("iii:i"), 6, opDefault()},
	{0x98, "sha3_256", opSHA3_256, proto("b:b"), 7, costly(130)},
	/* Will end up following keccak256 -
	{0x98, "sha3_256", opSHA3_256, proto("b:b"), unlimitedStorage, costByLength(58, 4, 8)},},
	*/

	{0x99, "bn256_add", opBn256Add, proto("bb:b"), pairingVersion, costly(70)},
	{0x9a, "bn256_scalar_mul", opBn256ScalarMul, proto("bb:b"), pairingVersion, costly(970)},
	{0x9b, "bn256_pairing", opBn256Pairing, proto("bb:i"), pairingVersion, costly(8700)},
	// leave room here for eip-2537 style opcodes

	// Byteslice math.
	{0xa0, "b+", opBytesPlus, proto("bb:b"), 4, costly(10)},
	{0xa1, "b-", opBytesMinus, proto("bb:b"), 4, costly(10)},
	{0xa2, "b/", opBytesDiv, proto("bb:b"), 4, costly(20)},
	{0xa3, "b*", opBytesMul, proto("bb:b"), 4, costly(20)},
	{0xa4, "b<", opBytesLt, proto("bb:i"), 4, opDefault()},
	{0xa5, "b>", opBytesGt, proto("bb:i"), 4, opDefault()},
	{0xa6, "b<=", opBytesLe, proto("bb:i"), 4, opDefault()},
	{0xa7, "b>=", opBytesGe, proto("bb:i"), 4, opDefault()},
	{0xa8, "b==", opBytesEq, proto("bb:i"), 4, opDefault()},
	{0xa9, "b!=", opBytesNeq, proto("bb:i"), 4, opDefault()},
	{0xaa, "b%", opBytesModulo, proto("bb:b"), 4, costly(20)},
	{0xab, "b|", opBytesBitOr, proto("bb:b"), 4, costly(6)},
	{0xac, "b&", opBytesBitAnd, proto("bb:b"), 4, costly(6)},
	{0xad, "b^", opBytesBitXor, proto("bb:b"), 4, costly(6)},
	{0xae, "b~", opBytesBitNot, proto("b:b"), 4, costly(4)},
	{0xaf, "bzero", opBytesZero, proto("i:b"), 4, opDefault()},

	// AVM "effects"
	{0xb0, "log", opLog, proto("b:"), 5, only(modeApp)},
	{0xb1, "itxn_begin", opTxBegin, proto(":"), 5, only(modeApp)},
	{0xb2, "itxn_field", opItxnField, proto("a:"), 5, stacky(typeTxField, "f").field("f", &TxnFields).only(modeApp).assembler(asmItxnField)},
	{0xb3, "itxn_submit", opItxnSubmit, proto(":"), 5, only(modeApp)},
	{0xb4, "itxn", opItxn, proto(":a"), 5, field("f", &TxnScalarFields).only(modeApp).assembler(asmItxn)},
	{0xb5, "itxna", opItxna, proto(":a"), 5, immediates("f", "i").field("f", &TxnArrayFields).only(modeApp)},
	{0xb6, "itxn_next", opItxnNext, proto(":"), 6, only(modeApp)},
	{0xb7, "gitxn", opGitxn, proto(":a"), 6, immediates("t", "f").field("f", &TxnFields).only(modeApp).assembler(asmGitxn)},
	{0xb8, "gitxna", opGitxna, proto(":a"), 6, immediates("t", "f", "i").field("f", &TxnArrayFields).only(modeApp)},

	// Dynamic indexing
	{0xc0, "txnas", opTxnas, proto("i:a"), 5, field("f", &TxnArrayFields)},
	{0xc1, "gtxnas", opGtxnas, proto("i:a"), 5, immediates("t", "f").field("f", &TxnArrayFields)},
	{0xc2, "gtxnsas", opGtxnsas, proto("ii:a"), 5, field("f", &TxnArrayFields)},
	{0xc3, "args", opArgs, proto("i:b"), 5, only(modeSig)},
	{0xc4, "gloadss", opGloadss, proto("ii:a"), 6, only(modeApp)},
	{0xc5, "itxnas", opItxnas, proto("i:a"), 6, field("f", &TxnArrayFields).only(modeApp)},
	{0xc6, "gitxnas", opGitxnas, proto("i:a"), 6, immediates("t", "f").field("f", &TxnArrayFields).only(modeApp)},
}

type sortByOpcode []OpSpec

func (a sortByOpcode) Len() int           { return len(a) }
func (a sortByOpcode) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortByOpcode) Less(i, j int) bool { return a[i].Opcode < a[j].Opcode }

// OpcodesByVersion returns list of opcodes available in a specific version of TEAL
// by copying v1 opcodes to v2, and then on to v3 to create a full list
func OpcodesByVersion(version uint64) []OpSpec {
	// for updated opcodes use the lowest version opcode was introduced in
	maxOpcode := 0
	for i := 0; i < len(OpSpecs); i++ {
		if int(OpSpecs[i].Opcode) > maxOpcode {
			maxOpcode = int(OpSpecs[i].Opcode)
		}
	}
	updated := make([]int, maxOpcode+1)
	for idx := range OpSpecs {
		op := OpSpecs[idx].Opcode
		cv := updated[op]
		if cv == 0 {
			cv = int(OpSpecs[idx].Version)
		} else {
			if int(OpSpecs[idx].Version) < cv {
				cv = int(OpSpecs[idx].Version)
			}
		}
		updated[op] = cv
	}

	subv := make(map[byte]OpSpec)
	for idx := range OpSpecs {
		if OpSpecs[idx].Version <= version {
			op := OpSpecs[idx].Opcode
			subv[op] = OpSpecs[idx]
			// if the opcode was updated then assume backward compatibility
			// and set version to minimum available
			if updated[op] < int(OpSpecs[idx].Version) {
				copy := OpSpecs[idx]
				copy.Version = uint64(updated[op])
				subv[op] = copy
			}
		}
	}
	result := make([]OpSpec, 0, len(subv))
	for _, v := range subv {
		result = append(result, v)
	}
	sort.Sort(sortByOpcode(result))
	return result
}

// direct opcode bytes
var opsByOpcode [LogicVersion + 1][256]OpSpec

// OpsByName map for each version, mapping opcode name to OpSpec
var OpsByName [LogicVersion + 1]map[string]OpSpec

// Migration from TEAL v1 to TEAL v2.
// TEAL v1 allowed execution of program with version 0.
// With TEAL v2 opcode versions are introduced and they are bound to every opcode.
// There is no opcodes with version 0 so that TEAL v2 evaluator rejects any program with version 0.
// To preserve backward compatibility version 0 array is populated with TEAL v1 opcodes
// with the version overwritten to 0.
func init() {
	// First, initialize baseline v1 opcodes.
	// Zero (empty) version is an alias for TEAL v1 opcodes and needed for compatibility with v1 code.
	OpsByName[0] = make(map[string]OpSpec, 256)
	OpsByName[1] = make(map[string]OpSpec, 256)
	for _, oi := range OpSpecs {
		if oi.Version == 1 {
			cp := oi
			cp.Version = 0
			opsByOpcode[0][oi.Opcode] = cp
			OpsByName[0][oi.Name] = cp

			opsByOpcode[1][oi.Opcode] = oi
			OpsByName[1][oi.Name] = oi
		}
	}
	// Start from v2 TEAL and higher,
	// copy lower version opcodes and overwrite matching version
	for v := uint64(2); v <= evalMaxVersion; v++ {
		OpsByName[v] = make(map[string]OpSpec, 256)

		// Copy opcodes from lower version
		for opName, oi := range OpsByName[v-1] {
			OpsByName[v][opName] = oi
		}
		for op, oi := range opsByOpcode[v-1] {
			opsByOpcode[v][op] = oi
		}

		// Update tables with opcodes from the current version
		for _, oi := range OpSpecs {
			if oi.Version == v {
				opsByOpcode[v][oi.Opcode] = oi
				OpsByName[v][oi.Name] = oi
			}
		}
	}
}
