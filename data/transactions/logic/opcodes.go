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

	"github.com/algorand/go-algorand/data/transactions"
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

// innerAppsEnabledVersion is the version that allowed inner app calls. No old
// apps should be called as inner apps. Set to ExtraProgramChecks version
// because those checks protect from tricky ClearState Programs.
const innerAppsEnabledVersion = transactions.ExtraProgramChecksVersion

// txnEffectsVersion is first version that allowed txn opcode to access
// "effects" (ApplyData info)
const txnEffectsVersion = 6

// createdResourcesVersion is the first version that allows access to assets and
// applications that were created in the same group, despite them not being in
// the Foreign arrays.
const createdResourcesVersion = 6

// experimental-
const fidoVersion = 7 // base64, json, secp256r1

type linearCost struct {
	baseCost  int
	chunkCost int
	chunkSize int
}

func (lc *linearCost) compute(stack []stackValue) int {
	cost := lc.baseCost
	if lc.chunkCost != 0 && lc.chunkSize != 0 {
		cost += lc.chunkCost * (len(stack[len(stack)-1].Bytes) + lc.chunkSize - 1) / lc.chunkSize
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

// opDetails records details such as non-standard costs, immediate
// arguments, or dynamic layout controlled by a check function.
type opDetails struct {
	FullCost   linearCost // if non-zero, the cost of the opcode, no fields matter
	Size       int
	checkFunc  opCheckFunc
	Immediates []immediate
	typeFunc   opTypeFunc
}

func (d *opDetails) docCost() string {
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
func (d *opDetails) Cost(program []byte, pc int, stack []stackValue) int {
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

var opDefault = opDetails{linearCost{baseCost: 1}, 1, nil, nil, nil}
var opBranch = opDetails{linearCost{baseCost: 1}, 3, checkBranch,
	[]immediate{imm("target", immLabel)}, nil}

func costly(cost int) opDetails {
	return opDetails{linearCost{baseCost: cost}, 1, nil, nil, nil}
}

func (d opDetails) costs(cost int) opDetails {
	clone := d
	clone.FullCost = linearCost{baseCost: cost}
	return clone
}

func (d opDetails) costByLength(initial, perChunk, chunkSize int) opDetails {
	clone := d
	clone.FullCost = costByLength(initial, perChunk, chunkSize).FullCost
	return clone
}

func immediates(names ...string) opDetails {
	immediates := make([]immediate, len(names))
	for i, name := range names {
		immediates[i] = imm(name, immByte)
	}
	return opDetails{linearCost{baseCost: 1}, 1 + len(immediates), nil, immediates, nil}
}

func stacky(typer opTypeFunc, imms ...string) opDetails {
	d := immediates(imms...)
	d.typeFunc = typer
	return d
}

func sizeVaries(checker opCheckFunc, name string, kind immKind) opDetails {
	return opDetails{linearCost{baseCost: 1}, 0, checker, []immediate{imm(name, kind)}, nil}
}

// field is used to create an opDetails for an opcode with a single field
func field(immediate string, group *FieldGroup) opDetails {
	opd := immediates(immediate)
	opd.Immediates[0].Group = group
	return opd
}

// field is used to annotate an existing immediate with group info
func (d opDetails) field(name string, group *FieldGroup) opDetails {
	for i := range d.Immediates {
		if d.Immediates[i].Name == name {
			d.Immediates[i].Group = group
			return d
		}
	}
	panic(name)
}

func costByField(immediate string, group *FieldGroup, costs []int) opDetails {
	opd := immediates(immediate).costs(0)
	opd.Immediates[0].Group = group
	fieldCosts := make([]int, 256)
	copy(fieldCosts, costs)
	opd.Immediates[0].fieldCosts = fieldCosts
	return opd
}

func costByLength(initial int, perChunk int, chunkSize int) opDetails {
	if initial < 1 || perChunk <= 0 || chunkSize < 1 || chunkSize > maxStringSize {
		panic("bad cost configuration")
	}
	return opDetails{linearCost{initial, perChunk, chunkSize}, 1, nil, nil, nil}
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

// OpSpec defines an opcode
type OpSpec struct {
	Opcode  byte
	Name    string
	op      evalFunc   // evaluate the op
	asm     asmFunc    // assemble the op
	dis     disFunc    // disassemble the op
	Args    StackTypes // what gets popped from the stack
	Returns StackTypes // what gets pushed to the stack
	Version uint64     // TEAL version opcode introduced
	Modes   runMode    // if non-zero, then (mode & Modes) != 0 to allow
	Details opDetails  // Special cost or bytecode layout considerations
}

var oneBytes = StackTypes{StackBytes}
var twoBytes = StackTypes{StackBytes, StackBytes}
var threeBytes = StackTypes{StackBytes, StackBytes, StackBytes}
var byteInt = StackTypes{StackBytes, StackUint64}
var byteIntInt = StackTypes{StackBytes, StackUint64, StackUint64}
var oneInt = StackTypes{StackUint64}
var twoInts = StackTypes{StackUint64, StackUint64}
var oneAny = StackTypes{StackAny}
var twoAny = StackTypes{StackAny, StackAny}
var anyInt = StackTypes{StackAny, StackUint64}
var anyIntInt = StackTypes{StackAny, StackUint64, StackUint64}

// OpSpecs is the table of operations that can be assembled and evaluated.
//
// Any changes should be reflected in README_in.md which serves as the language spec.
//
// Note: assembly can specialize an Any return type if known at
// assembly-time, with ops.returns()
var OpSpecs = []OpSpec{
	{0x00, "err", opErr, asmDefault, disDefault, nil, nil, 1, modeAny, opDefault},
	{0x01, "sha256", opSHA256, asmDefault, disDefault, oneBytes, oneBytes, 1, modeAny, costly(7)},
	{0x02, "keccak256", opKeccak256, asmDefault, disDefault, oneBytes, oneBytes, 1, modeAny, costly(26)},
	{0x03, "sha512_256", opSHA512_256, asmDefault, disDefault, oneBytes, oneBytes, 1, modeAny, costly(9)},

	// Cost of these opcodes increases in TEAL version 2 based on measured
	// performance. Should be able to run max hashes during stateful TEAL
	// and achieve reasonable TPS. Same opcode for different TEAL versions
	// is OK.
	{0x01, "sha256", opSHA256, asmDefault, disDefault, oneBytes, oneBytes, 2, modeAny, costly(35)},
	{0x02, "keccak256", opKeccak256, asmDefault, disDefault, oneBytes, oneBytes, 2, modeAny, costly(130)},
	{0x03, "sha512_256", opSHA512_256, asmDefault, disDefault, oneBytes, oneBytes, 2, modeAny, costly(45)},

	/*
		Tabling these changes until we offer unlimited global storage as there
		is currently a useful pattern that requires hashes on long slices to
		creating logicsigs in apps.

		{0x01, "sha256", opSHA256, asmDefault, disDefault, oneBytes, oneBytes, unlimitedStorage, modeAny, costByLength(12, 6, 8)},
		{0x02, "keccak256", opKeccak256, asmDefault, disDefault, oneBytes, oneBytes, unlimitedStorage, modeAny, costByLength(58, 4, 8)},
		{0x03, "sha512_256", opSHA512_256, asmDefault, disDefault, oneBytes, oneBytes, 7, unlimitedStorage, costByLength(17, 5, 8)},
	*/

	{0x04, "ed25519verify", opEd25519Verify, asmDefault, disDefault, threeBytes, oneInt, 1, runModeSignature, costly(1900)},
	{0x04, "ed25519verify", opEd25519Verify, asmDefault, disDefault, threeBytes, oneInt, 5, modeAny, costly(1900)},

	{0x05, "ecdsa_verify", opEcdsaVerify, asmDefault, disDefault, threeBytes.plus(twoBytes), oneInt, 5, modeAny, costByField("v", &EcdsaCurves, ecdsaVerifyCosts)},
	{0x06, "ecdsa_pk_decompress", opEcdsaPkDecompress, asmDefault, disDefault, oneBytes, twoBytes, 5, modeAny, costByField("v", &EcdsaCurves, ecdsaDecompressCosts)},
	{0x07, "ecdsa_pk_recover", opEcdsaPkRecover, asmDefault, disDefault, oneBytes.plus(oneInt).plus(twoBytes), twoBytes, 5, modeAny, field("v", &EcdsaCurves).costs(2000)},

	{0x08, "+", opPlus, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x09, "-", opMinus, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x0a, "/", opDiv, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x0b, "*", opMul, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x0c, "<", opLt, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x0d, ">", opGt, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x0e, "<=", opLe, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x0f, ">=", opGe, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x10, "&&", opAnd, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x11, "||", opOr, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x12, "==", opEq, asmDefault, disDefault, twoAny, oneInt, 1, modeAny, stacky(typeEquals)},
	{0x13, "!=", opNeq, asmDefault, disDefault, twoAny, oneInt, 1, modeAny, stacky(typeEquals)},
	{0x14, "!", opNot, asmDefault, disDefault, oneInt, oneInt, 1, modeAny, opDefault},
	{0x15, "len", opLen, asmDefault, disDefault, oneBytes, oneInt, 1, modeAny, opDefault},
	{0x16, "itob", opItob, asmDefault, disDefault, oneInt, oneBytes, 1, modeAny, opDefault},
	{0x17, "btoi", opBtoi, asmDefault, disDefault, oneBytes, oneInt, 1, modeAny, opDefault},
	{0x18, "%", opModulo, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x19, "|", opBitOr, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x1a, "&", opBitAnd, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x1b, "^", opBitXor, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opDefault},
	{0x1c, "~", opBitNot, asmDefault, disDefault, oneInt, oneInt, 1, modeAny, opDefault},
	{0x1d, "mulw", opMulw, asmDefault, disDefault, twoInts, twoInts, 1, modeAny, opDefault},
	{0x1e, "addw", opAddw, asmDefault, disDefault, twoInts, twoInts, 2, modeAny, opDefault},
	{0x1f, "divmodw", opDivModw, asmDefault, disDefault, twoInts.plus(twoInts), twoInts.plus(twoInts), 4, modeAny, costly(20)},

	{0x20, "intcblock", opIntConstBlock, asmIntCBlock, disDefault, nil, nil, 1, modeAny, sizeVaries(checkIntConstBlock, "uint ...", immInts)},
	{0x21, "intc", opIntConstLoad, asmIntC, disDefault, nil, oneInt, 1, modeAny, immediates("i")},
	{0x22, "intc_0", opIntConst0, asmDefault, disDefault, nil, oneInt, 1, modeAny, opDefault},
	{0x23, "intc_1", opIntConst1, asmDefault, disDefault, nil, oneInt, 1, modeAny, opDefault},
	{0x24, "intc_2", opIntConst2, asmDefault, disDefault, nil, oneInt, 1, modeAny, opDefault},
	{0x25, "intc_3", opIntConst3, asmDefault, disDefault, nil, oneInt, 1, modeAny, opDefault},
	{0x26, "bytecblock", opByteConstBlock, asmByteCBlock, disDefault, nil, nil, 1, modeAny, sizeVaries(checkByteConstBlock, "bytes ...", immBytess)},
	{0x27, "bytec", opByteConstLoad, asmByteC, disDefault, nil, oneBytes, 1, modeAny, immediates("i")},
	{0x28, "bytec_0", opByteConst0, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opDefault},
	{0x29, "bytec_1", opByteConst1, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opDefault},
	{0x2a, "bytec_2", opByteConst2, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opDefault},
	{0x2b, "bytec_3", opByteConst3, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opDefault},
	{0x2c, "arg", opArg, asmArg, disDefault, nil, oneBytes, 1, runModeSignature, immediates("n")},
	{0x2d, "arg_0", opArg0, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opDefault},
	{0x2e, "arg_1", opArg1, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opDefault},
	{0x2f, "arg_2", opArg2, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opDefault},
	{0x30, "arg_3", opArg3, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opDefault},
	{0x31, "txn", opTxn, asmDefault, disDefault, nil, oneAny, 1, modeAny, field("f", &TxnScalarFields)},
	// It is ok to have the same opcode for different TEAL versions.
	// This 'txn' asm command supports additional argument in version 2 and
	// generates 'txna' opcode in that particular case
	{0x31, "txn", opTxn, asmTxn2, disDefault, nil, oneAny, 2, modeAny, field("f", &TxnFields)},
	{0x32, "global", opGlobal, asmDefault, disDefault, nil, oneAny, 1, modeAny,
		field("f", &GlobalFields)},
	{0x33, "gtxn", opGtxn, asmDefault, disDefault, nil, oneAny, 1, modeAny,
		immediates("t", "f").field("f", &TxnScalarFields)},
	{0x33, "gtxn", opGtxn, asmGtxn2, disDefault, nil, oneAny, 2, modeAny,
		immediates("t", "f").field("f", &TxnFields)},
	{0x34, "load", opLoad, asmDefault, disDefault, nil, oneAny, 1, modeAny, immediates("i")},
	{0x35, "store", opStore, asmDefault, disDefault, oneAny, nil, 1, modeAny, immediates("i")},
	{0x36, "txna", opTxna, asmDefault, disDefault, nil, oneAny, 2, modeAny,
		immediates("f", "i").field("f", &TxnArrayFields)},
	{0x37, "gtxna", opGtxna, asmDefault, disDefault, nil, oneAny, 2, modeAny,
		immediates("t", "f", "i").field("f", &TxnArrayFields)},
	// Like gtxn, but gets txn index from stack, rather than immediate arg
	{0x38, "gtxns", opGtxns, asmGtxns, disDefault, oneInt, oneAny, 3, modeAny,
		immediates("f").field("f", &TxnFields)},
	{0x39, "gtxnsa", opGtxnsa, asmDefault, disDefault, oneInt, oneAny, 3, modeAny,
		immediates("f", "i").field("f", &TxnArrayFields)},
	// Group scratch space access
	{0x3a, "gload", opGload, asmDefault, disDefault, nil, oneAny, 4, runModeApplication, immediates("t", "i")},
	{0x3b, "gloads", opGloads, asmDefault, disDefault, oneInt, oneAny, 4, runModeApplication, immediates("i")},
	// Access creatable IDs (consider deprecating, as txn CreatedAssetID, CreatedApplicationID should be enough
	{0x3c, "gaid", opGaid, asmDefault, disDefault, nil, oneInt, 4, runModeApplication, immediates("t")},
	{0x3d, "gaids", opGaids, asmDefault, disDefault, oneInt, oneInt, 4, runModeApplication, opDefault},

	// Like load/store, but scratch slot taken from TOS instead of immediate
	{0x3e, "loads", opLoads, asmDefault, disDefault, oneInt, oneAny, 5, modeAny, opDefault},
	{0x3f, "stores", opStores, asmDefault, disDefault, oneInt.plus(oneAny), nil, 5, modeAny, opDefault},

	{0x40, "bnz", opBnz, asmBranch, disDefault, oneInt, nil, 1, modeAny, opBranch},
	{0x41, "bz", opBz, asmBranch, disDefault, oneInt, nil, 2, modeAny, opBranch},
	{0x42, "b", opB, asmBranch, disDefault, nil, nil, 2, modeAny, opBranch},
	{0x43, "return", opReturn, asmDefault, disDefault, oneInt, nil, 2, modeAny, opDefault},
	{0x44, "assert", opAssert, asmDefault, disDefault, oneInt, nil, 3, modeAny, opDefault},
	{0x48, "pop", opPop, asmDefault, disDefault, oneAny, nil, 1, modeAny, opDefault},
	{0x49, "dup", opDup, asmDefault, disDefault, oneAny, twoAny, 1, modeAny, stacky(typeDup)},
	{0x4a, "dup2", opDup2, asmDefault, disDefault, twoAny, twoAny.plus(twoAny), 2, modeAny, stacky(typeDupTwo)},
	// There must be at least one thing on the stack for dig, but
	// it would be nice if we did better checking than that.
	{0x4b, "dig", opDig, asmDefault, disDefault, oneAny, twoAny, 3, modeAny, stacky(typeDig, "n")},
	{0x4c, "swap", opSwap, asmDefault, disDefault, twoAny, twoAny, 3, modeAny, stacky(typeSwap)},
	{0x4d, "select", opSelect, asmDefault, disDefault, twoAny.plus(oneInt), oneAny, 3, modeAny, stacky(typeSelect)},
	{0x4e, "cover", opCover, asmDefault, disDefault, oneAny, oneAny, 5, modeAny, stacky(typeCover, "n")},
	{0x4f, "uncover", opUncover, asmDefault, disDefault, oneAny, oneAny, 5, modeAny, stacky(typeUncover, "n")},

	// byteslice processing / StringOps
	{0x50, "concat", opConcat, asmDefault, disDefault, twoBytes, oneBytes, 2, modeAny, opDefault},
	{0x51, "substring", opSubstring, asmSubstring, disDefault, oneBytes, oneBytes, 2, modeAny, immediates("s", "e")},
	{0x52, "substring3", opSubstring3, asmDefault, disDefault, byteIntInt, oneBytes, 2, modeAny, opDefault},
	{0x53, "getbit", opGetBit, asmDefault, disDefault, anyInt, oneInt, 3, modeAny, opDefault},
	{0x54, "setbit", opSetBit, asmDefault, disDefault, anyIntInt, oneAny, 3, modeAny, stacky(typeSetBit)},
	{0x55, "getbyte", opGetByte, asmDefault, disDefault, byteInt, oneInt, 3, modeAny, opDefault},
	{0x56, "setbyte", opSetByte, asmDefault, disDefault, byteIntInt, oneBytes, 3, modeAny, opDefault},
	{0x57, "extract", opExtract, asmDefault, disDefault, oneBytes, oneBytes, 5, modeAny, immediates("s", "l")},
	{0x58, "extract3", opExtract3, asmDefault, disDefault, byteIntInt, oneBytes, 5, modeAny, opDefault},
	{0x59, "extract_uint16", opExtract16Bits, asmDefault, disDefault, byteInt, oneInt, 5, modeAny, opDefault},
	{0x5a, "extract_uint32", opExtract32Bits, asmDefault, disDefault, byteInt, oneInt, 5, modeAny, opDefault},
	{0x5b, "extract_uint64", opExtract64Bits, asmDefault, disDefault, byteInt, oneInt, 5, modeAny, opDefault},
	{0x5c, "base64_decode", opBase64Decode, asmDefault, disDefault, oneBytes, oneBytes, fidoVersion, modeAny, field("e", &Base64Encodings).costByLength(1, 1, 16)},
	{0x5d, "json_ref", opJSONRef, asmDefault, disDefault, twoBytes, oneAny, fidoVersion, modeAny, field("r", &JSONRefTypes)},

	{0x60, "balance", opBalance, asmDefault, disDefault, oneInt, oneInt, 2, runModeApplication, opDefault},
	{0x60, "balance", opBalance, asmDefault, disDefault, oneAny, oneInt, directRefEnabledVersion, runModeApplication, opDefault},
	{0x61, "app_opted_in", opAppOptedIn, asmDefault, disDefault, twoInts, oneInt, 2, runModeApplication, opDefault},
	{0x61, "app_opted_in", opAppOptedIn, asmDefault, disDefault, oneAny.plus(oneInt), oneInt, directRefEnabledVersion, runModeApplication, opDefault},
	{0x62, "app_local_get", opAppLocalGet, asmDefault, disDefault, oneInt.plus(oneBytes), oneAny, 2, runModeApplication, opDefault},
	{0x62, "app_local_get", opAppLocalGet, asmDefault, disDefault, oneAny.plus(oneBytes), oneAny, directRefEnabledVersion, runModeApplication, opDefault},
	{0x63, "app_local_get_ex", opAppLocalGetEx, asmDefault, disDefault, twoInts.plus(oneBytes), oneAny.plus(oneInt), 2, runModeApplication, opDefault},
	{0x63, "app_local_get_ex", opAppLocalGetEx, asmDefault, disDefault, oneAny.plus(oneInt).plus(oneBytes), oneAny.plus(oneInt), directRefEnabledVersion, runModeApplication, opDefault},
	{0x64, "app_global_get", opAppGlobalGet, asmDefault, disDefault, oneBytes, oneAny, 2, runModeApplication, opDefault},
	{0x65, "app_global_get_ex", opAppGlobalGetEx, asmDefault, disDefault, oneInt.plus(oneBytes), oneAny.plus(oneInt), 2, runModeApplication, opDefault},
	{0x66, "app_local_put", opAppLocalPut, asmDefault, disDefault, oneInt.plus(oneBytes).plus(oneAny), nil, 2, runModeApplication, opDefault},
	{0x66, "app_local_put", opAppLocalPut, asmDefault, disDefault, oneAny.plus(oneBytes).plus(oneAny), nil, directRefEnabledVersion, runModeApplication, opDefault},
	{0x67, "app_global_put", opAppGlobalPut, asmDefault, disDefault, oneBytes.plus(oneAny), nil, 2, runModeApplication, opDefault},
	{0x68, "app_local_del", opAppLocalDel, asmDefault, disDefault, oneInt.plus(oneBytes), nil, 2, runModeApplication, opDefault},
	{0x68, "app_local_del", opAppLocalDel, asmDefault, disDefault, oneAny.plus(oneBytes), nil, directRefEnabledVersion, runModeApplication, opDefault},
	{0x69, "app_global_del", opAppGlobalDel, asmDefault, disDefault, oneBytes, nil, 2, runModeApplication, opDefault},

	{0x70, "asset_holding_get", opAssetHoldingGet, asmDefault, disDefault, twoInts, oneAny.plus(oneInt), 2, runModeApplication, field("f", &AssetHoldingFields)},
	{0x70, "asset_holding_get", opAssetHoldingGet, asmDefault, disDefault, oneAny.plus(oneInt), oneAny.plus(oneInt), directRefEnabledVersion, runModeApplication, field("f", &AssetHoldingFields)},
	{0x71, "asset_params_get", opAssetParamsGet, asmDefault, disDefault, oneInt, oneAny.plus(oneInt), 2, runModeApplication, field("f", &AssetParamsFields)},
	{0x72, "app_params_get", opAppParamsGet, asmDefault, disDefault, oneInt, oneAny.plus(oneInt), 5, runModeApplication, field("f", &AppParamsFields)},
	{0x73, "acct_params_get", opAcctParamsGet, asmDefault, disDefault, oneAny, oneAny.plus(oneInt), 6, runModeApplication, field("f", &AcctParamsFields)},

	{0x78, "min_balance", opMinBalance, asmDefault, disDefault, oneInt, oneInt, 3, runModeApplication, opDefault},
	{0x78, "min_balance", opMinBalance, asmDefault, disDefault, oneAny, oneInt, directRefEnabledVersion, runModeApplication, opDefault},

	// Immediate bytes and ints. Smaller code size for single use of constant.
	{0x80, "pushbytes", opPushBytes, asmPushBytes, disDefault, nil, oneBytes, 3, modeAny, sizeVaries(opPushBytes, "bytes", immBytes)},
	{0x81, "pushint", opPushInt, asmPushInt, disDefault, nil, oneInt, 3, modeAny, sizeVaries(opPushInt, "uint", immInt)},

	{0x84, "ed25519verify_bare", opEd25519VerifyBare, asmDefault, disDefault, threeBytes, oneInt, 7, modeAny, costly(1900)},

	// "Function oriented"
	{0x88, "callsub", opCallSub, asmBranch, disDefault, nil, nil, 4, modeAny, opBranch},
	{0x89, "retsub", opRetSub, asmDefault, disDefault, nil, nil, 4, modeAny, opDefault},
	// Leave a little room for indirect function calls, or similar

	// More math
	{0x90, "shl", opShiftLeft, asmDefault, disDefault, twoInts, oneInt, 4, modeAny, opDefault},
	{0x91, "shr", opShiftRight, asmDefault, disDefault, twoInts, oneInt, 4, modeAny, opDefault},
	{0x92, "sqrt", opSqrt, asmDefault, disDefault, oneInt, oneInt, 4, modeAny, costly(4)},
	{0x93, "bitlen", opBitLen, asmDefault, disDefault, oneAny, oneInt, 4, modeAny, opDefault},
	{0x94, "exp", opExp, asmDefault, disDefault, twoInts, oneInt, 4, modeAny, opDefault},
	{0x95, "expw", opExpw, asmDefault, disDefault, twoInts, twoInts, 4, modeAny, costly(10)},
	{0x96, "bsqrt", opBytesSqrt, asmDefault, disDefault, oneBytes, oneBytes, 6, modeAny, costly(40)},
	{0x97, "divw", opDivw, asmDefault, disDefault, twoInts.plus(oneInt), oneInt, 6, modeAny, opDefault},
	{0x98, "sha3_256", opSHA3_256, asmDefault, disDefault, oneBytes, oneBytes, 7, modeAny, costly(130)},

	/* Will end up following keccak256 -
	{0x98, "sha3_256", opSHA3_256, asmDefault, disDefault, oneBytes, oneBytes, unlimitedStorage, modeAny, costByLength(58, 4, 8)},},
	*/

	// Byteslice math.
	{0xa0, "b+", opBytesPlus, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(10)},
	{0xa1, "b-", opBytesMinus, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(10)},
	{0xa2, "b/", opBytesDiv, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(20)},
	{0xa3, "b*", opBytesMul, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(20)},
	{0xa4, "b<", opBytesLt, asmDefault, disDefault, twoBytes, oneInt, 4, modeAny, opDefault},
	{0xa5, "b>", opBytesGt, asmDefault, disDefault, twoBytes, oneInt, 4, modeAny, opDefault},
	{0xa6, "b<=", opBytesLe, asmDefault, disDefault, twoBytes, oneInt, 4, modeAny, opDefault},
	{0xa7, "b>=", opBytesGe, asmDefault, disDefault, twoBytes, oneInt, 4, modeAny, opDefault},
	{0xa8, "b==", opBytesEq, asmDefault, disDefault, twoBytes, oneInt, 4, modeAny, opDefault},
	{0xa9, "b!=", opBytesNeq, asmDefault, disDefault, twoBytes, oneInt, 4, modeAny, opDefault},
	{0xaa, "b%", opBytesModulo, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(20)},
	{0xab, "b|", opBytesBitOr, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(6)},
	{0xac, "b&", opBytesBitAnd, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(6)},
	{0xad, "b^", opBytesBitXor, asmDefault, disDefault, twoBytes, oneBytes, 4, modeAny, costly(6)},
	{0xae, "b~", opBytesBitNot, asmDefault, disDefault, oneBytes, oneBytes, 4, modeAny, costly(4)},
	{0xaf, "bzero", opBytesZero, asmDefault, disDefault, oneInt, oneBytes, 4, modeAny, opDefault},

	// AVM "effects"
	{0xb0, "log", opLog, asmDefault, disDefault, oneBytes, nil, 5, runModeApplication, opDefault},
	{0xb1, "itxn_begin", opTxBegin, asmDefault, disDefault, nil, nil, 5, runModeApplication, opDefault},
	{0xb2, "itxn_field", opItxnField, asmItxnField, disDefault, oneAny, nil, 5, runModeApplication,
		stacky(typeTxField, "f").field("f", &TxnFields)},
	{0xb3, "itxn_submit", opItxnSubmit, asmDefault, disDefault, nil, nil, 5, runModeApplication, opDefault},
	{0xb4, "itxn", opItxn, asmItxn, disDefault, nil, oneAny, 5, runModeApplication,
		field("f", &TxnScalarFields)},
	{0xb5, "itxna", opItxna, asmDefault, disDefault, nil, oneAny, 5, runModeApplication,
		immediates("f", "i").field("f", &TxnArrayFields)},
	{0xb6, "itxn_next", opItxnNext, asmDefault, disDefault, nil, nil, 6, runModeApplication, opDefault},
	{0xb7, "gitxn", opGitxn, asmGitxn, disDefault, nil, oneAny, 6, runModeApplication,
		immediates("t", "f").field("f", &TxnFields)},
	{0xb8, "gitxna", opGitxna, asmDefault, disDefault, nil, oneAny, 6, runModeApplication,
		immediates("t", "f", "i").field("f", &TxnArrayFields)},

	// Dynamic indexing
	{0xc0, "txnas", opTxnas, asmDefault, disDefault, oneInt, oneAny, 5, modeAny,
		field("f", &TxnArrayFields)},
	{0xc1, "gtxnas", opGtxnas, asmDefault, disDefault, oneInt, oneAny, 5, modeAny,
		immediates("t", "f").field("f", &TxnArrayFields)},
	{0xc2, "gtxnsas", opGtxnsas, asmDefault, disDefault, twoInts, oneAny, 5, modeAny,
		field("f", &TxnArrayFields)},
	{0xc3, "args", opArgs, asmDefault, disDefault, oneInt, oneBytes, 5, runModeSignature, opDefault},
	{0xc4, "gloadss", opGloadss, asmDefault, disDefault, twoInts, oneAny, 6, runModeApplication, opDefault},
	{0xc5, "itxnas", opItxnas, asmDefault, disDefault, oneInt, oneAny, 6, runModeApplication,
		field("f", &TxnArrayFields)},
	{0xc6, "gitxnas", opGitxnas, asmDefault, disDefault, oneInt, oneAny, 6, runModeApplication,
		immediates("t", "f").field("f", &TxnArrayFields)},
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
