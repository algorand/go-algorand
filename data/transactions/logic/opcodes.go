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
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
)

// LogicVersion defines default assembler and max eval versions
const LogicVersion = 13

// rekeyingEnabledVersion is the version of TEAL where RekeyTo functionality
// was enabled. This is important to remember so that old TEAL accounts cannot
// be maliciously or accidentally rekeyed. Do not edit!
const rekeyingEnabledVersion = 2

// appsEnabledVersion is the version of TEAL where ApplicationCall
// functionality was enabled. We use this to disallow v0 and v1 programs
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

const fidoVersion = 7       // base64, json, secp256r1
const randomnessVersion = 7 // vrf_verify, block
const fpVersion = 8         // changes for frame pointers and simpler function discipline

const sharedResourcesVersion = 9 // apps can access resources from other transactions.

const pairingVersion = 10 // bn256 opcodes. will add bls12-381, and unify the available opcodes.
const spliceVersion = 10  // box splicing/resizing

const incentiveVersion = 11 // block fields, heartbeat
const mimcVersion = 11

// EXPERIMENTAL. These should be revisited whenever a new LogicSigVersion is
// moved from vFuture to a new consensus version. If they remain unready, bump
// their version, and fixup TestAssemble() in assembler_test.go.
const sumhashVersion = 13

// Unlimited Global Storage opcodes
const boxVersion = 8 // box_*

type linearCost struct {
	baseCost  int
	chunkCost int
	chunkSize int
	depth     int
}

func (lc linearCost) check() linearCost {
	if lc.baseCost < 1 || lc.chunkCost < 0 || lc.chunkSize < 0 || lc.chunkSize > maxStringSize || lc.depth < 0 {
		panic(fmt.Sprintf("bad cost configuration %+v", lc))
	}
	if lc.chunkCost > 0 && lc.chunkSize == 0 {
		panic(fmt.Sprintf("chunk cost when chunk size is zero %+v", lc))
	}
	if lc.chunkCost == 0 && lc.chunkSize > 0 {
		panic(fmt.Sprintf("no chunk cost with positive chunk size %+v", lc))
	}
	return lc
}

func (lc *linearCost) compute(stack []stackValue) int {
	cost := lc.baseCost
	if lc.chunkCost != 0 && lc.chunkSize != 0 {
		// Uses basics.DivCeil rather than (count/chunkSize) to match how Ethereum discretizes hashing costs.
		count := len(stack[len(stack)-1-lc.depth].Bytes)
		cost += lc.chunkCost * basics.DivCeil(count, lc.chunkSize)
	}
	return cost
}

func (lc *linearCost) docCost(argLen int) string {
	if *lc == (linearCost{}) {
		return ""
	}
	if lc.chunkCost == 0 {
		return strconv.Itoa(lc.baseCost)
	}
	idxFromStart := argLen - lc.depth - 1
	stackArg := rune(int('A') + idxFromStart)
	if lc.chunkSize == 1 {
		return fmt.Sprintf("%d + %d per byte of %c", lc.baseCost, lc.chunkCost, stackArg)
	}
	return fmt.Sprintf("%d + %d per %d bytes of %c", lc.baseCost, lc.chunkCost, lc.chunkSize, stackArg)
}

// OpDetails records details such as non-standard costs, immediate arguments, or
// dynamic layout controlled by a check function. These objects are mostly built
// with constructor functions, so it's cleaner to have defaults set here, rather
// than in line after line of OpSpecs.
type OpDetails struct {
	asm    asmFunc    // assemble the op
	check  checkFunc  // static check bytecode (and determine size)
	refine refineFunc // refine arg/return types based on ProgramKnowledge at assembly time

	Modes RunMode // all modes that opcode can run in. i.e (cx.mode & Modes) != 0 allows

	FullCost   linearCost  // if non-zero, the cost of the opcode, no immediates matter
	Size       int         // if non-zero, the known size of opcode. if 0, check() determines.
	Immediates []immediate // details of each immediate arg to opcode

	trusted bool // if `trusted`, don't check stack effects. they are more complicated than simply checking the opcode prototype.
}

func (d *OpDetails) docCost(argLen int, version uint64) string {
	cost := d.FullCost.docCost(argLen)
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
			var fieldCostStrings []string
			for _, name := range group.Names {
				fs, ok := group.SpecByName(name)
				if !ok || fs.Version() > version {
					continue
				}
				fieldCostStrings = append(fieldCostStrings, fmt.Sprintf("%s=%s", name, imm.fieldCosts[fs.Field()].docCost(argLen)))
			}
			cost = strings.Join(fieldCostStrings, "; ")
		}
	}
	return cost
}

// Cost computes the cost of the opcode, given details about how it is used,
// both static (the program, which can be used to find the immediate values
// supplied), and dynamic (the stack, which can be used to find the run-time
// arguments supplied). Cost is used at run-time. docCost returns similar
// information in human-readable form.
func (d *OpDetails) Cost(program []byte, pc int, stack []stackValue) int {
	cost := d.FullCost.compute(stack)
	if cost != 0 {
		return cost
	}
	for i := range d.Immediates {
		if d.Immediates[i].fieldCosts != nil {
			lc := d.Immediates[i].fieldCosts[program[pc+1+i]]
			cost += lc.compute(stack)
		}
	}
	return cost
}

func detDefault() OpDetails {
	return OpDetails{asmDefault, nil, nil, modeAny, linearCost{baseCost: 1}, 1, nil, false}
}

func constants(asm asmFunc, checker checkFunc, name string, kind immKind) OpDetails {
	return OpDetails{asm, checker, nil, modeAny, linearCost{baseCost: 1}, 0, []immediate{imm(name, kind)}, false}
}

func detBranch() OpDetails {
	d := detDefault()
	d.asm = asmBranch
	d.check = checkBranch
	d.Size = 3
	d.Immediates = []immediate{imm("target", immLabel)}
	return d
}

func detSwitch() OpDetails {
	d := detDefault()
	d.asm = asmSwitch
	d.check = checkSwitch
	d.Size = 0
	d.Immediates = []immediate{imm("target ...", immLabels)}
	return d
}

func assembler(asm asmFunc) OpDetails {
	d := detDefault()
	d.asm = asm
	return d
}

func (d OpDetails) assembler(asm asmFunc) OpDetails {
	d.asm = asm
	return d
}

func costly(cost int) OpDetails {
	return detDefault().costs(cost)
}

func (d OpDetails) costs(cost int) OpDetails {
	d.FullCost = linearCost{baseCost: cost}.check()
	return d
}

func only(m RunMode) OpDetails {
	d := detDefault()
	d.Modes = m
	return d
}

func (d OpDetails) only(m RunMode) OpDetails {
	d.Modes = m
	return d
}

func (d OpDetails) costByLength(initial, perChunk, chunkSize, depth int) OpDetails {
	d.FullCost = costByLength(initial, perChunk, chunkSize, depth).FullCost
	return d
}

func immediates(names ...string) OpDetails {
	return immKinded(immByte, names...)
}

func (d OpDetails) trust() OpDetails {
	d.trusted = true
	return d
}

func immKinded(kind immKind, names ...string) OpDetails {
	d := detDefault()
	d.Size = len(names) + 1
	d.Immediates = make([]immediate, len(names))
	for i, name := range names {
		d.Immediates[i] = imm(name, kind)
	}
	return d
}

func typed(typer refineFunc) OpDetails {
	d := detDefault()
	d.refine = typer
	return d
}

func (d OpDetails) typed(typer refineFunc) OpDetails {
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
	if len(costs) != len(group.Names) {
		panic(fmt.Sprintf("While defining costs for %s in group %s: %d costs != %d names",
			immediate, group.Name, len(costs), len(group.Names)))
	}
	fieldCosts := make([]linearCost, len(costs))
	for i, cost := range costs {
		fieldCosts[i] = linearCost{baseCost: cost}
	}
	return costByFieldAndLength(immediate, group, fieldCosts)
}

func costByFieldAndLength(immediate string, group *FieldGroup, costs []linearCost) OpDetails {
	if len(costs) != len(group.Names) {
		panic(fmt.Sprintf("While defining costs for %s in group %s: %d costs != %d names",
			immediate, group.Name, len(costs), len(group.Names)))
	}
	opd := immediates(immediate)
	opd.FullCost = linearCost{} // zero FullCost is what causes eval to look deeper
	opd.Immediates[0].Group = group
	full := make([]linearCost, 256) // ensure we have 256 entries for easy lookup
	for i := range costs {
		full[i] = costs[i].check()
	}
	opd.Immediates[0].fieldCosts = full
	return opd
}

func costByLength(initial, perChunk, chunkSize, depth int) OpDetails {
	d := detDefault()
	d.FullCost = linearCost{initial, perChunk, chunkSize, depth}.check()
	return d
}

// immType describes the immediate arguments to an opcode
type immKind byte

const (
	immByte immKind = iota
	immInt8
	immLabel
	immInt
	immBytes
	immInts
	immBytess // "ss" not a typo.  Multiple "bytes"
	immLabels
)

func (ik immKind) String() string {
	switch ik {
	case immByte:
		return "uint8"
	case immInt8:
		return "int8"
	case immLabel:
		return "int16 (big-endian)"
	case immInt:
		return "varuint"
	case immBytes:
		return "varuint length, bytes"
	case immInts:
		return fmt.Sprintf("varuint count, [%s ...]", immInt.String())
	case immBytess: // "ss" not a typo.  Multiple "bytes"
		return fmt.Sprintf("varuint count, [%s ...]", immBytes.String())
	case immLabels:
		return fmt.Sprintf("varuint count, [%s ...]", immLabel.String())
	}
	return "unknown"
}

type immediate struct {
	Name  string
	kind  immKind
	Group *FieldGroup

	// If non-nil, always 256 long, so cost can be checked before eval
	fieldCosts []linearCost
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

	// StackExplain is the pointer to the function used in debugging process during simulation:
	// - on default construction, StackExplain relies on Arg and Return count.
	// - otherwise, we need to explicitly infer from EvalContext, by registering through explain function
	StackExplain debugStackExplain

	// AppStateExplain is the pointer to the function used for debugging in simulation:
	// - for an opcode not touching app's local/global/box state, this pointer is nil.
	// - otherwise, we call this method and check the operation of an opcode on app's state.
	AppStateExplain stateChangeExplain
}

func (p Proto) stackExplain(e debugStackExplain) Proto {
	p.StackExplain = e
	return p
}

func (p Proto) appStateExplain(s stateChangeExplain) Proto {
	p.AppStateExplain = s
	return p
}

func defaultDebugExplain(argCount, retCount int) debugStackExplain {
	return func(_ *EvalContext) (deletions, additions int) {
		deletions = argCount
		additions = retCount
		return
	}
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
	argTypes := parseStackTypes(parts[0])
	retTypes := parseStackTypes(parts[1])
	debugExplainFunc := defaultDebugExplain(len(filterNoneTypes(argTypes)), len(filterNoneTypes(retTypes)))
	return Proto{
		Arg:          typedList{argTypes, argEffect},
		Return:       typedList{retTypes, retEffect},
		StackExplain: debugExplainFunc,
	}
}

// OpSpec defines an opcode
type OpSpec struct {
	Opcode byte
	Name   string
	op     evalFunc // evaluate the op
	Proto
	Version   uint64 // AVM version opcode introduced
	OpDetails        // Special cost or bytecode layout considerations
}

// AlwaysExits is true iff the opcode always ends the program.
func (spec *OpSpec) AlwaysExits() bool {
	return len(spec.Return.Types) == 1 && spec.Return.Types[0].AVMType == avmNone
}

// DocCost returns the cost of the opcode in human-readable form.
func (spec *OpSpec) DocCost(version uint64) string {
	return spec.OpDetails.docCost(len(spec.Arg.Types), version)
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
	{0x00, "err", opErr, proto(":x"), 1, detDefault()},
	{0x01, "sha256", opSHA256, proto("b:b{32}"), 1, costly(7)},
	{0x02, "keccak256", opKeccak256, proto("b:b{32}"), 1, costly(26)},
	{0x03, "sha512_256", opSHA512_256, proto("b:b{32}"), 1, costly(9)},

	// Cost of these opcodes increases in AVM version 2 based on measured
	// performance. Should be able to run max hashes during stateful TEAL
	// and achieve reasonable TPS. Same opcode for different versions
	// is OK.
	{0x01, "sha256", opSHA256, proto("b:b{32}"), 2, costly(35)},
	{0x02, "keccak256", opKeccak256, proto("b:b{32}"), 2, costly(130)},
	{0x03, "sha512_256", opSHA512_256, proto("b:b{32}"), 2, costly(45)},

	/*
		Tabling these changes until we offer unlimited global storage as there
		is currently a useful pattern that requires hashes on long slices to
		creating logicsigs in apps.

		{0x01, "sha256", opSHA256, proto("b:b{32}"), ?, costByLength(...)},
		{0x02, "keccak256", opKeccak256, proto("b:b{32}"), ?, costByLength(...)},
		{0x03, "sha512_256", opSHA512_256, proto("b:b{32}"), ?, costByLength(...)},
	*/

	{0x04, "ed25519verify", opEd25519Verify, proto("bb{64}b{32}:T"), 1, costly(1900).only(ModeSig)},
	{0x04, "ed25519verify", opEd25519Verify, proto("bb{64}b{32}:T"), 5, costly(1900)},

	{0x05, "ecdsa_verify", opEcdsaVerify, proto("b{32}b{32}b{32}b{32}b{32}:T"), 5, costByField("v", &EcdsaCurves, ecdsaVerifyCosts)},
	{0x06, "ecdsa_pk_decompress", opEcdsaPkDecompress, proto("b{33}:b{32}b{32}"), 5, costByField("v", &EcdsaCurves, ecdsaDecompressCosts)},
	{0x07, "ecdsa_pk_recover", opEcdsaPkRecover, proto("b{32}ib{32}b{32}:b{32}b{32}"), 5, field("v", &EcdsaCurves).costs(2000)},

	{0x08, "+", opPlus, proto("ii:i"), 1, detDefault()},
	{0x09, "-", opMinus, proto("ii:i"), 1, detDefault()},
	{0x0a, "/", opDiv, proto("ii:i"), 1, detDefault()},
	{0x0b, "*", opMul, proto("ii:i"), 1, detDefault()},
	{0x0c, "<", opLt, proto("ii:T"), 1, detDefault()},
	{0x0d, ">", opGt, proto("ii:T"), 1, detDefault()},
	{0x0e, "<=", opLe, proto("ii:T"), 1, detDefault()},
	{0x0f, ">=", opGe, proto("ii:T"), 1, detDefault()},
	{0x10, "&&", opAnd, proto("ii:T"), 1, detDefault()},
	{0x11, "||", opOr, proto("ii:T"), 1, detDefault()},
	{0x12, "==", opEq, proto("aa:T"), 1, typed(typeEquals)},
	{0x13, "!=", opNeq, proto("aa:T"), 1, typed(typeEquals)},
	{0x14, "!", opNot, proto("i:i"), 1, detDefault()},
	{0x15, "len", opLen, proto("b:i"), 1, detDefault()},
	{0x16, "itob", opItob, proto("i:b{8}"), 1, detDefault()},
	{0x17, "btoi", opBtoi, proto("b:i"), 1, detDefault()},
	{0x18, "%", opModulo, proto("ii:i"), 1, detDefault()},
	{0x19, "|", opBitOr, proto("ii:i"), 1, detDefault()},
	{0x1a, "&", opBitAnd, proto("ii:i"), 1, detDefault()},
	{0x1b, "^", opBitXor, proto("ii:i"), 1, detDefault()},
	{0x1c, "~", opBitNot, proto("i:i"), 1, detDefault()},
	{0x1d, "mulw", opMulw, proto("ii:ii"), 1, detDefault()},
	{0x1e, "addw", opAddw, proto("ii:ii"), 2, detDefault()},
	{0x1f, "divmodw", opDivModw, proto("iiii:iiii"), 4, costly(20)},

	{0x20, "intcblock", opIntConstBlock, proto(":"), 1, constants(asmIntCBlock, checkIntImmArgs, "uint ...", immInts)},
	{0x21, "intc", opIntConstLoad, proto(":i"), 1, immediates("i").assembler(asmIntC)},
	{0x22, "intc_0", opIntConst0, proto(":i"), 1, detDefault()},
	{0x23, "intc_1", opIntConst1, proto(":i"), 1, detDefault()},
	{0x24, "intc_2", opIntConst2, proto(":i"), 1, detDefault()},
	{0x25, "intc_3", opIntConst3, proto(":i"), 1, detDefault()},
	{0x26, "bytecblock", opByteConstBlock, proto(":"), 1, constants(asmByteCBlock, checkByteImmArgs, "bytes ...", immBytess)},
	{0x27, "bytec", opByteConstLoad, proto(":b"), 1, immediates("i").assembler(asmByteC)},
	{0x28, "bytec_0", opByteConst0, proto(":b"), 1, detDefault()},
	{0x29, "bytec_1", opByteConst1, proto(":b"), 1, detDefault()},
	{0x2a, "bytec_2", opByteConst2, proto(":b"), 1, detDefault()},
	{0x2b, "bytec_3", opByteConst3, proto(":b"), 1, detDefault()},
	{0x2c, "arg", opArg, proto(":b"), 1, immediates("n").only(ModeSig).assembler(asmArg)},
	{0x2d, "arg_0", opArg0, proto(":b"), 1, only(ModeSig)},
	{0x2e, "arg_1", opArg1, proto(":b"), 1, only(ModeSig)},
	{0x2f, "arg_2", opArg2, proto(":b"), 1, only(ModeSig)},
	{0x30, "arg_3", opArg3, proto(":b"), 1, only(ModeSig)},
	// txn, gtxn, and gtxns are also implemented as pseudoOps to choose
	// between scalar and array version based on number of immediates.
	{0x31, "txn", opTxn, proto(":a"), 1, field("f", &TxnScalarFields)},
	{0x32, "global", opGlobal, proto(":a"), 1, field("f", &GlobalFields)},
	{0x33, "gtxn", opGtxn, proto(":a"), 1, immediates("t", "f").field("f", &TxnScalarFields)},
	{0x34, "load", opLoad, proto(":a"), 1, immediates("i").typed(typeLoad)},
	{0x35, "store", opStore, proto("a:"), 1, immediates("i").typed(typeStore)},
	{0x36, "txna", opTxna, proto(":a"), 2, immediates("f", "i").field("f", &TxnArrayFields)},
	{0x37, "gtxna", opGtxna, proto(":a"), 2, immediates("t", "f", "i").field("f", &TxnArrayFields)},
	// Like gtxn, but gets txn index from stack, rather than immediate arg
	{0x38, "gtxns", opGtxns, proto("i:a"), 3, immediates("f").field("f", &TxnScalarFields)},
	{0x39, "gtxnsa", opGtxnsa, proto("i:a"), 3, immediates("f", "i").field("f", &TxnArrayFields)},
	// Group scratch space access
	{0x3a, "gload", opGload, proto(":a"), 4, immediates("t", "i").only(ModeApp)},
	{0x3b, "gloads", opGloads, proto("i:a"), 4, immediates("i").only(ModeApp)},
	// Access creatable IDs (consider deprecating, as txn CreatedAssetID, CreatedApplicationID should be enough
	{0x3c, "gaid", opGaid, proto(":i"), 4, immediates("t").only(ModeApp)},
	{0x3d, "gaids", opGaids, proto("i:i"), 4, only(ModeApp)},

	// Like load/store, but scratch slot taken from TOS instead of immediate
	{0x3e, "loads", opLoads, proto("i:a"), 5, typed(typeLoads)},
	{0x3f, "stores", opStores, proto("ia:"), 5, typed(typeStores)},

	{0x40, "bnz", opBnz, proto("i:"), 1, detBranch()},
	{0x41, "bz", opBz, proto("i:"), 2, detBranch()},
	{0x42, "b", opB, proto(":"), 2, detBranch()},
	{0x43, "return", opReturn, proto("i:x").stackExplain(opReturnStackChange), 2, detDefault()},
	{0x44, "assert", opAssert, proto("i:"), 3, detDefault()},
	{0x45, "bury", opBury, proto("a:").stackExplain(opBuryStackChange), fpVersion, immediates("n").typed(typeBury)},
	{0x46, "popn", opPopN, proto(":", "[N items]", "").stackExplain(opPopNStackChange), fpVersion, immediates("n").typed(typePopN).trust()},
	{0x47, "dupn", opDupN, proto("a:", "", "A, [N copies of A]").stackExplain(opDupNStackChange), fpVersion, immediates("n").typed(typeDupN).trust()},
	{0x48, "pop", opPop, proto("a:"), 1, detDefault()},
	{0x49, "dup", opDup, proto("a:aa", "A, A"), 1, typed(typeDup)},
	{0x4a, "dup2", opDup2, proto("aa:aaaa", "A, B, A, B"), 2, typed(typeDupTwo)},
	{0x4b, "dig", opDig, proto("a:aa", "A, [N items]", "A, [N items], A").stackExplain(opDigStackChange), 3, immediates("n").typed(typeDig)},
	{0x4c, "swap", opSwap, proto("aa:aa", "B, A"), 3, typed(typeSwap)},
	{0x4d, "select", opSelect, proto("aai:a", "A or B"), 3, typed(typeSelect)},
	{0x4e, "cover", opCover, proto("a:a", "[N items], A", "A, [N items]").stackExplain(opCoverStackChange), 5, immediates("n").typed(typeCover)},
	{0x4f, "uncover", opUncover, proto("a:a", "A, [N items]", "[N items], A").stackExplain(opUncoverStackChange), 5, immediates("n").typed(typeUncover)},

	// byteslice processing / StringOps
	{0x50, "concat", opConcat, proto("bb:b"), 2, detDefault()},
	{0x51, "substring", opSubstring, proto("b:b"), 2, immediates("s", "e").assembler(asmSubstring)},
	{0x52, "substring3", opSubstring3, proto("bii:b"), 2, detDefault()},
	{0x53, "getbit", opGetBit, proto("ai:i"), 3, detDefault()},
	{0x54, "setbit", opSetBit, proto("aii:a"), 3, typed(typeSetBit)},
	{0x55, "getbyte", opGetByte, proto("bi:i"), 3, detDefault()},
	{0x56, "setbyte", opSetByte, proto("bii:b"), 3, detDefault()},
	{0x57, "extract", opExtract, proto("b:b"), 5, immediates("s", "l")},
	{0x58, "extract3", opExtract3, proto("bii:b"), 5, detDefault()},
	{0x59, "extract_uint16", opExtract16Bits, proto("bi:i"), 5, detDefault()},
	{0x5a, "extract_uint32", opExtract32Bits, proto("bi:i"), 5, detDefault()},
	{0x5b, "extract_uint64", opExtract64Bits, proto("bi:i"), 5, detDefault()},
	{0x5c, "replace2", opReplace2, proto("bb:b"), 7, immediates("s")},
	{0x5d, "replace3", opReplace3, proto("bib:b"), 7, detDefault()},
	{0x5e, "base64_decode", opBase64Decode, proto("b:b"), fidoVersion, field("e", &Base64Encodings).costByLength(1, 1, 16, 0)},
	{0x5f, "json_ref", opJSONRef, proto("bb:a"), fidoVersion, field("r", &JSONRefTypes).costByLength(25, 2, 7, 1)},

	{0x60, "balance", opBalance, proto("i:i"), 2, only(ModeApp)},
	{0x60, "balance", opBalance, proto("a:i"), directRefEnabledVersion, only(ModeApp)},
	{0x61, "app_opted_in", opAppOptedIn, proto("ii:T"), 2, only(ModeApp)},
	{0x61, "app_opted_in", opAppOptedIn, proto("ai:T"), directRefEnabledVersion, only(ModeApp)},
	{0x62, "app_local_get", opAppLocalGet, proto("iK:a").appStateExplain(opAppLocalGetStateChange), 2, only(ModeApp)},
	{0x62, "app_local_get", opAppLocalGet, proto("aK:a").appStateExplain(opAppLocalGetStateChange), directRefEnabledVersion, only(ModeApp)},
	{0x63, "app_local_get_ex", opAppLocalGetEx, proto("iiK:aT").appStateExplain(opAppLocalGetExStateChange), 2, only(ModeApp)},
	{0x63, "app_local_get_ex", opAppLocalGetEx, proto("aiK:aT").appStateExplain(opAppLocalGetExStateChange), directRefEnabledVersion, only(ModeApp)},
	{0x64, "app_global_get", opAppGlobalGet, proto("K:a").appStateExplain(opAppGlobalGetStateChange), 2, only(ModeApp)},
	{0x65, "app_global_get_ex", opAppGlobalGetEx, proto("iK:aT").appStateExplain(opAppGlobalGetExStateChange), 2, only(ModeApp)},
	{0x66, "app_local_put", opAppLocalPut, proto("iKa:").appStateExplain(opAppLocalPutStateChange), 2, only(ModeApp)},
	{0x66, "app_local_put", opAppLocalPut, proto("aKa:").appStateExplain(opAppLocalPutStateChange), directRefEnabledVersion, only(ModeApp)},
	{0x67, "app_global_put", opAppGlobalPut, proto("Ka:").appStateExplain(opAppGlobalPutStateChange), 2, only(ModeApp)},
	{0x68, "app_local_del", opAppLocalDel, proto("iK:").appStateExplain(opAppLocalDelStateChange), 2, only(ModeApp)},
	{0x68, "app_local_del", opAppLocalDel, proto("aK:").appStateExplain(opAppLocalDelStateChange), directRefEnabledVersion, only(ModeApp)},
	{0x69, "app_global_del", opAppGlobalDel, proto("K:").appStateExplain(opAppGlobalDelStateChange), 2, only(ModeApp)},
	{0x70, "asset_holding_get", opAssetHoldingGet, proto("ii:aT"), 2, field("f", &AssetHoldingFields).only(ModeApp)},
	{0x70, "asset_holding_get", opAssetHoldingGet, proto("ai:aT"), directRefEnabledVersion, field("f", &AssetHoldingFields).only(ModeApp)},
	{0x71, "asset_params_get", opAssetParamsGet, proto("i:aT"), 2, field("f", &AssetParamsFields).only(ModeApp)},
	{0x72, "app_params_get", opAppParamsGet, proto("i:aT"), 5, field("f", &AppParamsFields).only(ModeApp)},
	{0x73, "acct_params_get", opAcctParamsGet, proto("a:aT"), 6, field("f", &AcctParamsFields).only(ModeApp)},
	{0x74, "voter_params_get", opVoterParamsGet, proto("a:aT"), incentiveVersion, field("f", &VoterParamsFields).only(ModeApp)},
	{0x75, "online_stake", opOnlineStake, proto(":i"), incentiveVersion, only(ModeApp)},

	{0x78, "min_balance", opMinBalance, proto("i:i"), 3, only(ModeApp)},
	{0x78, "min_balance", opMinBalance, proto("a:i"), directRefEnabledVersion, only(ModeApp)},

	// Immediate bytes and ints. Smaller code size for single use of constant.
	{0x80, "pushbytes", opPushBytes, proto(":b"), 3, constants(asmPushBytes, opPushBytes, "bytes", immBytes)},
	{0x81, "pushint", opPushInt, proto(":i"), 3, constants(asmPushInt, opPushInt, "uint", immInt)},
	{0x82, "pushbytess", opPushBytess, proto(":", "", "[N items]").stackExplain(opPushBytessStackChange), 8, constants(asmPushBytess, checkByteImmArgs, "bytes ...", immBytess).typed(typePushBytess).trust()},
	{0x83, "pushints", opPushInts, proto(":", "", "[N items]").stackExplain(opPushIntsStackChange), 8, constants(asmPushInts, checkIntImmArgs, "uint ...", immInts).typed(typePushInts).trust()},

	{0x84, "ed25519verify_bare", opEd25519VerifyBare, proto("bb{64}b{32}:T"), 7, costly(1900)},
	{0x85, "falcon_verify", opFalconVerify, proto("bb{1232}b{1793}:T"), 12, costly(1700)}, // dynamic for internal hash?
	{0x86, "sumhash512", opSumhash512, proto("b:b{64}"), sumhashVersion, costByLength(150, 7, 4, 0)},
	{0x87, "sha512", opSHA512, proto("b:b{64}"), 13, costByLength(15, 32, 2, 0)},

	// "Function oriented"
	{0x88, "callsub", opCallSub, proto(":"), 4, detBranch()},
	{0x89, "retsub", opRetSub, proto(":").stackExplain(opRetSubStackChange), 4, detDefault().trust()},
	// protoByte is a named constant because opCallSub needs to know it.
	{protoByte, "proto", opProto, proto(":"), fpVersion, immediates("a", "r").typed(typeProto)},
	{0x8b, "frame_dig", opFrameDig, proto(":a").stackExplain(opFrameDigStackChange), fpVersion, immKinded(immInt8, "i").typed(typeFrameDig)},
	{0x8c, "frame_bury", opFrameBury, proto("a:").stackExplain(opFrameBuryStackChange), fpVersion, immKinded(immInt8, "i").typed(typeFrameBury)},
	{0x8d, "switch", opSwitch, proto("i:"), 8, detSwitch()},
	{0x8e, "match", opMatch, proto(":", "[A1, A2, ..., AN], B", "").stackExplain(opMatchStackChange), 8, detSwitch().trust()},

	// More math
	{0x90, "shl", opShiftLeft, proto("ii:i"), 4, detDefault()},
	{0x91, "shr", opShiftRight, proto("ii:i"), 4, detDefault()},
	{0x92, "sqrt", opSqrt, proto("i:i"), 4, costly(4)},
	{0x93, "bitlen", opBitLen, proto("a:i"), 4, detDefault()},
	{0x94, "exp", opExp, proto("ii:i"), 4, detDefault()},
	{0x95, "expw", opExpw, proto("ii:ii"), 4, costly(10)},
	{0x96, "bsqrt", opBytesSqrt, proto("I:I"), 6, costly(40)},
	{0x97, "divw", opDivw, proto("iii:i"), 6, detDefault()},
	{0x98, "sha3_256", opSHA3_256, proto("b:b{32}"), 7, costly(130)},
	/* Will end up following keccak256 -
	{0x98, "sha3_256", opSHA3_256, proto("b:b{32}"), ?, costByLength(...)},},
	*/

	// Byteslice math.
	{0xa0, "b+", opBytesPlus, proto("II:b"), 4, costly(10).typed(typeByteMath(maxByteMathSize + 1))},
	{0xa1, "b-", opBytesMinus, proto("II:I"), 4, costly(10)},
	{0xa2, "b/", opBytesDiv, proto("II:I"), 4, costly(20)},
	{0xa3, "b*", opBytesMul, proto("II:b"), 4, costly(20).typed(typeByteMath(maxByteMathSize * 2))},
	{0xa4, "b<", opBytesLt, proto("II:T"), 4, detDefault()},
	{0xa5, "b>", opBytesGt, proto("II:T"), 4, detDefault()},
	{0xa6, "b<=", opBytesLe, proto("II:T"), 4, detDefault()},
	{0xa7, "b>=", opBytesGe, proto("II:T"), 4, detDefault()},
	{0xa8, "b==", opBytesEq, proto("II:T"), 4, detDefault()},
	{0xa9, "b!=", opBytesNeq, proto("II:T"), 4, detDefault()},
	{0xaa, "b%", opBytesModulo, proto("II:I"), 4, costly(20)},
	{0xab, "b|", opBytesBitOr, proto("bb:b"), 4, costly(6)},
	{0xac, "b&", opBytesBitAnd, proto("bb:b"), 4, costly(6)},
	{0xad, "b^", opBytesBitXor, proto("bb:b"), 4, costly(6)},
	{0xae, "b~", opBytesBitNot, proto("b:b"), 4, costly(4)},
	{0xaf, "bzero", opBytesZero, proto("i:b"), 4, detDefault().typed(typeBzero)},

	// AVM "effects"
	{0xb0, "log", opLog, proto("b:"), 5, only(ModeApp)},
	{0xb1, "itxn_begin", opItxnBegin, proto(":"), 5, only(ModeApp)},
	{0xb2, "itxn_field", opItxnField, proto("a:"), 5, immediates("f").typed(typeTxField).field("f", &TxnFields).only(ModeApp).assembler(asmItxnField)},
	{0xb3, "itxn_submit", opItxnSubmit, proto(":"), 5, only(ModeApp)},
	{0xb4, "itxn", opItxn, proto(":a"), 5, field("f", &TxnScalarFields).only(ModeApp).assembler(asmItxn)},
	{0xb5, "itxna", opItxna, proto(":a"), 5, immediates("f", "i").field("f", &TxnArrayFields).only(ModeApp)},
	{0xb6, "itxn_next", opItxnNext, proto(":"), 6, only(ModeApp)},
	{0xb7, "gitxn", opGitxn, proto(":a"), 6, immediates("t", "f").field("f", &TxnFields).only(ModeApp).assembler(asmGitxn)},
	{0xb8, "gitxna", opGitxna, proto(":a"), 6, immediates("t", "f", "i").field("f", &TxnArrayFields).only(ModeApp)},

	// Unlimited Global Storage - Boxes
	{0xb9, "box_create", opBoxCreate, proto("Ni:T").appStateExplain(opBoxCreateStateChange), boxVersion, only(ModeApp)},
	{0xba, "box_extract", opBoxExtract, proto("Nii:b").appStateExplain(opBoxExtractStateChange), boxVersion, only(ModeApp)},
	{0xbb, "box_replace", opBoxReplace, proto("Nib:").appStateExplain(opBoxReplaceStateChange), boxVersion, only(ModeApp)},
	{0xbc, "box_del", opBoxDel, proto("N:T").appStateExplain(opBoxDelStateChange), boxVersion, only(ModeApp)},
	{0xbd, "box_len", opBoxLen, proto("N:iT").appStateExplain(opBoxGetStateChange), boxVersion, only(ModeApp)},
	{0xbe, "box_get", opBoxGet, proto("N:bT").appStateExplain(opBoxGetStateChange), boxVersion, only(ModeApp)},
	{0xbf, "box_put", opBoxPut, proto("Nb:").appStateExplain(opBoxPutStateChange), boxVersion, only(ModeApp)},

	// Dynamic indexing
	{0xc0, "txnas", opTxnas, proto("i:a"), 5, field("f", &TxnArrayFields)},
	{0xc1, "gtxnas", opGtxnas, proto("i:a"), 5, immediates("t", "f").field("f", &TxnArrayFields)},
	{0xc2, "gtxnsas", opGtxnsas, proto("ii:a"), 5, field("f", &TxnArrayFields)},
	{0xc3, "args", opArgs, proto("i:b"), 5, only(ModeSig)},
	{0xc4, "gloadss", opGloadss, proto("ii:a"), 6, only(ModeApp)},
	{0xc5, "itxnas", opItxnas, proto("i:a"), 6, field("f", &TxnArrayFields).only(ModeApp)},
	{0xc6, "gitxnas", opGitxnas, proto("i:a"), 6, immediates("t", "f").field("f", &TxnArrayFields).only(ModeApp)},

	// randomness support
	{0xd0, "vrf_verify", opVrfVerify, proto("bb{80}b{32}:b{64}T"), randomnessVersion, field("s", &VrfStandards).costs(5700)},
	{0xd1, "block", opBlock, proto("i:a"), randomnessVersion, field("f", &BlockFields)},
	{0xd2, "box_splice", opBoxSplice, proto("Niib:").appStateExplain(opBoxSpliceStateChange), spliceVersion, only(ModeApp)},
	{0xd3, "box_resize", opBoxResize, proto("Ni:").appStateExplain(opBoxResizeStateChange), spliceVersion, only(ModeApp)},

	{0xe0, "ec_add", opEcAdd, proto("bb:b"), pairingVersion,
		costByField("g", &EcGroups, []int{
			BN254g1: 125, BN254g2: 170,
			BLS12_381g1: 205, BLS12_381g2: 290})},

	{0xe1, "ec_scalar_mul", opEcScalarMul, proto("bb:b"), pairingVersion,
		costByField("g", &EcGroups, []int{
			BN254g1: 1810, BN254g2: 3430,
			BLS12_381g1: 2950, BLS12_381g2: 6530})},

	{0xe2, "ec_pairing_check", opEcPairingCheck, proto("bb:T"), pairingVersion,
		costByFieldAndLength("g", &EcGroups, []linearCost{
			BN254g1: {
				baseCost:  8000,
				chunkCost: 7_400,
				chunkSize: bn254g1Size,
			},
			BN254g2: {
				baseCost:  8000,
				chunkCost: 7_400,
				chunkSize: bn254g2Size,
			},
			BLS12_381g1: {
				baseCost:  13_000,
				chunkCost: 10_000,
				chunkSize: bls12381g1Size,
			},
			BLS12_381g2: {
				baseCost:  13_000,
				chunkCost: 10_000,
				chunkSize: bls12381g2Size,
			}})},

	{0xe3, "ec_multi_scalar_mul", opEcMultiScalarMul, proto("bb:b"), pairingVersion,
		costByFieldAndLength("g", &EcGroups, []linearCost{
			BN254g1: {
				baseCost:  3_600,
				chunkCost: 90,
				chunkSize: scalarSize,
			},
			BN254g2: {
				baseCost:  7_200,
				chunkCost: 270,
				chunkSize: scalarSize,
			},
			BLS12_381g1: {
				baseCost:  6_500,
				chunkCost: 95,
				chunkSize: scalarSize,
			},
			BLS12_381g2: {
				baseCost:  14_850,
				chunkCost: 485,
				chunkSize: scalarSize,
			}})},

	{0xe4, "ec_subgroup_check", opEcSubgroupCheck, proto("b:T"), pairingVersion,
		costByField("g", &EcGroups, []int{
			BN254g1: 20, BN254g2: 3_100, // g1 subgroup is nearly a no-op
			BLS12_381g1: 1_850, BLS12_381g2: 2_340})},
	{0xe5, "ec_map_to", opEcMapTo, proto("b:b"), pairingVersion,
		costByField("g", &EcGroups, []int{
			BN254g1: 630, BN254g2: 3_300,
			BLS12_381g1: 1_950, BLS12_381g2: 8_150})},
	{0xe6, "mimc", opMimc, proto("b:b{32}"), mimcVersion, costByFieldAndLength("c", &MimcConfigs, []linearCost{
		BN254Mp110: {
			baseCost:  10,
			chunkCost: 550,
			chunkSize: 32,
		},
		BLS12_381Mp111: {
			baseCost:  10,
			chunkCost: 550,
			chunkSize: 32,
		}})},
}

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
	values := maps.Values(subv)
	return slices.SortedFunc(values, func(a, b OpSpec) int {
		return cmp.Compare(a.Opcode, b.Opcode)
	})
}

// direct opcode bytes
var opsByOpcode [LogicVersion + 1][256]OpSpec

// OpsByName map for each version, mapping opcode name to OpSpec
var OpsByName [LogicVersion + 1]map[string]OpSpec

// Keeps track of all field names accessible in each version
var fieldNames [LogicVersion + 1]map[string]bool

// Migration from v1 to v2.
// v1 allowed execution of program with version 0.
// With v2 opcode versions are introduced and they are bound to every opcode.
// There is no opcodes with version 0 so that v2 evaluator rejects any program with version 0.
// To preserve backward compatibility version 0 array is populated with v1 opcodes
// with the version overwritten to 0.
func init() {
	// First, initialize baseline v1 opcodes.
	// Zero (empty) version is an alias for v1 opcodes and needed for compatibility with v1 code.
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
	// Start from v2 and higher,
	// copy lower version opcodes and overwrite matching version
	for v := uint64(2); v <= LogicVersion; v++ {
		// Copy opcodes from lower version
		OpsByName[v] = maps.Clone(OpsByName[v-1])
		// Copy array with direct assignment instead of a loop
		opsByOpcode[v] = opsByOpcode[v-1]

		// Update tables with opcodes from the current version
		for _, oi := range OpSpecs {
			if oi.Version == v {
				opsByOpcode[v][oi.Opcode] = oi
				OpsByName[v][oi.Name] = oi
			}
		}
	}

	for v := 0; v <= LogicVersion; v++ {
		fieldNames[v] = make(map[string]bool)
		for _, spec := range OpsByName[v] {
			for _, imm := range spec.Immediates {
				if imm.Group != nil {
					for _, fieldName := range imm.Group.Names {
						fieldNames[v][fieldName] = true
					}
				}
			}
		}
	}
}
