// Copyright (C) 2019 Algorand, Inc.
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
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// EvalMaxVersion is the max version we can interpret and run
const EvalMaxVersion = 1

// EvalMaxArgs is the maximum number of arguments to an LSig
const EvalMaxArgs = 255

// EvalMaxScratchSize is the maximum number of scratch slots.
const EvalMaxScratchSize = 255

// stackValue is the type for the operand stack.
// Each stackValue is either a valid []byte value or a uint64 value.
// If (.Bytes != nil) the stackValue is a []byte value, otherwise uint64 value.
type stackValue struct {
	Uint  uint64
	Bytes []byte
}

func (sv *stackValue) argType() StackType {
	if sv.Bytes != nil {
		return StackBytes
	}
	return StackUint64
}

func (sv *stackValue) typeName() string {
	if sv.Bytes != nil {
		return "[]byte"
	}
	return "uint64"
}

func (sv *stackValue) String() string {
	if sv.Bytes != nil {
		return hex.EncodeToString(sv.Bytes)
	}
	return fmt.Sprintf("%d 0x%x", sv.Uint, sv.Uint)
}

// EvalParams contains data that comes into condition evaluation.
type EvalParams struct {
	// the transaction being evaluated
	Txn *transactions.SignedTxn

	Proto *config.ConsensusParams

	Trace io.Writer

	TxnGroup []transactions.SignedTxn

	// GroupIndex should point to Txn within TxnGroup
	GroupIndex int

	Logger logging.Logger
}

func (ep EvalParams) log() logging.Logger {
	if ep.Logger != nil {
		return ep.Logger
	}
	return logging.Base()
}

type evalContext struct {
	EvalParams

	stack   []stackValue
	program []byte // txn.Lsig.Logic ?
	pc      int
	nextpc  int
	err     error
	intc    []uint64
	bytec   [][]byte
	version uint64
	scratch [256]stackValue

	stepCount int
	cost      int

	// Ordered set of pc values that a branch could go to.
	// If Check pc skips a target, the source branch was invalid!
	branchTargets []int

	programHash crypto.Digest
}

type opFunc func(cx *evalContext)

// StackType describes the type of a value on the operand stack
type StackType byte

// StackNone in an OpSpec shows that the op pops or yields nothing
const StackNone StackType = 0

// StackAny in an OpSpec shows that the op pops or yield any type
const StackAny StackType = 1

// StackUint64 in an OpSpec shows that the op pops or yields a uint64
const StackUint64 StackType = 2

// StackBytes in an OpSpec shows that the op pops or yields a []byte
const StackBytes StackType = 3

func (st StackType) String() string {
	switch st {
	case StackNone:
		return "None"
	case StackAny:
		return "any"
	case StackUint64:
		return "uint64"
	case StackBytes:
		return "[]byte"
	}
	return "internal error, unknown type"
}

// PanicError wraps a recover() catching a panic()
type PanicError struct {
	PanicValue interface{}
	StackTrace string
}

func (pe PanicError) Error() string {
	return fmt.Sprintf("panic in TEAL Eval: %v\n%s", pe.PanicValue, pe.StackTrace)
}

var errLoopDetected = errors.New("loop detected")
var errCostTooHigh = errors.New("LogicSigMaxCost exceded")
var errLogicSignNotSupported = errors.New("LogicSig not supported")
var errTooManyArgs = errors.New("LogicSig has too many arguments")

// Eval checks to see if a transaction passes logic
// A program passes succesfully if it finishes with one int element on the stack that is non-zero.
func Eval(program []byte, params EvalParams) (pass bool, err error) {
	defer func() {
		if x := recover(); x != nil {
			buf := make([]byte, 16*1024)
			stlen := runtime.Stack(buf, false)
			pass = false
			errstr := string(buf[:stlen])
			if params.Trace != nil {
				if sb, ok := params.Trace.(*strings.Builder); ok {
					errstr += sb.String()
				}
			}
			err = PanicError{x, errstr}
			params.log().Errorf("recovered panic in Eval: %s", err)
		}
	}()
	if (params.Proto == nil) || (params.Proto.LogicSigVersion == 0) {
		err = errLogicSignNotSupported
		return
	}
	if params.Txn.Lsig.Args != nil && len(params.Txn.Lsig.Args) > EvalMaxArgs {
		err = errTooManyArgs
		return
	}
	var cx evalContext
	version, vlen := binary.Uvarint(program)
	if vlen <= 0 {
		cx.err = errors.New("invalid version")
		return false, cx.err
	}
	if version > EvalMaxVersion {
		cx.err = fmt.Errorf("program version %d greater than max supported version %d", version, EvalMaxVersion)
		return false, cx.err
	}
	if version > params.Proto.LogicSigVersion {
		cx.err = fmt.Errorf("program version %d greater than protocol supported version %d", version, params.Proto.LogicSigVersion)
		return false, cx.err
	}
	// TODO: if EvalMaxVersion > version, ensure that inaccessible
	// fields as of the program's version are zero or other
	// default value so that no one is hiding unexpected
	// operations from an old program.
	cx.version = version
	cx.pc = vlen
	cx.EvalParams = params
	cx.stack = make([]stackValue, 0, 10)
	cx.program = program
	cx.programHash = crypto.HashObj(Program(program))
	for (cx.err == nil) && (cx.pc < len(cx.program)) {
		cx.step()
		cx.stepCount++
		if cx.stepCount > len(cx.program) {
			return false, errLoopDetected
		}
		if uint64(cx.cost) > params.Proto.LogicSigMaxCost {
			return false, errCostTooHigh
		}
	}
	if cx.err != nil {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "%3d %s\n", cx.pc, cx.err)
		}
		return false, cx.err
	}
	if len(cx.stack) != 1 {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "end stack:\n")
			for i, sv := range cx.stack {
				fmt.Fprintf(cx.Trace, "[%d] %s\n", i, sv.String())
			}
		}
		return false, fmt.Errorf("stack len is %d instead of 1", len(cx.stack))
	}
	if cx.stack[0].Bytes != nil {
		return false, errors.New("stack finished with bytes not int")
	}
	return cx.stack[0].Uint != 0, nil
}

// Check should be faster than Eval.
// Returns 'cost' which is an estimate of relative execution time.
func Check(program []byte, params EvalParams) (cost int, err error) {
	defer func() {
		if x := recover(); x != nil {
			buf := make([]byte, 16*1024)
			stlen := runtime.Stack(buf, false)
			cost = 0
			errstr := string(buf[:stlen])
			if params.Trace != nil {
				if sb, ok := params.Trace.(*strings.Builder); ok {
					errstr += sb.String()
				}
			}
			err = PanicError{x, errstr}
			params.log().Errorf("recovered panic in Check: %s", err)
		}
	}()
	if (params.Proto == nil) || (params.Proto.LogicSigVersion == 0) {
		err = errLogicSignNotSupported
		return
	}
	var cx evalContext
	version, vlen := binary.Uvarint(program)
	if vlen <= 0 {
		cx.err = errors.New("invalid version")
		return 0, cx.err
	}
	if version > EvalMaxVersion {
		err = fmt.Errorf("program version %d greater than max supported version %d", version, EvalMaxVersion)
		return
	}
	if version > params.Proto.LogicSigVersion {
		err = fmt.Errorf("program version %d greater than protocol supported version %d", version, params.Proto.LogicSigVersion)
		return
	}
	cx.version = version
	cx.pc = vlen
	cx.EvalParams = params
	cx.program = program
	for (cx.err == nil) && (cx.pc < len(cx.program)) {
		cost += cx.checkStep()
	}
	if cx.err != nil {
		err = fmt.Errorf("%3d %s", cx.pc, cx.err)
		return
	}
	return
}

// OpSpec defines one byte opcode
type OpSpec struct {
	Opcode  byte
	Name    string
	op      opFunc      // evaluate the op
	Args    []StackType // what gets popped from the stack
	Returns []StackType // what gets pushed to the stack
}

var oneBytes = []StackType{StackBytes}
var threeBytes = []StackType{StackBytes, StackBytes, StackBytes}
var oneInt = []StackType{StackUint64}
var twoInts = []StackType{StackUint64, StackUint64}
var oneAny = []StackType{StackAny}
var twoAny = []StackType{StackAny, StackAny}

// OpSpecs is the table of operations that can be assembled and evaluated.
//
// Any changes should be reflected in README.md which serves as the language spec.
var OpSpecs = []OpSpec{
	{0x00, "err", opErr, nil, nil},
	{0x01, "sha256", opSHA256, oneBytes, oneBytes},
	{0x02, "keccak256", opKeccak256, oneBytes, oneBytes},
	{0x03, "sha512_256", opSHA512_256, oneBytes, oneBytes},
	{0x04, "ed25519verify", opEd25519verify, threeBytes, oneInt},
	{0x08, "+", opPlus, twoInts, oneInt},
	{0x09, "-", opMinus, twoInts, oneInt},
	{0x0a, "/", opDiv, twoInts, oneInt},
	{0x0b, "*", opMul, twoInts, oneInt},
	{0x0c, "<", opLt, twoInts, oneInt},
	{0x0d, ">", opGt, twoInts, oneInt},
	{0x0e, "<=", opLe, twoInts, oneInt},
	{0x0f, ">=", opGe, twoInts, oneInt},
	{0x10, "&&", opAnd, twoInts, oneInt},
	{0x11, "||", opOr, twoInts, oneInt},
	{0x12, "==", opEq, twoAny, oneInt},
	{0x13, "!=", opNeq, twoAny, oneInt},
	{0x14, "!", opNot, oneInt, oneInt},
	{0x15, "len", opLen, oneBytes, oneInt},
	{0x16, "itob", opItob, oneInt, oneBytes},
	{0x17, "btoi", opBtoi, oneBytes, oneInt},
	{0x18, "%", opModulo, twoInts, oneInt},
	{0x19, "|", opBitOr, twoInts, oneInt},
	{0x1a, "&", opBitAnd, twoInts, oneInt},
	{0x1b, "^", opBitXor, twoInts, oneInt},
	{0x1c, "~", opBitNot, oneInt, oneInt},
	{0x1d, "mulw", opMulw, twoInts, twoInts},

	{0x20, "intcblock", opIntConstBlock, nil, nil},
	{0x21, "intc", opIntConstLoad, nil, oneInt},
	{0x22, "intc_0", opIntConst0, nil, oneInt},
	{0x23, "intc_1", opIntConst1, nil, oneInt},
	{0x24, "intc_2", opIntConst2, nil, oneInt},
	{0x25, "intc_3", opIntConst3, nil, oneInt},
	{0x26, "bytecblock", opByteConstBlock, nil, nil},
	{0x27, "bytec", opByteConstLoad, nil, oneBytes},
	{0x28, "bytec_0", opByteConst0, nil, oneBytes},
	{0x29, "bytec_1", opByteConst1, nil, oneBytes},
	{0x2a, "bytec_2", opByteConst2, nil, oneBytes},
	{0x2b, "bytec_3", opByteConst3, nil, oneBytes},
	{0x2c, "arg", opArg, nil, oneBytes},
	{0x2d, "arg_0", opArg0, nil, oneBytes},
	{0x2e, "arg_1", opArg1, nil, oneBytes},
	{0x2f, "arg_2", opArg2, nil, oneBytes},
	{0x30, "arg_3", opArg3, nil, oneBytes},
	{0x31, "txn", opTxn, nil, oneAny},       // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x32, "global", opGlobal, nil, oneAny}, // TODO: check output type against specific field
	{0x33, "gtxn", opGtxn, nil, oneAny},     // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x34, "load", opLoad, nil, oneAny},
	{0x35, "store", opStore, oneAny, nil},

	{0x40, "bnz", opBnz, oneInt, nil},
	{0x48, "pop", opPop, oneAny, nil},
	{0x49, "dup", opDup, oneAny, twoAny},
}

// direct opcode bytes
var opsByOpcode []OpSpec

type opCheckFunc func(cx *evalContext) int

// opSize records the length in bytes for an op that is constant-length but not length 1
type opSize struct {
	name      string
	cost      int
	size      int
	checkFunc opCheckFunc
}

// opSizes records the size of ops that are constant size but not 1
// Also records time 'cost' and custom check functions.
var opSizes = []opSize{
	{"sha256", 7, 1, nil},
	{"keccak256", 26, 1, nil},
	{"sha512_256", 9, 1, nil},
	{"ed25519verify", 1900, 1, nil},
	{"bnz", 1, 3, checkBnz},
	{"intc", 1, 2, nil},
	{"bytec", 1, 2, nil},
	{"arg", 1, 2, nil},
	{"txn", 1, 2, nil},
	{"gtxn", 1, 3, nil},
	{"global", 1, 2, nil},
	{"intcblock", 1, 0, checkIntConstBlock},
	{"bytecblock", 1, 0, checkByteConstBlock},
	{"load", 1, 2, nil},
	{"store", 1, 2, nil},
}

var opSizeByOpcode []opSize

func init() {
	opsByOpcode = make([]OpSpec, 256)
	for _, oi := range OpSpecs {
		opsByOpcode[oi.Opcode] = oi
	}

	opSizeByName := make(map[string]*opSize, len(opSizes))
	for i, oz := range opSizes {
		opSizeByName[oz.name] = &opSizes[i]
	}
	opSizeByOpcode = make([]opSize, 256)
	for _, oi := range OpSpecs {
		oz := opSizeByName[oi.Name]
		if oz == nil {
			opSizeByOpcode[oi.Opcode] = opSize{oi.Name, 1, 1, nil}
		} else {
			opSizeByOpcode[oi.Opcode] = *oz
		}
	}
}

func opCompat(expected, got StackType) bool {
	if expected == StackAny {
		return true
	}
	return expected == got
}

func nilToEmpty(x []byte) []byte {
	if x == nil {
		return make([]byte, 0)
	}
	return x
}

// MaxStackDepth should move to consensus params
const MaxStackDepth = 1000

func (cx *evalContext) step() {
	opcode := cx.program[cx.pc]
	if opsByOpcode[opcode].op == nil {
		cx.err = fmt.Errorf("%3d illegal opcode %02x", cx.pc, opcode)
		return
	}
	argsTypes := opsByOpcode[opcode].Args
	if len(argsTypes) >= 0 {
		// check args for stack underflow and types
		if len(cx.stack) < len(argsTypes) {
			cx.err = fmt.Errorf("stack underflow in %s", opsByOpcode[opcode].Name)
			return
		}
		first := len(cx.stack) - len(argsTypes)
		for i, argType := range argsTypes {
			if !opCompat(argType, cx.stack[first+i].argType()) {
				cx.err = fmt.Errorf("%s arg %d wanted %s but got %s", opsByOpcode[opcode].Name, i, argType.String(), cx.stack[first+i].typeName())
				return
			}
		}
	}
	oz := opSizeByOpcode[opcode]
	if oz.size != 0 && (cx.pc+oz.size > len(cx.program)) {
		cx.err = fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, opsByOpcode[opcode].Name)
		return
	}
	cx.cost += oz.cost
	opsByOpcode[opcode].op(cx)
	if cx.Trace != nil {
		if len(cx.stack) == 0 {
			fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, opsByOpcode[opcode].Name, "<empty stack>")
		} else {
			fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, opsByOpcode[opcode].Name, cx.stack[len(cx.stack)-1].String())
		}
	}
	if cx.err != nil {
		return
	}
	if len(cx.stack) > MaxStackDepth {
		cx.err = errors.New("stack overflow")
		return
	}
	if cx.nextpc != 0 {
		cx.pc = cx.nextpc
		cx.nextpc = 0
	} else {
		cx.pc++
	}
}

func (cx *evalContext) checkStep() (cost int) {
	opcode := cx.program[cx.pc]
	if opsByOpcode[opcode].op == nil {
		cx.err = fmt.Errorf("%3d illegal opcode %02x", cx.pc, opcode)
		return 1
	}
	oz := opSizeByOpcode[opcode]
	if oz.size != 0 && (cx.pc+oz.size > len(cx.program)) {
		cx.err = fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, opsByOpcode[opcode].Name)
		return 1
	}
	if oz.checkFunc != nil {
		cost = oz.checkFunc(cx)
		if cx.nextpc != 0 {
			cx.pc = cx.nextpc
			cx.nextpc = 0
		} else {
			cx.pc += oz.size
		}
	} else {
		cost = oz.cost
		cx.pc += oz.size
	}
	if cx.err != nil {
		return 1
	}
	if len(cx.branchTargets) > 0 {
		if cx.branchTargets[0] < cx.pc {
			cx.err = fmt.Errorf("branch target at %d not an aligned instruction", cx.branchTargets[0])
			return 1
		}
		for len(cx.branchTargets) > 0 && cx.branchTargets[0] == cx.pc {
			// checks okay
			cx.branchTargets = cx.branchTargets[1:]
		}
	}
	return
}

func opErr(cx *evalContext) {
	cx.err = errors.New("error")
}

func opSHA256(cx *evalContext) {
	last := len(cx.stack) - 1
	hash := sha256.Sum256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
}

// The Keccak256 variant of SHA-3 is implemented for compatibility with Ethereum
func opKeccak256(cx *evalContext) {
	last := len(cx.stack) - 1
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(cx.stack[last].Bytes)
	hv := make([]byte, 0, hasher.Size())
	hv = hasher.Sum(hv)
	cx.stack[last].Bytes = hv
}

// This is the hash commonly used in Algorand in crypto/util.go Hash()
//
// It is explicitly implemented here in terms of the specific hash for
// stability and portability in case the rest of Algorand ever moves
// to a different default hash. For stability of this language, at
// that time a new opcode should be made with the new hash.
func opSHA512_256(cx *evalContext) {
	last := len(cx.stack) - 1
	hash := sha512.Sum512_256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
}

func opPlus(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint += cx.stack[last].Uint
	if cx.stack[prev].Uint < cx.stack[last].Uint {
		cx.err = errors.New("+ overflowed")
		return
	}
	cx.stack = cx.stack[:last]
}

func opMinus(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > cx.stack[prev].Uint {
		cx.err = errors.New("- would result negative")
		return
	}
	cx.stack[prev].Uint -= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opDiv(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		cx.err = errors.New("/ 0")
		return
	}
	cx.stack[prev].Uint /= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opModulo(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		cx.err = errors.New("% 0")
		return
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint % cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opMul(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	a := cx.stack[prev].Uint
	b := cx.stack[last].Uint
	v := a * b
	if (a != 0) && (b != 0) && (v/a != b) {
		cx.err = errors.New("* overflowed")
		return
	}
	cx.stack[prev].Uint = v
	cx.stack = cx.stack[:last]
}

func opMulwImpl(x, y uint64) (high64 uint64, low64 uint64, err error) {
	var a, b, v big.Int
	a.SetUint64(x)
	b.SetUint64(y)
	v.Mul(&a, &b)

	var maxUint, high, low big.Int
	maxUint.SetUint64(math.MaxUint64)
	low.And(&v, &maxUint)
	high.Rsh(&v, 64)
	if !low.IsUint64() || !high.IsUint64() {
		err = errors.New("mulw overflowed")
		return
	}

	high64 = high.Uint64()
	low64 = low.Uint64()
	return
}

func opMulw(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	high, low, err := opMulwImpl(cx.stack[prev].Uint, cx.stack[last].Uint)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack[prev].Uint = high
	cx.stack[last].Uint = low
}

func opLt(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint < cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opGt(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint > cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opLe(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint <= cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opGe(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint >= cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opAnd(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := (cx.stack[prev].Uint != 0) && (cx.stack[last].Uint != 0)
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opOr(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := (cx.stack[prev].Uint != 0) || (cx.stack[last].Uint != 0)
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opEq(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	ta := cx.stack[prev].argType()
	tb := cx.stack[last].argType()
	if ta != tb {
		cx.err = fmt.Errorf("cannot compare (%s == %s)", cx.stack[prev].typeName(), cx.stack[last].typeName())
		return
	}
	var cond bool
	if ta == StackBytes {
		cond = bytes.Compare(cx.stack[prev].Bytes, cx.stack[last].Bytes) == 0
	} else {
		cond = cx.stack[prev].Uint == cx.stack[last].Uint
	}
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
}

func opNeq(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	ta := cx.stack[prev].argType()
	tb := cx.stack[last].argType()
	if ta != tb {
		cx.err = fmt.Errorf("cannot compare (%s == %s)", cx.stack[prev].typeName(), cx.stack[last].typeName())
		return
	}
	var cond bool
	if ta == StackBytes {
		cond = bytes.Compare(cx.stack[prev].Bytes, cx.stack[last].Bytes) != 0
		cx.stack[prev].Bytes = nil
	} else {
		cond = cx.stack[prev].Uint != cx.stack[last].Uint
	}
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opNot(cx *evalContext) {
	last := len(cx.stack) - 1
	cond := cx.stack[last].Uint == 0
	if cond {
		cx.stack[last].Uint = 1
	} else {
		cx.stack[last].Uint = 0
	}
}

func opLen(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = uint64(len(cx.stack[last].Bytes))
	cx.stack[last].Bytes = nil
}

func opItob(cx *evalContext) {
	last := len(cx.stack) - 1
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, cx.stack[last].Uint)
	cx.stack[last].Bytes = ibytes
}

func opBtoi(cx *evalContext) {
	last := len(cx.stack) - 1
	ibytes := cx.stack[last].Bytes
	if len(ibytes) > 8 {
		cx.err = fmt.Errorf("btoi arg too long, got [%d]bytes", len(ibytes))
		return
	}
	value := uint64(0)
	for _, b := range ibytes {
		value = value << 8
		value = value | (uint64(b) & 0x0ff)
	}
	cx.stack[last].Uint = value
	cx.stack[last].Bytes = nil
}

func opBitOr(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint | cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitAnd(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint & cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitXor(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint ^ cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitNot(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = cx.stack[last].Uint ^ 0xffffffffffffffff
}

func opIntConstBlock(cx *evalContext) {
	cx.intc, cx.nextpc, cx.err = parseIntcblock(cx.program, cx.pc)
}

func opIntConstN(cx *evalContext, n uint) {
	if n >= uint(len(cx.intc)) {
		cx.err = fmt.Errorf("intc [%d] beyond %d constants", n, len(cx.intc))
		return
	}
	cx.stack = append(cx.stack, stackValue{Uint: cx.intc[n]})
}
func opIntConstLoad(cx *evalContext) {
	n := uint(cx.program[cx.pc+1])
	opIntConstN(cx, n)
	cx.nextpc = cx.pc + 2
}
func opIntConst0(cx *evalContext) {
	opIntConstN(cx, 0)
}
func opIntConst1(cx *evalContext) {
	opIntConstN(cx, 1)
}
func opIntConst2(cx *evalContext) {
	opIntConstN(cx, 2)
}
func opIntConst3(cx *evalContext) {
	opIntConstN(cx, 3)
}

func opByteConstBlock(cx *evalContext) {
	cx.bytec, cx.nextpc, cx.err = parseBytecBlock(cx.program, cx.pc)
}

func opByteConstN(cx *evalContext, n uint) {
	if n >= uint(len(cx.bytec)) {
		cx.err = fmt.Errorf("bytec [%d] beyond %d constants", n, len(cx.bytec))
		return
	}
	cx.stack = append(cx.stack, stackValue{Bytes: cx.bytec[n]})
}
func opByteConstLoad(cx *evalContext) {
	n := uint(cx.program[cx.pc+1])
	opByteConstN(cx, n)
	cx.nextpc = cx.pc + 2
}
func opByteConst0(cx *evalContext) {
	opByteConstN(cx, 0)
}
func opByteConst1(cx *evalContext) {
	opByteConstN(cx, 1)
}
func opByteConst2(cx *evalContext) {
	opByteConstN(cx, 2)
}
func opByteConst3(cx *evalContext) {
	opByteConstN(cx, 3)
}

func opArgN(cx *evalContext, n uint64) {
	if n >= uint64(len(cx.Txn.Lsig.Args)) {
		cx.err = fmt.Errorf("cannot load arg[%d] of %d", n, len(cx.Txn.Lsig.Args))
		return
	}
	val := nilToEmpty(cx.Txn.Lsig.Args[n])
	cx.stack = append(cx.stack, stackValue{Bytes: val})
}
func opArg(cx *evalContext) {
	n := uint64(cx.program[cx.pc+1])
	opArgN(cx, n)
	cx.nextpc = cx.pc + 2
}
func opArg0(cx *evalContext) {
	opArgN(cx, 0)
}
func opArg1(cx *evalContext) {
	opArgN(cx, 1)
}
func opArg2(cx *evalContext) {
	opArgN(cx, 2)
}
func opArg3(cx *evalContext) {
	opArgN(cx, 3)
}

func checkBnz(cx *evalContext) int {
	offset := (uint(cx.program[cx.pc+1]) << 8) | uint(cx.program[cx.pc+2])
	if offset > 0x7fff {
		cx.err = fmt.Errorf("bnz offset %x too large", offset)
		return 1
	}
	cx.nextpc = cx.pc + 3
	target := cx.nextpc + int(offset)
	if target >= len(cx.program) {
		cx.err = errors.New("bnz target beyond end of program")
		return 1
	}
	cx.branchTargets = append(cx.branchTargets, target)
	sort.Ints(cx.branchTargets)
	return 1
}
func opBnz(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.nextpc = cx.pc + 3
	isNonZero := cx.stack[last].Uint != 0
	cx.stack = cx.stack[:last] // pop
	if isNonZero {
		offset := (uint(cx.program[cx.pc+1]) << 8) | uint(cx.program[cx.pc+2])
		if offset > 0x7fff {
			cx.err = fmt.Errorf("bnz offset %x too large", offset)
			return
		}
		cx.nextpc += int(offset)
	}
}

func opPop(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.stack = cx.stack[:last]
}

func opDup(cx *evalContext) {
	last := len(cx.stack) - 1
	sv := cx.stack[last]
	cx.stack = append(cx.stack, sv)
}

func (cx *evalContext) txnFieldToStack(txn *transactions.Transaction, field uint64) (sv stackValue, err error) {
	err = nil
	switch TxnField(field) {
	case Sender:
		sv.Bytes = txn.Sender[:]
	case Fee:
		sv.Uint = txn.Fee.Raw
	case FirstValid:
		sv.Uint = uint64(txn.FirstValid)
	case LastValid:
		sv.Uint = uint64(txn.LastValid)
	case Note:
		sv.Bytes = nilToEmpty(txn.Note)
	case Receiver:
		sv.Bytes = txn.Receiver[:]
	case Amount:
		sv.Uint = txn.Amount.Raw
	case CloseRemainderTo:
		sv.Bytes = txn.CloseRemainderTo[:]
	case VotePK:
		sv.Bytes = txn.VotePK[:]
	case SelectionPK:
		sv.Bytes = txn.SelectionPK[:]
	case VoteFirst:
		sv.Uint = uint64(txn.VoteFirst)
	case VoteLast:
		sv.Uint = uint64(txn.VoteLast)
	case VoteKeyDilution:
		sv.Uint = txn.VoteKeyDilution
	case Type:
		sv.Bytes = []byte(txn.Type)
	case TypeEnum:
		sv.Uint = uint64(txnTypeIndexes[string(txn.Type)])
	case XferAsset:
		sv.Uint = uint64(txn.XferAsset)
	case AssetAmount:
		sv.Uint = txn.AssetAmount
	case AssetSender:
		sv.Bytes = txn.AssetSender[:]
	case AssetReceiver:
		sv.Bytes = txn.AssetReceiver[:]
	case AssetCloseTo:
		sv.Bytes = txn.AssetCloseTo[:]
	case GroupIndex:
		sv.Uint = uint64(cx.GroupIndex)
	case TxID:
		txid := txn.ID()
		sv.Bytes = txid[:]
	case Lease:
		sv.Bytes = txn.Lease[:]
	default:
		err = fmt.Errorf("invalid txn field %d", field)
	}
	return
}

func opTxn(cx *evalContext) {
	field := uint64(cx.program[cx.pc+1])
	var sv stackValue
	var err error
	sv, err = cx.txnFieldToStack(&cx.Txn.Txn, field)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 2
}

func opGtxn(cx *evalContext) {
	gtxid := int(uint(cx.program[cx.pc+1]))
	if gtxid >= len(cx.TxnGroup) {
		cx.err = fmt.Errorf("gtxn lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := uint64(cx.program[cx.pc+2])
	var sv stackValue
	var err error
	if TxnField(field) == GroupIndex {
		// GroupIndex; asking this when we just specified it is _dumb_, but oh well
		sv.Uint = uint64(gtxid)
	} else {
		sv, err = cx.txnFieldToStack(tx, field)
		if err != nil {
			cx.err = err
			return
		}
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 3
}

var zeroAddress basics.Address

func opGlobal(cx *evalContext) {
	gindex := uint64(cx.program[cx.pc+1])
	var sv stackValue
	switch GlobalField(gindex) {
	case MinTxnFee:
		sv.Uint = cx.Proto.MinTxnFee
	case MinBalance:
		sv.Uint = cx.Proto.MinBalance
	case MaxTxnLife:
		sv.Uint = cx.Proto.MaxTxnLife
	case ZeroAddress:
		sv.Bytes = zeroAddress[:]
	case GroupSize:
		sv.Uint = uint64(len(cx.TxnGroup))
	default:
		cx.err = fmt.Errorf("invalid global[%d]", gindex)
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 2
}

// Msg is data meant to be signed and then verified with the
// ed25519verify opcode.
type Msg struct {
	_struct     struct{}      `codec:",omitempty,omitemptyarray"`
	ProgramHash crypto.Digest `codec:"p"`
	Data        []byte        `codec:"d"`
}

// ToBeHashed implements crypto.Hashable
func (msg Msg) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.ProgramData, append(msg.ProgramHash[:], msg.Data...)
}

func opEd25519verify(cx *evalContext) {
	last := len(cx.stack) - 1 // index of PK
	prev := last - 1          // index of signature
	pprev := prev - 1         // index of data

	var sv crypto.SignatureVerifier
	if len(cx.stack[last].Bytes) != len(sv) {
		cx.err = errors.New("invalid public key")
		return
	}
	copy(sv[:], cx.stack[last].Bytes)

	var sig crypto.Signature
	if len(cx.stack[prev].Bytes) != len(sig) {
		cx.err = errors.New("invalid signature")
		return
	}
	copy(sig[:], cx.stack[prev].Bytes)

	msg := Msg{ProgramHash: cx.programHash, Data: cx.stack[pprev].Bytes}
	if sv.Verify(msg, sig) {
		cx.stack[pprev].Uint = 1
	} else {
		cx.stack[pprev].Uint = 0
	}
	cx.stack[pprev].Bytes = nil
	cx.stack = cx.stack[:prev]
}

func opLoad(cx *evalContext) {
	gindex := int(uint(cx.program[cx.pc+1]))
	cx.stack = append(cx.stack, cx.scratch[gindex])
	cx.nextpc = cx.pc + 2
}

func opStore(cx *evalContext) {
	gindex := int(uint(cx.program[cx.pc+1]))
	last := len(cx.stack) - 1
	cx.scratch[gindex] = cx.stack[last]
	cx.stack = cx.stack[:last]
	cx.nextpc = cx.pc + 2
}
