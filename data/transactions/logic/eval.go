// Copyright (C) 2019-2020 Algorand, Inc.
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
	"os"
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
const EvalMaxVersion = LogicVersion

// EvalMaxScratchSize is the maximum number of scratch slots.
const EvalMaxScratchSize = 255

// MaxStringSize is the limit of byte strings created by `cons`
const MaxStringSize = 4096

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

func stackValueFromTealValue(tv *basics.TealValue) (sv stackValue, err error) {
	switch tv.Type {
	case basics.TealBytesType:
		sv.Bytes = []byte(tv.Bytes)
	case basics.TealUintType:
		sv.Uint = tv.Uint
	default:
		err = fmt.Errorf("invalid TealValue type: %d", tv.Type)
	}
	return
}

func (sv *stackValue) toTealValue() (tv basics.TealValue) {
	if sv.argType() == StackBytes {
		return basics.TealValue{Type: basics.TealBytesType, Bytes: string(sv.Bytes)}
	}
	return basics.TealValue{Type: basics.TealUintType, Uint: sv.Uint}
}

// LedgerForLogic represents ledger API for Stateful TEAL program
type LedgerForLogic interface {
	Balance(addr basics.Address) (uint64, error)
	AppGlobalState() (basics.TealKeyValue, error)
	AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error)
	AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error)
	AssetParams(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetParams, error)
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

	Ledger LedgerForLogic

	// determines eval mode: runModeSignature or runModeApplication
	runModeFlags runMode
}

type opEvalFunc func(cx *evalContext)
type opCheckFunc func(cx *evalContext) int

type runMode uint64

const (
	// runModeSignature is TEAL in LogicSig execution
	runModeSignature runMode = 1 << iota

	// runModeApplication is TEAL in application/stateful mode
	runModeApplication

	// local constant, run in any mode
	modeAny = runModeSignature | runModeApplication
)

func (r runMode) Any() bool {
	return r == modeAny
}

func (r runMode) String() string {
	switch r {
	case runModeSignature:
		return "Signature"
	case runModeApplication:
		return "Application"
	case modeAny:
		return "Any"
	default:
	}
	return "Unknown"
}

func (ep EvalParams) log() logging.Logger {
	if ep.Logger != nil {
		return ep.Logger
	}
	return logging.Base()
}

type ckey struct {
	app  uint64
	addr basics.Address
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

	appGlobalStateRCache basics.TealKeyValue // read only state to track deletes
	appGlobalStateWCache basics.TealKeyValue
	appLocalStateRCache  map[ckey]basics.TealKeyValue // read only state to track deletes
	appLocalStateWCache  map[ckey]basics.TealKeyValue
	appEvalDelta         basics.EvalDelta

	// Stores state & disassembly for the optional web debugger
	debuggerState DebuggerState
	debugger      *Debugger
}

// StackType describes the type of a value on the operand stack
type StackType byte

// StackTypes is an alias for a list of StackType with syntactic sugar
type StackTypes []StackType

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

func (sts StackTypes) plus(other StackTypes) StackTypes {
	return append(sts, other...)
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

// EvalStateful executes stateful TEAL program
func EvalStateful(program []byte, params EvalParams) (pass bool, delta basics.EvalDelta, err error) {
	var cx evalContext
	cx.EvalParams = params
	cx.runModeFlags = runModeApplication

	cx.appEvalDelta = basics.MakeEvalDelta()
	cx.appGlobalStateRCache = nil
	cx.appGlobalStateWCache = nil // use nil as indicator of not loaded yet
	cx.appLocalStateRCache = make(map[ckey]basics.TealKeyValue)
	cx.appLocalStateWCache = make(map[ckey]basics.TealKeyValue)

	pass, err = eval(program, &cx)
	// remove possible leftovers from writing and removing keys
	for k, v := range cx.appEvalDelta.LocalDeltas {
		if len(v) == 0 {
			delete(cx.appEvalDelta.LocalDeltas, k)
		}
	}
	delta = cx.appEvalDelta
	return pass, delta, err
}

// Eval checks to see if a transaction passes logic
// A program passes succesfully if it finishes with one int element on the stack that is non-zero.
func Eval(program []byte, params EvalParams) (pass bool, err error) {
	var cx evalContext
	cx.EvalParams = params
	cx.runModeFlags = runModeSignature
	return eval(program, &cx)
}

// eval impelementation
// A program passes succesfully if it finishes with one int element on the stack that is non-zero.
func eval(program []byte, cx *evalContext) (pass bool, err error) {
	defer func() {
		if x := recover(); x != nil {
			buf := make([]byte, 16*1024)
			stlen := runtime.Stack(buf, false)
			pass = false
			errstr := string(buf[:stlen])
			if cx.EvalParams.Trace != nil {
				if sb, ok := cx.EvalParams.Trace.(*strings.Builder); ok {
					errstr += sb.String()
				}
			}
			err = PanicError{x, errstr}
			cx.EvalParams.log().Errorf("recovered panic in Eval: %s", err)
		}
	}()

	defer func() {
		// Ensure we update the debugger before exiting
		if cx.debugger != nil {
			cx.debugger.complete(cx)
		}
	}()

	if (cx.EvalParams.Proto == nil) || (cx.EvalParams.Proto.LogicSigVersion == 0) {
		err = errLogicSignNotSupported
		return
	}
	if cx.EvalParams.Txn.Lsig.Args != nil && len(cx.EvalParams.Txn.Lsig.Args) > transactions.EvalMaxArgs {
		err = errTooManyArgs
		return
	}

	if len(program) == 0 {
		cx.err = errors.New("invalid program (empty)")
		return false, cx.err
	}
	version, vlen := binary.Uvarint(program)
	if vlen <= 0 {
		cx.err = errors.New("invalid version")
		return false, cx.err
	}
	if version > EvalMaxVersion {
		cx.err = fmt.Errorf("program version %d greater than max supported version %d", version, EvalMaxVersion)
		return false, cx.err
	}
	if version > cx.EvalParams.Proto.LogicSigVersion {
		cx.err = fmt.Errorf("program version %d greater than protocol supported version %d", version, cx.EvalParams.Proto.LogicSigVersion)
		return false, cx.err
	}

	// TODO: if EvalMaxVersion > version, ensure that inaccessible
	// fields as of the program's version are zero or other
	// default value so that no one is hiding unexpected
	// operations from an old program.
	cx.version = version
	cx.pc = vlen
	cx.stack = make([]stackValue, 0, 10)
	cx.program = program
	cx.programHash = crypto.HashObj(Program(program))

	debugURL := os.Getenv("TEAL_DEBUGGER_URL")
	if debugURL != "" {
		cx.debugger = &Debugger{URL: debugURL}
	}

	if cx.debugger != nil {
		cx.debugger.register(cx)
	}

	for (cx.err == nil) && (cx.pc < len(cx.program)) {
		if cx.debugger != nil {
			cx.debugger.update(cx)
		}

		cx.step()
		cx.stepCount++
		if cx.stepCount > len(cx.program) {
			return false, errLoopDetected
		}
		if uint64(cx.cost) > cx.EvalParams.Proto.LogicSigMaxCost {
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

// CheckStateful should be faster than EvalStateful.
// Returns 'cost' which is an estimate of relative execution time.
func CheckStateful(program []byte, params EvalParams) (cost int, err error) {
	params.runModeFlags = runModeApplication
	return check(program, params)
}

// Check should be faster than Eval.
// Returns 'cost' which is an estimate of relative execution time.
func Check(program []byte, params EvalParams) (cost int, err error) {
	params.runModeFlags = runModeSignature
	return check(program, params)
}

func check(program []byte, params EvalParams) (cost int, err error) {
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
		prevpc := cx.pc
		cost += cx.checkStep()
		if cx.pc == prevpc {
			err = fmt.Errorf("pc did not advance, stuck at %d", cx.pc)
			return
		}
	}
	if cx.err != nil {
		err = fmt.Errorf("%3d %s", cx.pc, cx.err)
		return
	}
	return
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
	spec := opsByOpcode[cx.version][opcode]

	if spec.op == nil {
		cx.err = fmt.Errorf("%3d illegal opcode 0x%02x", cx.pc, opcode)
		return
	}
	if (cx.runModeFlags & spec.Modes) == 0 {
		cx.err = fmt.Errorf("%s not allowed in current mode", spec.Name)
		return
	}
	if spec.Version > cx.version {
		cx.err = fmt.Errorf("%s not allowed in program version %d", spec.Name, cx.version)
		return
	}
	argsTypes := spec.Args
	if len(argsTypes) >= 0 {
		// check args for stack underflow and types
		if len(cx.stack) < len(argsTypes) {
			cx.err = fmt.Errorf("stack underflow in %s", spec.Name)
			return
		}
		first := len(cx.stack) - len(argsTypes)
		for i, argType := range argsTypes {
			if !opCompat(argType, cx.stack[first+i].argType()) {
				cx.err = fmt.Errorf("%s arg %d wanted %s but got %s", spec.Name, i, argType.String(), cx.stack[first+i].typeName())
				return
			}
		}
	}
	oz := spec.opSize
	if oz.size != 0 && (cx.pc+oz.size > len(cx.program)) {
		cx.err = fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, spec.Name)
		return
	}
	cx.cost += oz.cost
	spec.op(cx)
	if cx.Trace != nil {
		immArgsString := " "
		if spec.Name != "bnz" {
			for i := 1; i < spec.opSize.size; i++ {
				immArgsString += fmt.Sprintf("0x%02x ", cx.program[cx.pc+i])
			}
		}
		var stackString string
		if len(cx.stack) == 0 {
			stackString = "<empty stack>"
		} else {
			num := 1
			if len(spec.Returns) > 1 {
				num = len(spec.Returns)
			}
			for i := 1; i <= num; i++ {
				stackString += fmt.Sprintf("(%s) ", cx.stack[len(cx.stack)-i].String())
			}
		}
		fmt.Fprintf(cx.Trace, "%3d %s%s=> %s\n", cx.pc, spec.Name, immArgsString, stackString)
	}
	if cx.err != nil {
		return
	}
	if cx.version >= 2 {
		// additional type checks for return values
		if len(cx.stack) < len(spec.Returns) {
			cx.err = fmt.Errorf("%3d %s expected to return %d values but stack has only %d", cx.pc, spec.Name, len(spec.Returns), len(cx.stack))
			return
		}
		for i := 0; i < len(spec.Returns); i++ {
			sp := len(cx.stack) - 1 - i
			stackType := cx.stack[sp].argType()
			retType := spec.Returns[i]
			if !typecheck(retType, stackType) {
				cx.err = fmt.Errorf("%3d %s expected to return %s but actual is %s", cx.pc, spec.Name, retType.String(), stackType.String())
				return
			}
		}
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
	spec := opsByOpcode[cx.version][opcode]
	if spec.op == nil {
		cx.err = fmt.Errorf("%3d illegal opcode 0x%02x", cx.pc, opcode)
		return 1
	}
	if (cx.runModeFlags & spec.Modes) == 0 {
		cx.err = fmt.Errorf("%s not allowed in current mode", spec.Name)
		return
	}
	oz := spec.opSize
	if oz.size != 0 && (cx.pc+oz.size > len(cx.program)) {
		cx.err = fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, spec.Name)
		return 1
	}
	prevpc := cx.pc
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
	if cx.Trace != nil {
		fmt.Fprintf(cx.Trace, "%3d %s\n", prevpc, spec.Name)
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
	cx.err = errors.New("TEAL runtime encountered err opcode")
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
	var branchTooFar bool
	if cx.version >= 2 {
		// branching to exactly the end of the program (target == len(cx.program)), the next pc after the last instruction, is okay and ends normally
		branchTooFar = target > len(cx.program)
	} else {
		branchTooFar = target >= len(cx.program)
	}
	if branchTooFar {
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

func (cx *evalContext) assetHoldingEnumToValue(holding *basics.AssetHolding, field uint64) (sv stackValue, err error) {
	switch AssetHoldingField(field) {
	case AssetBalance:
		sv.Uint = holding.Amount
	case AssetFrozen:
		if holding.Frozen {
			sv.Uint = 1
		} else {
			sv.Uint = 0
		}
	default:
		err = fmt.Errorf("invalid asset holding field %d", field)
		return
	}

	assetHoldingField := AssetHoldingField(field)
	assetHoldingFieldType := AssetHoldingFieldTypes[assetHoldingField]
	if assetHoldingFieldType != sv.argType() {
		err = fmt.Errorf("%s expected field type is %s but got %s", assetHoldingField.String(), assetHoldingFieldType.String(), sv.argType().String())
	}
	return
}

func (cx *evalContext) assetParamsEnumToValue(params *basics.AssetParams, field uint64) (sv stackValue, err error) {
	switch AssetParamsField(field) {
	case AssetTotal:
		sv.Uint = params.Total
	case AssetDecimals:
		sv.Uint = uint64(params.Decimals)
	case AssetDefaultFrozen:
		if params.DefaultFrozen {
			sv.Uint = 1
		} else {
			sv.Uint = 0
		}
	case AssetUnitName:
		sv.Bytes = []byte(params.UnitName)
	case AssetAssetName:
		sv.Bytes = []byte(params.AssetName)
	case AssetURL:
		sv.Bytes = []byte(params.URL)
	case AssetMetadataHash:
		sv.Bytes = params.MetadataHash[:]
	case AssetManager:
		sv.Bytes = params.Manager[:]
	case AssetReserve:
		sv.Bytes = params.Reserve[:]
	case AssetFreeze:
		sv.Bytes = params.Freeze[:]
	case AssetClawback:
		sv.Bytes = params.Clawback[:]
	default:
		err = fmt.Errorf("invalid asset params field %d", field)
		return
	}

	assetParamsField := AssetParamsField(field)
	assetParamsFieldType := AssetParamsFieldTypes[assetParamsField]
	if assetParamsFieldType != sv.argType() {
		err = fmt.Errorf("%s expected field type is %s but got %s", assetParamsField.String(), assetParamsFieldType.String(), sv.argType().String())
	}
	return
}

func (cx *evalContext) txnFieldToStack(txn *transactions.Transaction, field uint64, arrayFieldIdx uint64) (sv stackValue, err error) {
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
	case ApplicationID:
		sv.Uint = uint64(txn.ApplicationID)
	case OnCompletion:
		sv.Uint = uint64(txn.OnCompletion)
	case ApplicationArgs:
		if arrayFieldIdx >= uint64(len(txn.ApplicationArgs)) {
			err = fmt.Errorf("invalid ApplicationArgs index %d", arrayFieldIdx)
			return
		}
		sv.Bytes = []byte(txn.ApplicationArgs[arrayFieldIdx])
	case NumAppArgs:
		sv.Uint = uint64(len(txn.ApplicationArgs))
	case Accounts:
		if arrayFieldIdx == 0 {
			// special case: sender
			sv.Bytes = txn.Sender[:]
		} else {
			if arrayFieldIdx > uint64(len(txn.Accounts)) {
				err = fmt.Errorf("invalid Accounts index %d", arrayFieldIdx)
				return
			}
			sv.Bytes = txn.Accounts[arrayFieldIdx-1][:]
		}
	case NumAccounts:
		sv.Uint = uint64(len(txn.Accounts))
	default:
		err = fmt.Errorf("invalid txn field %d", field)
		return
	}

	txnField := TxnField(field)
	txnFieldType := TxnFieldTypes[txnField]
	if txnFieldType != sv.argType() {
		err = fmt.Errorf("%s expected field type is %s but got %s", txnField.String(), txnFieldType.String(), sv.argType().String())
	}
	return
}

func opTxn(cx *evalContext) {
	field := uint64(cx.program[cx.pc+1])
	var sv stackValue
	var err error
	sv, err = cx.txnFieldToStack(&cx.Txn.Txn, field, 0)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 2
}

func opTxna(cx *evalContext) {
	field := uint64(cx.program[cx.pc+1])
	var sv stackValue
	var err error
	if field != uint64(ApplicationArgs) && field != uint64(Accounts) {
		cx.err = fmt.Errorf("txna unsupported field %d", field)
		return
	}
	arrayFieldIdx := uint64(cx.program[cx.pc+2])
	sv, err = cx.txnFieldToStack(&cx.Txn.Txn, field, arrayFieldIdx)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 3
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
		sv, err = cx.txnFieldToStack(tx, field, 0)
		if err != nil {
			cx.err = err
			return
		}
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 3
}

func opGtxna(cx *evalContext) {
	gtxid := int(uint(cx.program[cx.pc+1]))
	if gtxid >= len(cx.TxnGroup) {
		cx.err = fmt.Errorf("gtxna lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := uint64(cx.program[cx.pc+2])
	var sv stackValue
	var err error
	if TxnField(field) != ApplicationArgs && TxnField(field) != Accounts {
		cx.err = fmt.Errorf("gtxna unsupported field %d", field)
		return
	}
	arrayFieldIdx := uint64(cx.program[cx.pc+3])
	sv, err = cx.txnFieldToStack(tx, field, arrayFieldIdx)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 4
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
	case LogicSigVersion:
		sv.Uint = cx.Proto.LogicSigVersion
	default:
		cx.err = fmt.Errorf("invalid global[%d]", gindex)
		return
	}

	globalField := GlobalField(gindex)
	globalFieldType := GlobalFieldTypes[globalField]
	if globalFieldType != sv.argType() {
		cx.err = fmt.Errorf("%s expected field type is %s but got %s", globalField.String(), globalFieldType.String(), sv.argType().String())
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

func opConcat(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	a := cx.stack[prev].Bytes
	b := cx.stack[last].Bytes
	newlen := len(a) + len(b)
	if newlen > MaxStringSize {
		cx.err = errors.New("cons resulted in string too long")
		return
	}
	newvalue := make([]byte, newlen)
	copy(newvalue, a)
	copy(newvalue[len(a):], b)
	cx.stack[prev].Bytes = newvalue
	cx.stack = cx.stack[:last]
}

func substring(x []byte, start, end int) (out []byte, err error) {
	out = x
	if end <= start {
		err = errors.New("substring end before start")
		return
	}
	if start > len(x) || end > len(x) {
		err = errors.New("substring range beyond length of string")
		return
	}
	out = x[start:end]
	err = nil
	return
}

func opSubstring(cx *evalContext) {
	last := len(cx.stack) - 1
	start := cx.program[cx.pc+1]
	end := cx.program[cx.pc+2]
	cx.stack[last].Bytes, cx.err = substring(cx.stack[last].Bytes, int(start), int(end))
	cx.nextpc = cx.pc + 3
}

const maxInt = int((^uint(0)) >> 1)

func opSubstring3(cx *evalContext) {
	last := len(cx.stack) - 1 // end
	prev := last - 1          // start
	pprev := prev - 1         // bytes
	start := cx.stack[prev].Uint
	end := cx.stack[last].Uint
	if start > uint64(maxInt) || end > uint64(maxInt) {
		cx.err = errors.New("substring range beyond length of string")
		return
	}
	cx.stack[pprev].Bytes, cx.err = substring(cx.stack[pprev].Bytes, int(start), int(end))
	cx.stack = cx.stack[:prev]
}

// getAccountAddrByOffset resolves account offset to address
// it treats offset == 0 as Sender otherwise looks up into Txn.Accounts
func getAccountAddrByOffset(txn *transactions.SignedTxn, accountIdx uint64) (basics.Address, error) {
	var addr basics.Address
	if accountIdx == 0 {
		addr = txn.Txn.Sender
		return addr, nil
	}

	if accountIdx > uint64(len(txn.Txn.Accounts)) {
		return addr, fmt.Errorf("cannot load account[%d] of %d", accountIdx, len(txn.Txn.Accounts))
	}

	addr = txn.Txn.Accounts[accountIdx-1]
	return addr, nil
}

func opBalance(cx *evalContext) {
	last := len(cx.stack) - 1 // account offset

	accountIdx := cx.stack[last].Uint

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := getAccountAddrByOffset(cx.Txn, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	amount, err := cx.Ledger.Balance(addr)
	if err != nil {
		cx.err = fmt.Errorf("failed to fetch balance of %s: %s", addr, err.Error())
		return
	}

	cx.stack[last].Uint = amount
}

func opAppCheckOptedIn(cx *evalContext) {
	last := len(cx.stack) - 1 // app id
	prev := last - 1          // account offset

	appID := cx.stack[last].Uint
	accountIdx := cx.stack[prev].Uint

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := getAccountAddrByOffset(cx.Txn, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	_, err = cx.Ledger.AppLocalState(addr, basics.AppIndex(appID))
	if err != nil {
		cx.stack[prev].Uint = 0
	} else {
		cx.stack[prev].Uint = 1
	}

	cx.stack = cx.stack[:last]
}

func (cx *evalContext) getLocalKV(appID uint64, addr basics.Address) (basics.TealKeyValue, error) {
	tkv, ok := cx.appLocalStateWCache[ckey{appID, addr}]
	if !ok {
		var err error
		tkv, err = cx.Ledger.AppLocalState(addr, basics.AppIndex(appID))
		if err != nil {
			return nil, fmt.Errorf("failed to fetch local state [%s] of the app %d: %s", addr, appID, err.Error())
		}
		cx.appLocalStateRCache[ckey{appID, addr}] = tkv.Clone()
		cx.appLocalStateWCache[ckey{appID, addr}] = tkv
	}
	return tkv, nil
}

func (cx *evalContext) appReadLocalKey(appID uint64, addr basics.Address, key string) (basics.TealValue, bool, error) {
	tkv, err := cx.getLocalKV(appID, addr)
	if err != nil {
		return basics.TealValue{}, false, err
	}
	tv, ok := tkv[string(key)]
	return tv, ok, nil
}

// appWriteLocalKey adds value to StateDelta
func (cx *evalContext) appWriteLocalKey(appID uint64, addr basics.Address, key string, tv basics.TealValue) error {
	tkv, err := cx.getLocalKV(appID, addr)
	if err != nil {
		return err
	}

	// if the value is in cache => it is not changed, no state change
	if v, ok := tkv[key]; ok && tv == v {
		return nil
	}

	// update the value
	tkv[key] = tv

	// and update EvalDelta
	delta, ok := cx.appEvalDelta.LocalDeltas[addr]
	if !ok {
		delta = make(basics.StateDelta)
		cx.appEvalDelta.LocalDeltas[addr] = delta
	}
	delta[key] = tv.ToValueDelta()
	return nil
}

// appDeleteLocalKey deletes a value from the cache and adds it to StateDelta
func (cx *evalContext) appDeleteLocalKey(appID uint64, addr basics.Address, key string) error {
	tkv, err := cx.getLocalKV(appID, addr)
	if err != nil {
		return err
	}

	// if the value is not in the cache => no state change
	if _, ok := tkv[key]; !ok {
		return nil
	}

	// update the value
	delete(tkv, key)

	// the key was not in the state originally then no state change
	if _, ok := cx.appLocalStateRCache[ckey{appID, addr}][key]; !ok {
		delete(cx.appEvalDelta.LocalDeltas[addr], key)
	} else {
		// otherwise update EvalDelta
		delta, ok := cx.appEvalDelta.LocalDeltas[addr]
		if !ok {
			delta = make(basics.StateDelta)
			cx.appEvalDelta.LocalDeltas[addr] = delta
		}
		delta[key] = basics.ValueDelta{Action: basics.DeleteAction}
	}
	return nil
}

func (cx *evalContext) getGlobalKV() (basics.TealKeyValue, error) {
	if cx.appGlobalStateWCache == nil {
		tkv, err := cx.Ledger.AppGlobalState()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch global state of this app: %s", err.Error())
		}
		cx.appGlobalStateRCache = tkv.Clone()
		cx.appGlobalStateWCache = tkv
	}
	return cx.appGlobalStateWCache, nil
}

func (cx *evalContext) appReadGlobalKey(key string) (basics.TealValue, bool, error) {
	tkv, err := cx.getGlobalKV()
	if err != nil {
		return basics.TealValue{}, false, err
	}

	tv, ok := tkv[string(key)]
	return tv, ok, nil
}

// appWriteGlobalKey adds value to StateDelta
func (cx *evalContext) appWriteGlobalKey(key string, tv basics.TealValue) error {
	tkv, err := cx.getGlobalKV()
	if err != nil {
		return err
	}

	// if the value is in cache => it is not changed, no state change
	if v, ok := tkv[key]; ok && tv == v {
		return nil
	}

	// update the value
	tkv[key] = tv

	// and update EvalDelta
	cx.appEvalDelta.GlobalDelta[key] = tv.ToValueDelta()
	return nil
}

// appDeleteGlobalKey deletes a value from the cache and adds it to StateDelta
func (cx *evalContext) appDeleteGlobalKey(key string) error {
	tkv, err := cx.getGlobalKV()
	if err != nil {
		return err
	}

	// if the value is not in the cache => no state change
	if _, ok := tkv[key]; !ok {
		return nil
	}

	// update the value
	delete(tkv, key)

	// the key was not in the state originally then no state change
	if _, ok := cx.appGlobalStateRCache[key]; !ok {
		delete(cx.appEvalDelta.GlobalDelta, key)
	} else {
		// otherwise update EvalDelta
		cx.appEvalDelta.GlobalDelta[key] = basics.ValueDelta{Action: basics.DeleteAction}
	}
	return nil
}

func opAppGetLocalState(cx *evalContext) {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // app id
	pprev := prev - 1         // account offset

	key := cx.stack[last].Bytes
	appID := cx.stack[prev].Uint
	accountIdx := cx.stack[pprev].Uint

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := getAccountAddrByOffset(cx.Txn, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	if appID != 0 && appID == uint64(cx.Txn.Txn.ApplicationID) {
		appID = 0 // 0 is an alias for the current app
	}

	tv, ok, err := cx.appReadLocalKey(appID, addr, string(key))
	if err != nil {
		cx.err = err
		return
	}

	var result stackValue
	var isOk stackValue

	if ok {
		result, err = stackValueFromTealValue(&tv)
		if err != nil {
			cx.err = err
			return
		}
		isOk.Uint = 1
	}
	cx.stack[pprev] = result
	cx.stack[prev] = isOk
	cx.stack = cx.stack[:last]
}

func opAppGetGlobalState(cx *evalContext) {
	// TODO: add Global State access restriction

	last := len(cx.stack) - 1 // state key

	key := cx.stack[last].Bytes

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	tv, ok, err := cx.appReadGlobalKey(string(key))
	if err != nil {
		cx.err = err
		return
	}

	var result stackValue
	var isOk stackValue
	if ok {
		result, err = stackValueFromTealValue(&tv)
		if err != nil {
			cx.err = err
			return
		}
		isOk.Uint = 1
	}

	cx.stack[last] = result
	cx.stack = append(cx.stack, isOk)
}

func opAppPutLocalState(cx *evalContext) {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // state key
	pprev := prev - 1         // account offset

	sv := cx.stack[last]
	key := string(cx.stack[prev].Bytes)
	accountIdx := cx.stack[pprev].Uint
	appID := uint64(0) // 0 is an alias for the current app

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := getAccountAddrByOffset(cx.Txn, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	err = cx.appWriteLocalKey(appID, addr, key, sv.toTealValue())
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = cx.stack[:pprev]
}

func opAppPutGlobalState(cx *evalContext) {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // state key

	sv := cx.stack[last]
	key := string(cx.stack[prev].Bytes)

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	err := cx.appWriteGlobalKey(key, sv.toTealValue())
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = cx.stack[:prev]
}

func opAppDeleteLocalState(cx *evalContext) {
	last := len(cx.stack) - 1 // key
	prev := last - 1          // account offset

	key := string(cx.stack[last].Bytes)
	accountIdx := cx.stack[prev].Uint
	appID := uint64(0) // 0 is an alias for the current app

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := getAccountAddrByOffset(cx.Txn, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	err = cx.appDeleteLocalKey(appID, addr, key)
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = cx.stack[:prev]
}

func opAppDeleteGlobalState(cx *evalContext) {
	last := len(cx.stack) - 1 // key

	key := string(cx.stack[last].Bytes)

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	err := cx.appDeleteGlobalKey(key)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = cx.stack[:last]
}

func opAssetHoldingGet(cx *evalContext) {
	last := len(cx.stack) - 1 // asset id
	prev := last - 1          // account offset

	assetID := cx.stack[last].Uint
	accountIdx := cx.stack[prev].Uint
	fieldIdx := uint64(cx.program[cx.pc+1])

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := getAccountAddrByOffset(cx.Txn, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	var exist uint64 = 0
	var value stackValue
	if holding, err := cx.Ledger.AssetHolding(addr, basics.AssetIndex(assetID)); err == nil {
		// the holding exist, read the value
		exist = 1
		value, err = cx.assetHoldingEnumToValue(&holding, fieldIdx)
		if err != nil {
			cx.err = err
			return
		}
	}

	cx.stack[prev] = value
	cx.stack[last].Uint = exist

	cx.nextpc = cx.pc + 2
}

func opAssetParamsGet(cx *evalContext) {
	last := len(cx.stack) - 1 // asset id
	prev := last - 1          // account offset

	assetID := cx.stack[last].Uint
	accountIdx := cx.stack[prev].Uint
	paramIdx := uint64(cx.program[cx.pc+1])

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := getAccountAddrByOffset(cx.Txn, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	var exist uint64 = 0
	var value stackValue
	if params, err := cx.Ledger.AssetParams(addr, basics.AssetIndex(assetID)); err == nil {
		// params exist, read the value
		exist = 1
		value, err = cx.assetParamsEnumToValue(&params, paramIdx)
		if err != nil {
			cx.err = err
			return
		}
	}

	cx.stack[prev] = value
	cx.stack[last].Uint = exist

	cx.nextpc = cx.pc + 2
}
