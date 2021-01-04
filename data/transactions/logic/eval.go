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
const EvalMaxVersion = LogicVersion

// EvalMaxScratchSize is the maximum number of scratch slots.
const EvalMaxScratchSize = 255

// MaxStringSize is the limit of byte strings created by `concat`
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

// ComputeMinTealVersion calculates the minimum safe TEAL version that may be
// used by a transaction in this group. It is important to prevent
// newly-introduced transaction fields from breaking assumptions made by older
// versions of TEAL. If one of the transactions in a group will execute a TEAL
// program whose version predates a given field, that field must not be set
// anywhere in the transaction group, or the group will be rejected.
func ComputeMinTealVersion(group []transactions.SignedTxn) uint64 {
	var minVersion uint64
	for _, txn := range group {
		if !txn.Txn.RekeyTo.IsZero() {
			if minVersion < rekeyingEnabledVersion {
				minVersion = rekeyingEnabledVersion
			}
		}
		if txn.Txn.Type == protocol.ApplicationCallTx {
			if minVersion < appsEnabledVersion {
				minVersion = appsEnabledVersion
			}
		}
	}
	return minVersion
}

func (sv *stackValue) toTealValue() (tv basics.TealValue) {
	if sv.argType() == StackBytes {
		return basics.TealValue{Type: basics.TealBytesType, Bytes: string(sv.Bytes)}
	}
	return basics.TealValue{Type: basics.TealUintType, Uint: sv.Uint}
}

// LedgerForLogic represents ledger API for Stateful TEAL program
type LedgerForLogic interface {
	Balance(addr basics.Address) (basics.MicroAlgos, error)
	Round() basics.Round
	LatestTimestamp() int64
	AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error)
	AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error)
	AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error)
	AssetParams(assetIdx basics.AssetIndex) (basics.AssetParams, error)
	ApplicationID() basics.AppIndex
	LocalSchema() basics.StateSchema
	GlobalSchema() basics.StateSchema
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

	// optional debugger
	Debugger DebuggerHook

	// MinTealVersion is the minimum allowed TEAL version of this program.
	// The program must reject if its version is less than this version. If
	// MinTealVersion is nil, we will compute it ourselves
	MinTealVersion *uint64

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

type indexedCow struct {
	accountIdx uint64
	cow        *keyValueCow
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

	programHashCached crypto.Digest
	txidCache         map[int]transactions.Txid

	globalStateCow       *keyValueCow
	readOnlyGlobalStates map[uint64]basics.TealKeyValue
	localStateCows       map[basics.Address]*indexedCow
	readOnlyLocalStates  map[ckey]basics.TealKeyValue
	appEvalDelta         basics.EvalDelta

	// Stores state & disassembly for the optional debugger
	debugState DebugState
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
var errLogicSignNotSupported = errors.New("LogicSig not supported")
var errTooManyArgs = errors.New("LogicSig has too many arguments")

// EvalStateful executes stateful TEAL program
func EvalStateful(program []byte, params EvalParams) (pass bool, delta basics.EvalDelta, err error) {
	var cx evalContext
	cx.EvalParams = params
	cx.runModeFlags = runModeApplication

	cx.appEvalDelta = basics.EvalDelta{
		GlobalDelta: make(basics.StateDelta),
		LocalDeltas: make(map[uint64]basics.StateDelta, len(params.Txn.Txn.Accounts)+1),
	}

	// Allocate global delta cow lazily to avoid ledger lookups
	cx.globalStateCow = nil

	// Stores read-only global key/value stores keyed off app
	cx.readOnlyGlobalStates = make(map[uint64]basics.TealKeyValue)

	// Stores state cows for each modified LocalState for this app
	cx.localStateCows = make(map[basics.Address]*indexedCow)

	// Stores read-only local key/value stores keyed off of <addr, app>
	cx.readOnlyLocalStates = make(map[ckey]basics.TealKeyValue)

	// Evaluate the program
	pass, err = eval(program, &cx)

	// Fill in state deltas
	for _, idxCow := range cx.localStateCows {
		if len(idxCow.cow.delta) > 0 {
			cx.appEvalDelta.LocalDeltas[idxCow.accountIdx] = idxCow.cow.delta
		}
	}

	return pass, cx.appEvalDelta, err
}

// Eval checks to see if a transaction passes logic
// A program passes successfully if it finishes with one int element on the stack that is non-zero.
func Eval(program []byte, params EvalParams) (pass bool, err error) {
	var cx evalContext
	cx.EvalParams = params
	cx.runModeFlags = runModeSignature
	return eval(program, &cx)
}

// eval implementation
// A program passes successfully if it finishes with one int element on the stack that is non-zero.
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
		if cx.Debugger != nil {
			errDbg := cx.Debugger.Complete(cx.refreshDebugState())
			if err == nil {
				err = errDbg
			}
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

	var minVersion uint64
	if cx.EvalParams.MinTealVersion == nil {
		minVersion = ComputeMinTealVersion(cx.EvalParams.TxnGroup)
	} else {
		minVersion = *cx.EvalParams.MinTealVersion
	}
	if version < minVersion {
		err = fmt.Errorf("program version must be >= %d for this transaction group, but have version %d", minVersion, version)
		return
	}

	cx.version = version
	cx.pc = vlen
	cx.stack = make([]stackValue, 0, 10)
	cx.program = program

	if cx.Debugger != nil {
		cx.debugState = makeDebugState(cx)
		if err = cx.Debugger.Register(cx.refreshDebugState()); err != nil {
			return
		}
	}

	for (cx.err == nil) && (cx.pc < len(cx.program)) {
		if cx.Debugger != nil {
			if err = cx.Debugger.Update(cx.refreshDebugState()); err != nil {
				return
			}
		}

		cx.step()
		cx.stepCount++
		if cx.stepCount > len(cx.program) {
			return false, errLoopDetected
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

	var minVersion uint64
	if params.MinTealVersion == nil {
		minVersion = ComputeMinTealVersion(params.TxnGroup)
	} else {
		minVersion = *params.MinTealVersion
	}
	if version < minVersion {
		err = fmt.Errorf("program version must be >= %d for this transaction group, but have version %d", minVersion, version)
		return
	}

	cx.version = version
	cx.pc = vlen
	cx.EvalParams = params
	cx.program = program

	for cx.pc < len(cx.program) {
		prevpc := cx.pc
		cost += cx.checkStep()
		if cx.err != nil {
			break
		}
		if cx.pc <= prevpc {
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

func boolToUint(x bool) uint64 {
	if x {
		return 1
	}
	return 0
}

// MaxStackDepth should move to consensus params
const MaxStackDepth = 1000

func (cx *evalContext) step() {
	opcode := cx.program[cx.pc]
	spec := &opsByOpcode[cx.version][opcode]

	// this check also ensures TEAL versioning: v2 opcodes are not in opsByOpcode[1] array
	if spec.op == nil {
		cx.err = fmt.Errorf("%3d illegal opcode 0x%02x", cx.pc, opcode)
		return
	}
	if (cx.runModeFlags & spec.Modes) == 0 {
		cx.err = fmt.Errorf("%s not allowed in current mode", spec.Name)
		return
	}
	argsTypes := spec.Args

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
			// check for nil error here, because we might not return
			// values if we encounter an error in the opcode
			if cx.err == nil {
				if len(cx.stack) < num {
					cx.err = fmt.Errorf("stack underflow: expected %d, have %d", num, len(cx.stack))
					return
				}
				for i := 1; i <= num; i++ {
					stackString += fmt.Sprintf("(%s) ", cx.stack[len(cx.stack)-i].String())
				}
			}
		}
		fmt.Fprintf(cx.Trace, "%3d %s%s=> %s\n", cx.pc, spec.Name, immArgsString, stackString)
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
	spec := &opsByOpcode[cx.version][opcode]
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

func opReturn(cx *evalContext) {
	// Achieve the end condition:
	// Take the last element on the stack and make it the return value (only element on the stack)
	// Move the pc to the end of the program
	last := len(cx.stack) - 1
	cx.stack[0] = cx.stack[last]
	cx.stack = cx.stack[:1]
	cx.nextpc = len(cx.program)
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

func opAddwImpl(x, y uint64) (carry uint64, sum uint64) {
	sum = x + y
	if sum < x {
		carry = 1
	}
	return
}

func opAddw(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	carry, sum := opAddwImpl(cx.stack[prev].Uint, cx.stack[last].Uint)
	cx.stack[prev].Uint = carry
	cx.stack[last].Uint = sum
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
	// cx.stack[last].Uint is not cleared out as optimization
	// stackValue.argType() checks Bytes field first
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

// checks any branch that is {op} {int16 be offset}
func checkBranch(cx *evalContext) int {
	offset := (uint(cx.program[cx.pc+1]) << 8) | uint(cx.program[cx.pc+2])
	if offset > 0x7fff {
		cx.err = fmt.Errorf("branch offset %x too large", offset)
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
		cx.err = errors.New("branch target beyond end of program")
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

func opBz(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.nextpc = cx.pc + 3
	isZero := cx.stack[last].Uint == 0
	cx.stack = cx.stack[:last] // pop
	if isZero {
		offset := (uint(cx.program[cx.pc+1]) << 8) | uint(cx.program[cx.pc+2])
		if offset > 0x7fff {
			cx.err = fmt.Errorf("bz offset %x too large", offset)
			return
		}
		cx.nextpc += int(offset)
	}
}

func opB(cx *evalContext) {
	offset := (uint(cx.program[cx.pc+1]) << 8) | uint(cx.program[cx.pc+2])
	if offset > 0x7fff {
		cx.err = fmt.Errorf("b offset %x too large", offset)
		return
	}
	cx.nextpc = cx.pc + 3 + int(offset)
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

func opDup2(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack = append(cx.stack, cx.stack[prev:]...)
}

func (cx *evalContext) assetHoldingEnumToValue(holding *basics.AssetHolding, field uint64) (sv stackValue, err error) {
	switch AssetHoldingField(field) {
	case AssetBalance:
		sv.Uint = holding.Amount
	case AssetFrozen:
		sv.Uint = boolToUint(holding.Frozen)
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
		sv.Uint = boolToUint(params.DefaultFrozen)
	case AssetUnitName:
		sv.Bytes = []byte(params.UnitName)
	case AssetName:
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

// TxnFieldToTealValue is a thin wrapper for txnFieldToStack for external use
func TxnFieldToTealValue(txn *transactions.Transaction, groupIndex int, field TxnField, arrayFieldIdx uint64) (basics.TealValue, error) {
	cx := evalContext{EvalParams: EvalParams{GroupIndex: groupIndex}}
	sv, err := cx.txnFieldToStack(txn, field, arrayFieldIdx, groupIndex)
	return sv.toTealValue(), err
}

func (cx *evalContext) getTxID(txn *transactions.Transaction, groupIndex int) transactions.Txid {
	// Initialize txidCache if necessary
	if cx.txidCache == nil {
		cx.txidCache = make(map[int]transactions.Txid, len(cx.TxnGroup))
	}

	// Hashes are expensive, so we cache computed TxIDs
	txid, ok := cx.txidCache[groupIndex]
	if !ok {
		txid = txn.ID()
		cx.txidCache[groupIndex] = txid
	}

	return txid
}

func (cx *evalContext) txnFieldToStack(txn *transactions.Transaction, field TxnField, arrayFieldIdx uint64, groupIndex int) (sv stackValue, err error) {
	err = nil
	switch field {
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
		sv.Uint = txnTypeIndexes[string(txn.Type)]
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
		sv.Uint = uint64(groupIndex)
	case TxID:
		txid := cx.getTxID(txn, groupIndex)
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
		sv.Bytes = nilToEmpty(txn.ApplicationArgs[arrayFieldIdx])
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
	case ApprovalProgram:
		sv.Bytes = nilToEmpty(txn.ApprovalProgram)
	case ClearStateProgram:
		sv.Bytes = nilToEmpty(txn.ClearStateProgram)
	case RekeyTo:
		sv.Bytes = txn.RekeyTo[:]
	case ConfigAsset:
		sv.Uint = uint64(txn.ConfigAsset)
	case ConfigAssetTotal:
		sv.Uint = uint64(txn.AssetParams.Total)
	case ConfigAssetDecimals:
		sv.Uint = uint64(txn.AssetParams.Decimals)
	case ConfigAssetDefaultFrozen:
		sv.Uint = boolToUint(txn.AssetParams.DefaultFrozen)
	case ConfigAssetUnitName:
		sv.Bytes = nilToEmpty([]byte(txn.AssetParams.UnitName))
	case ConfigAssetName:
		sv.Bytes = nilToEmpty([]byte(txn.AssetParams.AssetName))
	case ConfigAssetURL:
		sv.Bytes = nilToEmpty([]byte(txn.AssetParams.URL))
	case ConfigAssetMetadataHash:
		sv.Bytes = nilToEmpty(txn.AssetParams.MetadataHash[:])
	case ConfigAssetManager:
		sv.Bytes = txn.AssetParams.Manager[:]
	case ConfigAssetReserve:
		sv.Bytes = txn.AssetParams.Reserve[:]
	case ConfigAssetFreeze:
		sv.Bytes = txn.AssetParams.Freeze[:]
	case ConfigAssetClawback:
		sv.Bytes = txn.AssetParams.Clawback[:]
	case FreezeAsset:
		sv.Uint = uint64(txn.FreezeAsset)
	case FreezeAssetAccount:
		sv.Bytes = txn.FreezeAccount[:]
	case FreezeAssetFrozen:
		sv.Uint = boolToUint(txn.AssetFrozen)
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
	field := TxnField(uint64(cx.program[cx.pc+1]))
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if ok {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	var sv stackValue
	var err error
	sv, err = cx.txnFieldToStack(&cx.Txn.Txn, field, 0, cx.GroupIndex)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 2
}

func opTxna(cx *evalContext) {
	field := TxnField(uint64(cx.program[cx.pc+1]))
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if !ok {
		cx.err = fmt.Errorf("txna unsupported field %d", field)
		return
	}
	var sv stackValue
	var err error
	arrayFieldIdx := uint64(cx.program[cx.pc+2])
	sv, err = cx.txnFieldToStack(&cx.Txn.Txn, field, arrayFieldIdx, cx.GroupIndex)
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
	field := TxnField(uint64(cx.program[cx.pc+2]))
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if ok {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	var sv stackValue
	var err error
	if TxnField(field) == GroupIndex {
		// GroupIndex; asking this when we just specified it is _dumb_, but oh well
		sv.Uint = uint64(gtxid)
	} else {
		sv, err = cx.txnFieldToStack(tx, field, 0, gtxid)
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
	field := TxnField(uint64(cx.program[cx.pc+2]))
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if !ok {
		cx.err = fmt.Errorf("gtxna unsupported field %d", field)
		return
	}
	var sv stackValue
	var err error
	arrayFieldIdx := uint64(cx.program[cx.pc+3])
	sv, err = cx.txnFieldToStack(tx, field, arrayFieldIdx, gtxid)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 4
}

func (cx *evalContext) getRound() (rnd uint64, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}
	return uint64(cx.Ledger.Round()), nil
}

func (cx *evalContext) getLatestTimestamp() (timestamp uint64, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}
	ts := cx.Ledger.LatestTimestamp()
	if ts < 0 {
		err = fmt.Errorf("latest timestamp %d < 0", ts)
		return
	}
	return uint64(ts), nil
}

func (cx *evalContext) getApplicationID() (rnd uint64, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}
	return uint64(cx.Ledger.ApplicationID()), nil
}

var zeroAddress basics.Address

func (cx *evalContext) globalFieldToStack(field GlobalField) (sv stackValue, err error) {
	switch field {
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
	case Round:
		sv.Uint, err = cx.getRound()
	case LatestTimestamp:
		sv.Uint, err = cx.getLatestTimestamp()
	case CurrentApplicationID:
		sv.Uint, err = cx.getApplicationID()
	default:
		err = fmt.Errorf("invalid global[%d]", field)
	}
	return sv, err
}

func opGlobal(cx *evalContext) {
	gindex := uint64(cx.program[cx.pc+1])
	globalField := GlobalField(gindex)
	fs, ok := globalFieldSpecByField[globalField]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid global[%d]", globalField)
		return
	}
	if (cx.runModeFlags & fs.mode) == 0 {
		cx.err = fmt.Errorf("global[%d] not allowed in current mode", globalField)
		return
	}

	sv, err := cx.globalFieldToStack(globalField)
	if err != nil {
		cx.err = err
		return
	}

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

// programHash lets us lazily compute H(cx.program)
func (cx *evalContext) programHash() crypto.Digest {
	if cx.programHashCached == (crypto.Digest{}) {
		cx.programHashCached = crypto.HashObj(Program(cx.program))
	}
	return cx.programHashCached
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

	msg := Msg{ProgramHash: cx.programHash(), Data: cx.stack[pprev].Bytes}
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
		cx.err = errors.New("concat resulted in string too long")
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
	if end < start {
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

func opSubstring3(cx *evalContext) {
	last := len(cx.stack) - 1 // end
	prev := last - 1          // start
	pprev := prev - 1         // bytes
	start := cx.stack[prev].Uint
	end := cx.stack[last].Uint
	if start > math.MaxInt32 || end > math.MaxInt32 {
		cx.err = errors.New("substring range beyond length of string")
		return
	}
	cx.stack[pprev].Bytes, cx.err = substring(cx.stack[pprev].Bytes, int(start), int(end))
	cx.stack = cx.stack[:prev]
}

func opBalance(cx *evalContext) {
	last := len(cx.stack) - 1 // account offset

	accountIdx := cx.stack[last].Uint

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, err := cx.Txn.Txn.AddressByIndex(accountIdx, cx.Txn.Txn.Sender)
	if err != nil {
		cx.err = err
		return
	}

	microAlgos, err := cx.Ledger.Balance(addr)
	if err != nil {
		cx.err = fmt.Errorf("failed to fetch balance of %v: %s", addr, err.Error())
		return
	}

	cx.stack[last].Uint = microAlgos.Raw
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

	addr, err := cx.Txn.Txn.AddressByIndex(accountIdx, cx.Txn.Txn.Sender)
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

func (cx *evalContext) getReadOnlyLocalState(appID uint64, accountIdx uint64) (basics.TealKeyValue, error) {
	// Convert the account offset to an address
	addr, err := cx.Txn.Txn.AddressByIndex(accountIdx, cx.Txn.Txn.Sender)
	if err != nil {
		return nil, err
	}

	kvIdx := ckey{appID, addr}
	localKV, ok := cx.readOnlyLocalStates[kvIdx]
	if !ok {
		var err error
		localKV, err = cx.Ledger.AppLocalState(addr, basics.AppIndex(appID))
		if err != nil {
			return nil, fmt.Errorf("failed to fetch app local state for acct %v, app %d: %v", addr, appID, err)
		}
		cx.readOnlyLocalStates[kvIdx] = localKV
	}
	return localKV, nil
}

func (cx *evalContext) getLocalStateCow(accountIdx uint64) (*keyValueCow, error) {
	// Convert the account offset to an address
	addr, err := cx.Txn.Txn.AddressByIndex(accountIdx, cx.Txn.Txn.Sender)
	if err != nil {
		return nil, err
	}

	// We key localStateCows by address and not accountIdx, because
	// multiple accountIdxs may refer to the same address
	idxCow, ok := cx.localStateCows[addr]
	if !ok {
		// No cached cow for this address. Make one.
		localKV, err := cx.Ledger.AppLocalState(addr, basics.AppIndex(cx.Txn.Txn.ApplicationID))
		if err != nil {
			return nil, fmt.Errorf("failed to fetch app local state for acct %v: %v", addr, err)
		}

		localDelta := make(basics.StateDelta)
		kvCow, err := makeKeyValueCow(localKV, localDelta, cx.Ledger.LocalSchema(), cx.Proto)
		if err != nil {
			return nil, err
		}
		idxCow = &indexedCow{accountIdx, kvCow}
		cx.localStateCows[addr] = idxCow
	}
	return idxCow.cow, nil
}

func (cx *evalContext) appReadLocalKey(appID uint64, accountIdx uint64, key string) (basics.TealValue, bool, error) {
	// If this is for the application mentioned in the transaction header,
	// return the result from a LocalState cow, since we may have written
	// to it
	if appID == 0 || appID == uint64(cx.Ledger.ApplicationID()) {
		kvCow, err := cx.getLocalStateCow(accountIdx)
		if err != nil {
			return basics.TealValue{}, false, err
		}
		tv, ok := kvCow.read(key)
		return tv, ok, nil
	}

	// Otherwise, the state is read only, so return from the read only cache
	kv, err := cx.getReadOnlyLocalState(appID, accountIdx)
	if err != nil {
		return basics.TealValue{}, false, err
	}
	tv, ok := kv[key]
	return tv, ok, nil
}

// appWriteLocalKey writes value to local key/value cow
func (cx *evalContext) appWriteLocalKey(accountIdx uint64, key string, tv basics.TealValue) error {
	kvCow, err := cx.getLocalStateCow(accountIdx)
	if err != nil {
		return err
	}
	return kvCow.write(key, tv)
}

// appDeleteLocalKey deletes a value from the key/value cow
func (cx *evalContext) appDeleteLocalKey(accountIdx uint64, key string) error {
	kvCow, err := cx.getLocalStateCow(accountIdx)
	if err != nil {
		return err
	}
	return kvCow.del(key)
}

func (cx *evalContext) getReadOnlyGlobalState(appID uint64) (basics.TealKeyValue, error) {
	globalKV, ok := cx.readOnlyGlobalStates[appID]
	if !ok {
		var err error
		globalKV, err = cx.Ledger.AppGlobalState(basics.AppIndex(appID))
		if err != nil {
			return nil, fmt.Errorf("failed to fetch global state for app %d: %v", appID, err)
		}
		cx.readOnlyGlobalStates[appID] = globalKV
	}
	return globalKV, nil
}

func (cx *evalContext) getGlobalStateCow() (*keyValueCow, error) {
	if cx.globalStateCow == nil {
		appIdx := cx.Ledger.ApplicationID()
		globalKV, err := cx.Ledger.AppGlobalState(appIdx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch global state: %v", err)
		}
		cx.globalStateCow, err = makeKeyValueCow(globalKV, cx.appEvalDelta.GlobalDelta, cx.Ledger.GlobalSchema(), cx.Proto)
		if err != nil {
			return nil, err
		}
	}
	return cx.globalStateCow, nil
}

func (cx *evalContext) appReadGlobalKey(foreignAppsIndex uint64, key string) (basics.TealValue, bool, error) {
	// If this is for the current app (ForeignApps index zero),
	// return the result from a GlobalState cow, since we may have written
	// to it
	if foreignAppsIndex > uint64(len(cx.Txn.Txn.ForeignApps)) {
		err := fmt.Errorf("invalid ForeignApps index %d", foreignAppsIndex)
		return basics.TealValue{}, false, err
	}

	var appIdx basics.AppIndex
	if foreignAppsIndex == 0 {
		appIdx = 0
	} else {
		appIdx = cx.Txn.Txn.ForeignApps[foreignAppsIndex-1]
		if appIdx == cx.Ledger.ApplicationID() {
			appIdx = 0
		}
	}
	if appIdx == 0 {
		kvCow, err := cx.getGlobalStateCow()
		if err != nil {
			return basics.TealValue{}, false, err
		}
		tv, ok := kvCow.read(key)
		return tv, ok, nil
	}

	// Otherwise, the state is read only, so return from the read only cache
	kv, err := cx.getReadOnlyGlobalState(uint64(appIdx))
	if err != nil {
		return basics.TealValue{}, false, err
	}
	tv, ok := kv[key]
	return tv, ok, nil
}

// appWriteGlobalKey adds value to StateDelta
func (cx *evalContext) appWriteGlobalKey(key string, tv basics.TealValue) error {
	kvCow, err := cx.getGlobalStateCow()
	if err != nil {
		return err
	}
	return kvCow.write(key, tv)
}

// appDeleteGlobalKey deletes a value from the cache and adds it to StateDelta
func (cx *evalContext) appDeleteGlobalKey(key string) error {
	kvCow, err := cx.getGlobalStateCow()
	if err != nil {
		return err
	}
	return kvCow.del(key)
}

func opAppGetLocalState(cx *evalContext) {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // account offset

	key := cx.stack[last].Bytes
	accountIdx := cx.stack[prev].Uint

	var appID uint64 = 0
	result, _, err := opAppGetLocalStateImpl(cx, appID, key, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	cx.stack[prev] = result
	cx.stack = cx.stack[:last]
}

func opAppGetLocalStateEx(cx *evalContext) {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // app id
	pprev := prev - 1         // account offset

	key := cx.stack[last].Bytes
	appID := cx.stack[prev].Uint
	accountIdx := cx.stack[pprev].Uint

	result, ok, err := opAppGetLocalStateImpl(cx, appID, key, accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	var isOk stackValue
	if ok {
		isOk.Uint = 1
	}

	cx.stack[pprev] = result
	cx.stack[prev] = isOk
	cx.stack = cx.stack[:last]
}

func opAppGetLocalStateImpl(cx *evalContext, appID uint64, key []byte, accountIdx uint64) (result stackValue, ok bool, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}

	tv, ok, err := cx.appReadLocalKey(appID, accountIdx, string(key))
	if err != nil {
		cx.err = err
		return
	}

	if ok {
		result, err = stackValueFromTealValue(&tv)
	}
	return
}

func opAppGetGlobalStateImpl(cx *evalContext, appIndex uint64, key []byte) (result stackValue, ok bool, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}

	tv, ok, err := cx.appReadGlobalKey(appIndex, string(key))
	if err != nil {
		return
	}

	if ok {
		result, err = stackValueFromTealValue(&tv)
	}
	return
}

func opAppGetGlobalState(cx *evalContext) {
	last := len(cx.stack) - 1 // state key

	key := cx.stack[last].Bytes

	var index uint64 = 0 // index in txn.ForeignApps
	result, _, err := opAppGetGlobalStateImpl(cx, index, key)
	if err != nil {
		cx.err = err
		return
	}

	cx.stack[last] = result
}

func opAppGetGlobalStateEx(cx *evalContext) {
	last := len(cx.stack) - 1 // state key
	prev := last - 1

	key := cx.stack[last].Bytes
	index := cx.stack[prev].Uint // index in txn.ForeignApps

	result, ok, err := opAppGetGlobalStateImpl(cx, index, key)
	if err != nil {
		cx.err = err
		return
	}

	var isOk stackValue
	if ok {
		isOk.Uint = 1
	}

	cx.stack[prev] = result
	cx.stack[last] = isOk
}

func opAppPutLocalState(cx *evalContext) {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // state key
	pprev := prev - 1         // account offset

	sv := cx.stack[last]
	key := string(cx.stack[prev].Bytes)
	accountIdx := cx.stack[pprev].Uint

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	err := cx.appWriteLocalKey(accountIdx, key, sv.toTealValue())
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

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	err := cx.appDeleteLocalKey(accountIdx, key)
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

	addr, err := cx.Txn.Txn.AddressByIndex(accountIdx, cx.Txn.Txn.Sender)
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
	last := len(cx.stack) - 1 // foreign asset id

	foreignAssetsIndex := cx.stack[last].Uint
	paramIdx := uint64(cx.program[cx.pc+1])

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	if foreignAssetsIndex >= uint64(len(cx.Txn.Txn.ForeignAssets)) {
		cx.err = fmt.Errorf("invalid ForeignAssets index %d", foreignAssetsIndex)
		return
	}
	assetID := cx.Txn.Txn.ForeignAssets[foreignAssetsIndex]

	var exist uint64 = 0
	var value stackValue
	if params, err := cx.Ledger.AssetParams(basics.AssetIndex(assetID)); err == nil {
		// params exist, read the value
		exist = 1
		value, err = cx.assetParamsEnumToValue(&params, paramIdx)
		if err != nil {
			cx.err = err
			return
		}
	}

	cx.stack[last] = value
	cx.stack = append(cx.stack, stackValue{Uint: exist})

	cx.nextpc = cx.pc + 2
}
