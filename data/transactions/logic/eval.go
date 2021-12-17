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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"runtime"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// EvalMaxVersion is the max version we can interpret and run
const EvalMaxVersion = LogicVersion

// The constants below control TEAL opcodes evaluation and MAY NOT be changed
// without moving them into consensus parameters.

// MaxStringSize is the limit of byte strings created by `concat`
const MaxStringSize = 4096

// MaxByteMathSize is the limit of byte strings supplied as input to byte math opcodes
const MaxByteMathSize = 64

// MaxLogSize is the limit of total log size from n log calls in a program
const MaxLogSize = 1024

// MaxLogCalls is the limit of total log calls during a program execution
const MaxLogCalls = 32

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

func (sv *stackValue) clone() stackValue {
	if sv.Bytes != nil {
		// clone stack value if Bytes
		bytesClone := make([]byte, len(sv.Bytes))
		copy(bytesClone, sv.Bytes)
		return stackValue{Bytes: bytesClone}
	}
	// otherwise no cloning is needed if Uint
	return stackValue{Uint: sv.Uint}
}

func (sv *stackValue) String() string {
	if sv.Bytes != nil {
		return hex.EncodeToString(sv.Bytes)
	}
	return fmt.Sprintf("%d 0x%x", sv.Uint, sv.Uint)
}

func (sv *stackValue) address() (addr basics.Address, err error) {
	if len(sv.Bytes) != len(addr) {
		return basics.Address{}, errors.New("not an address")
	}
	copy(addr[:], sv.Bytes)
	return
}

func (sv *stackValue) uint() (uint64, error) {
	if sv.Bytes != nil {
		return 0, errors.New("not a uint64")
	}
	return sv.Uint, nil
}

func (sv *stackValue) bool() (bool, error) {
	u64, err := sv.uint()
	if err != nil {
		return false, err
	}
	switch u64 {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("boolean is neither 1 nor 0: %d", u64)
	}
}

func (sv *stackValue) string(limit int) (string, error) {
	if sv.Bytes == nil {
		return "", errors.New("not a byte array")
	}
	if len(sv.Bytes) > limit {
		return "", errors.New("value is too long")
	}
	return string(sv.Bytes), nil
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
	MinBalance(addr basics.Address, proto *config.ConsensusParams) (basics.MicroAlgos, error)
	Authorizer(addr basics.Address) (basics.Address, error)
	Round() basics.Round
	LatestTimestamp() int64

	AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error)
	AssetParams(aidx basics.AssetIndex) (basics.AssetParams, basics.Address, error)
	AppParams(aidx basics.AppIndex) (basics.AppParams, basics.Address, error)
	ApplicationID() basics.AppIndex
	OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error)
	GetCreatableID(groupIdx int) basics.CreatableIndex

	GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (value basics.TealValue, exists bool, err error)
	SetLocal(addr basics.Address, key string, value basics.TealValue, accountIdx uint64) error
	DelLocal(addr basics.Address, key string, accountIdx uint64) error

	GetGlobal(appIdx basics.AppIndex, key string) (value basics.TealValue, exists bool, err error)
	SetGlobal(key string, value basics.TealValue) error
	DelGlobal(key string) error

	GetDelta(txn *transactions.Transaction) (evalDelta transactions.EvalDelta, err error)

	Perform(txn *transactions.Transaction, spec transactions.SpecialAddresses) (transactions.ApplyData, error)
}

// EvalSideEffects contains data returned from evaluation
type EvalSideEffects struct {
	scratchSpace scratchSpace
}

// MakePastSideEffects allocates and initializes a slice of EvalSideEffects of length `size`
func MakePastSideEffects(size int) (pastSideEffects []EvalSideEffects) {
	pastSideEffects = make([]EvalSideEffects, size)
	for j := range pastSideEffects {
		pastSideEffects[j] = EvalSideEffects{}
	}
	return
}

// getScratchValue loads and clones a stackValue
// The value is cloned so the original bytes are protected from changes
func (se *EvalSideEffects) getScratchValue(scratchPos uint8) stackValue {
	return se.scratchSpace[scratchPos].clone()
}

// setScratchSpace stores the scratch space
func (se *EvalSideEffects) setScratchSpace(scratch scratchSpace) {
	se.scratchSpace = scratch
}

// EvalParams contains data that comes into condition evaluation.
type EvalParams struct {
	// the transaction being evaluated
	Txn *transactions.SignedTxn

	Proto *config.ConsensusParams

	Trace io.Writer

	TxnGroup []transactions.SignedTxn

	// GroupIndex should point to Txn within TxnGroup
	GroupIndex uint64

	PastSideEffects []EvalSideEffects

	Logger logging.Logger

	Ledger LedgerForLogic

	// optional debugger
	Debugger DebuggerHook

	// MinTealVersion is the minimum allowed TEAL version of this program.
	// The program must reject if its version is less than this version. If
	// MinTealVersion is nil, we will compute it ourselves
	MinTealVersion *uint64

	// Amount "overpaid" by the top-level transactions of the
	// group.  Often 0.  When positive, it is spent by application
	// actions.  Shared value across a group's txns, so that it
	// can be updated. nil is interpretted as 0.
	FeeCredit *uint64

	Specials *transactions.SpecialAddresses

	// determines eval mode: runModeSignature or runModeApplication
	runModeFlags runMode

	// Total pool of app call budget in a group transaction
	PooledApplicationBudget *uint64
}

type opEvalFunc func(cx *EvalContext)
type opCheckFunc func(cx *EvalContext) error

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

func (ep EvalParams) budget() int {
	if ep.runModeFlags == runModeSignature {
		return int(ep.Proto.LogicSigMaxCost)
	}
	if ep.Proto.EnableAppCostPooling && ep.PooledApplicationBudget != nil {
		return int(*ep.PooledApplicationBudget)
	}
	return ep.Proto.MaxAppProgramCost
}

func (ep EvalParams) log() logging.Logger {
	if ep.Logger != nil {
		return ep.Logger
	}
	return logging.Base()
}

type scratchSpace = [256]stackValue

// EvalContext is the execution context of AVM bytecode.  It contains
// the full state of the running program, and tracks some of the
// things that the program has been done, like log message and inner
// transactions.
type EvalContext struct {
	EvalParams

	stack     []stackValue
	callstack []int

	program []byte
	pc      int
	nextpc  int
	err     error
	intc    []uint64
	bytec   [][]byte
	version uint64
	scratch scratchSpace

	subtxns []transactions.SignedTxn // place to build for itxn_submit
	// Previous transactions Performed() and their effects
	InnerTxns []transactions.SignedTxnWithAD

	cost    int // cost incurred so far
	Logs    []string
	logSize int // total log size so far

	// Set of PC values that branches we've seen so far might
	// go. So, if checkStep() skips one, that branch is trying to
	// jump into the middle of a multibyte instruction
	branchTargets map[int]bool

	// Set of PC values that we have begun a checkStep() with. So
	// if a back jump is going to a value that isn't here, it's
	// jumping into the middle of multibyte instruction.
	instructionStarts map[int]bool

	programHashCached crypto.Digest
	txidCache         map[uint64]transactions.Txid
	appAddrCache      map[basics.AppIndex]basics.Address

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

var errLogicSigNotSupported = errors.New("LogicSig not supported")
var errTooManyArgs = errors.New("LogicSig has too many arguments")

// EvalStatefulCx executes stateful TEAL program
func EvalStatefulCx(program []byte, params EvalParams) (bool, *EvalContext, error) {
	var cx EvalContext
	cx.EvalParams = params
	cx.runModeFlags = runModeApplication
	pass, err := eval(program, &cx)

	// The following two updates show a need for something like a
	// GroupEvalContext, as we are currently tucking things into the
	// EvalParams so that they are available to later calls.

	// update pooled budget
	if cx.Proto.EnableAppCostPooling && cx.PooledApplicationBudget != nil {
		// if eval passes, then budget is always greater than cost, so should not have underflow
		*cx.PooledApplicationBudget = basics.SubSaturate(*cx.PooledApplicationBudget, uint64(cx.cost))
	}
	// update side effects
	cx.PastSideEffects[cx.GroupIndex].setScratchSpace(cx.scratch)

	return pass, &cx, err
}

// EvalStateful is a lighter weight interface that doesn't return the EvalContext
func EvalStateful(program []byte, params EvalParams) (bool, error) {
	pass, _, err := EvalStatefulCx(program, params)
	return pass, err
}

// Eval checks to see if a transaction passes logic
// A program passes successfully if it finishes with one int element on the stack that is non-zero.
func Eval(program []byte, params EvalParams) (pass bool, err error) {
	var cx EvalContext
	cx.EvalParams = params
	cx.runModeFlags = runModeSignature
	return eval(program, &cx)
}

// eval implementation
// A program passes successfully if it finishes with one int element on the stack that is non-zero.
func eval(program []byte, cx *EvalContext) (pass bool, err error) {
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
			cx.EvalParams.log().Errorf("recovered panic in Eval: %w", err)
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
		err = errLogicSigNotSupported
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
		cx.err = fmt.Errorf("program version must be >= %d for this transaction group, but have version %d", minVersion, version)
		return false, cx.err
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

// CheckStateful should be faster than EvalStateful.  It can perform
// static checks and reject programs that are invalid. Prior to v4,
// these static checks include a cost estimate that must be low enough
// (controlled by params.Proto).
func CheckStateful(program []byte, params EvalParams) error {
	params.runModeFlags = runModeApplication
	return check(program, params)
}

// Check should be faster than Eval.  It can perform static checks and
// reject programs that are invalid. Prior to v4, these static checks
// include a cost estimate that must be low enough (controlled by
// params.Proto).
func Check(program []byte, params EvalParams) error {
	params.runModeFlags = runModeSignature
	return check(program, params)
}

func check(program []byte, params EvalParams) (err error) {
	defer func() {
		if x := recover(); x != nil {
			buf := make([]byte, 16*1024)
			stlen := runtime.Stack(buf, false)
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
		return errLogicSigNotSupported
	}
	version, vlen := binary.Uvarint(program)
	if vlen <= 0 {
		return errors.New("invalid version")
	}
	if version > EvalMaxVersion {
		return fmt.Errorf("program version %d greater than max supported version %d", version, EvalMaxVersion)
	}
	if version > params.Proto.LogicSigVersion {
		return fmt.Errorf("program version %d greater than protocol supported version %d", version, params.Proto.LogicSigVersion)
	}

	var minVersion uint64
	if params.MinTealVersion == nil {
		minVersion = ComputeMinTealVersion(params.TxnGroup)
	} else {
		minVersion = *params.MinTealVersion
	}
	if version < minVersion {
		return fmt.Errorf("program version must be >= %d for this transaction group, but have version %d", minVersion, version)
	}

	var cx EvalContext
	cx.version = version
	cx.pc = vlen
	cx.EvalParams = params
	cx.program = program
	cx.branchTargets = make(map[int]bool)
	cx.instructionStarts = make(map[int]bool)

	maxCost := params.budget()
	if version >= backBranchEnabledVersion {
		maxCost = math.MaxInt32
	}
	staticCost := 0
	for cx.pc < len(cx.program) {
		prevpc := cx.pc
		stepCost, err := cx.checkStep()
		if err != nil {
			return fmt.Errorf("pc=%3d %w", cx.pc, err)
		}
		staticCost += stepCost
		if staticCost > maxCost {
			return fmt.Errorf("pc=%3d static cost budget of %d exceeded", cx.pc, maxCost)
		}
		if cx.pc <= prevpc {
			// Recall, this is advancing through opcodes
			// without evaluation. It always goes forward,
			// even if we're in v4 and the jump would go
			// back.
			return fmt.Errorf("pc did not advance, stuck at %d", cx.pc)
		}
	}
	return nil
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

func (cx *EvalContext) step() {
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

	// check args for stack underflow and types
	if len(cx.stack) < len(spec.Args) {
		cx.err = fmt.Errorf("stack underflow in %s", spec.Name)
		return
	}
	first := len(cx.stack) - len(spec.Args)
	for i, argType := range spec.Args {
		if !opCompat(argType, cx.stack[first+i].argType()) {
			cx.err = fmt.Errorf("%s arg %d wanted %s but got %s", spec.Name, i, argType.String(), cx.stack[first+i].typeName())
			return
		}
	}

	deets := spec.Details
	if deets.Size != 0 && (cx.pc+deets.Size > len(cx.program)) {
		cx.err = fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, spec.Name)
		return
	}
	cx.cost += deets.Cost
	if cx.cost > cx.budget() {
		cx.err = fmt.Errorf("pc=%3d dynamic cost budget exceeded, executing %s: remaining budget is %d but program cost was %d",
			cx.pc, spec.Name, cx.budget(), cx.cost)
		return
	}

	preheight := len(cx.stack)
	spec.op(cx)

	if cx.err == nil {
		postheight := len(cx.stack)
		if spec.Name != "return" && postheight-preheight != len(spec.Returns)-len(spec.Args) {
			cx.err = fmt.Errorf("%s changed stack height improperly %d != %d",
				spec.Name, postheight-preheight, len(spec.Returns)-len(spec.Args))
			return
		}
		first = postheight - len(spec.Returns)
		for i, argType := range spec.Returns {
			stackType := cx.stack[first+i].argType()
			if !opCompat(argType, stackType) {
				cx.err = fmt.Errorf("%s produced %s but intended %s", spec.Name, cx.stack[first+i].typeName(), argType.String())
				return
			}
			if stackType == StackBytes && len(cx.stack[first+i].Bytes) > MaxStringSize {
				cx.err = fmt.Errorf("%s produced a too big (%d) byte-array", spec.Name, len(cx.stack[first+i].Bytes))
				return
			}
		}
	}

	if cx.Trace != nil {
		// This code used to do a little disassembly on its
		// own, but then it missed out on some nuances like
		// getting the field names instead of constants in the
		// txn opcodes.  To get them, we conjure up a
		// disassembleState from the current execution state,
		// and use the existing disassembly routines.  It
		// feels a little funny to make a disassembleState
		// right here, rather than build it as we go, or
		// perhaps we could have an interface that allows
		// disassembly to use the cx directly.  But for now,
		// we don't want to worry about the dissassembly
		// routines mucking about in the execution context
		// (changing the pc, for example) and this gives a big
		// improvement of dryrun readability
		dstate := &disassembleState{program: cx.program, pc: cx.pc, numericTargets: true, intc: cx.intc, bytec: cx.bytec}
		var sourceLine string
		sourceLine, err := spec.dis(dstate, spec)
		if err != nil {
			if cx.err == nil { // don't override an error from evaluation
				cx.err = err
			}
			return
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
		fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, sourceLine, stackString)
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
		cx.pc += deets.Size
	}
}

func (cx *EvalContext) checkStep() (int, error) {
	cx.instructionStarts[cx.pc] = true
	opcode := cx.program[cx.pc]
	spec := &opsByOpcode[cx.version][opcode]
	if spec.op == nil {
		return 0, fmt.Errorf("%3d illegal opcode 0x%02x", cx.pc, opcode)
	}
	if (cx.runModeFlags & spec.Modes) == 0 {
		return 0, fmt.Errorf("%s not allowed in current mode", spec.Name)
	}
	deets := spec.Details
	if deets.Size != 0 && (cx.pc+deets.Size > len(cx.program)) {
		return 0, fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, spec.Name)
	}
	prevpc := cx.pc
	if deets.checkFunc != nil {
		err := deets.checkFunc(cx)
		if err != nil {
			return 0, err
		}
		if cx.nextpc != 0 {
			cx.pc = cx.nextpc
			cx.nextpc = 0
		} else {
			cx.pc += deets.Size
		}
	} else {
		cx.pc += deets.Size
	}
	if cx.Trace != nil {
		fmt.Fprintf(cx.Trace, "%3d %s\n", prevpc, spec.Name)
	}
	if cx.err == nil {
		for pc := prevpc + 1; pc < cx.pc; pc++ {
			if _, ok := cx.branchTargets[pc]; ok {
				return 0, fmt.Errorf("branch target %d is not an aligned instruction", pc)
			}
		}
	}
	return deets.Cost, nil
}

func opErr(cx *EvalContext) {
	cx.err = errors.New("TEAL runtime encountered err opcode")
}

func opReturn(cx *EvalContext) {
	// Achieve the end condition:
	// Take the last element on the stack and make it the return value (only element on the stack)
	// Move the pc to the end of the program
	last := len(cx.stack) - 1
	cx.stack[0] = cx.stack[last]
	cx.stack = cx.stack[:1]
	cx.nextpc = len(cx.program)
}

func opAssert(cx *EvalContext) {
	last := len(cx.stack) - 1
	if cx.stack[last].Uint != 0 {
		cx.stack = cx.stack[:last]
		return
	}
	cx.err = fmt.Errorf("assert failed pc=%d", cx.pc)
}

func opSwap(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[last], cx.stack[prev] = cx.stack[prev], cx.stack[last]
}

func opSelect(cx *EvalContext) {
	last := len(cx.stack) - 1 // condition on top
	prev := last - 1          // true is one down
	pprev := prev - 1         // false below that

	if cx.stack[last].Uint != 0 {
		cx.stack[pprev] = cx.stack[prev]
	}
	cx.stack = cx.stack[:prev]
}

func opSHA256(cx *EvalContext) {
	last := len(cx.stack) - 1
	hash := sha256.Sum256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
}

// The Keccak256 variant of SHA-3 is implemented for compatibility with Ethereum
func opKeccak256(cx *EvalContext) {
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
func opSHA512_256(cx *EvalContext) {
	last := len(cx.stack) - 1
	hash := sha512.Sum512_256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
}

func opPlus(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	sum, carry := bits.Add64(cx.stack[prev].Uint, cx.stack[last].Uint, 0)
	if carry > 0 {
		cx.err = errors.New("+ overflowed")
		return
	}
	cx.stack[prev].Uint = sum
	cx.stack = cx.stack[:last]
}

func opAddw(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	sum, carry := bits.Add64(cx.stack[prev].Uint, cx.stack[last].Uint, 0)
	cx.stack[prev].Uint = carry
	cx.stack[last].Uint = sum
}

func uint128(hi uint64, lo uint64) *big.Int {
	whole := new(big.Int).SetUint64(hi)
	whole.Lsh(whole, 64)
	whole.Add(whole, new(big.Int).SetUint64(lo))
	return whole
}

func opDivModwImpl(hiNum, loNum, hiDen, loDen uint64) (hiQuo uint64, loQuo uint64, hiRem uint64, loRem uint64) {
	dividend := uint128(hiNum, loNum)
	divisor := uint128(hiDen, loDen)

	quo, rem := new(big.Int).QuoRem(dividend, divisor, new(big.Int))
	return new(big.Int).Rsh(quo, 64).Uint64(),
		quo.Uint64(),
		new(big.Int).Rsh(rem, 64).Uint64(),
		rem.Uint64()
}

func opDivModw(cx *EvalContext) {
	loDen := len(cx.stack) - 1
	hiDen := loDen - 1
	if cx.stack[loDen].Uint == 0 && cx.stack[hiDen].Uint == 0 {
		cx.err = errors.New("/ 0")
		return
	}
	loNum := loDen - 2
	hiNum := loDen - 3
	hiQuo, loQuo, hiRem, loRem :=
		opDivModwImpl(cx.stack[hiNum].Uint, cx.stack[loNum].Uint, cx.stack[hiDen].Uint, cx.stack[loDen].Uint)
	cx.stack[hiNum].Uint = hiQuo
	cx.stack[loNum].Uint = loQuo
	cx.stack[hiDen].Uint = hiRem
	cx.stack[loDen].Uint = loRem
}

func opMinus(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > cx.stack[prev].Uint {
		cx.err = errors.New("- would result negative")
		return
	}
	cx.stack[prev].Uint -= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opDiv(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		cx.err = errors.New("/ 0")
		return
	}
	cx.stack[prev].Uint /= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opModulo(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		cx.err = errors.New("% 0")
		return
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint % cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opMul(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	high, low := bits.Mul64(cx.stack[prev].Uint, cx.stack[last].Uint)
	if high > 0 {
		cx.err = errors.New("* overflowed")
		return
	}
	cx.stack[prev].Uint = low
	cx.stack = cx.stack[:last]
}

func opMulw(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	high, low := bits.Mul64(cx.stack[prev].Uint, cx.stack[last].Uint)
	cx.stack[prev].Uint = high
	cx.stack[last].Uint = low
}

func opLt(cx *EvalContext) {
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

func opGt(cx *EvalContext) {
	opSwap(cx)
	opLt(cx)
}

func opLe(cx *EvalContext) {
	opGt(cx)
	opNot(cx)
}

func opGe(cx *EvalContext) {
	opLt(cx)
	opNot(cx)
}

func opAnd(cx *EvalContext) {
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

func opOr(cx *EvalContext) {
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

func opEq(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	ta := cx.stack[prev].argType()
	tb := cx.stack[last].argType()
	if ta != tb {
		cx.err = fmt.Errorf("cannot compare (%s to %s)", cx.stack[prev].typeName(), cx.stack[last].typeName())
		return
	}
	var cond bool
	if ta == StackBytes {
		cond = bytes.Equal(cx.stack[prev].Bytes, cx.stack[last].Bytes)
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

func opNeq(cx *EvalContext) {
	opEq(cx)
	opNot(cx)
}

func opNot(cx *EvalContext) {
	last := len(cx.stack) - 1
	cond := cx.stack[last].Uint == 0
	if cond {
		cx.stack[last].Uint = 1
	} else {
		cx.stack[last].Uint = 0
	}
}

func opLen(cx *EvalContext) {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = uint64(len(cx.stack[last].Bytes))
	cx.stack[last].Bytes = nil
}

func opItob(cx *EvalContext) {
	last := len(cx.stack) - 1
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, cx.stack[last].Uint)
	// cx.stack[last].Uint is not cleared out as optimization
	// stackValue.argType() checks Bytes field first
	cx.stack[last].Bytes = ibytes
}

func opBtoi(cx *EvalContext) {
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

func opBitOr(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint | cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitAnd(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint & cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitXor(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint ^ cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitNot(cx *EvalContext) {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = cx.stack[last].Uint ^ 0xffffffffffffffff
}

func opShiftLeft(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > 63 {
		cx.err = fmt.Errorf("shl arg too big, (%d)", cx.stack[last].Uint)
		return
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint << cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opShiftRight(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > 63 {
		cx.err = fmt.Errorf("shr arg too big, (%d)", cx.stack[last].Uint)
		return
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint >> cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opSqrt(cx *EvalContext) {
	/*
		        It would not be safe to use math.Sqrt, because we would have to
			convert our u64 to an f64, but f64 cannot represent all u64s exactly.

			This algorithm comes from Jack W. Crenshaw's 1998 article in Embedded:
			http://www.embedded.com/electronics-blogs/programmer-s-toolbox/4219659/Integer-Square-Roots
	*/

	last := len(cx.stack) - 1

	sq := cx.stack[last].Uint
	var rem uint64 = 0
	var root uint64 = 0

	for i := 0; i < 32; i++ {
		root <<= 1
		rem = (rem << 2) | (sq >> (64 - 2))
		sq <<= 2
		if root < rem {
			rem -= root | 1
			root += 2
		}
	}
	cx.stack[last].Uint = root >> 1
}

func opBitLen(cx *EvalContext) {
	last := len(cx.stack) - 1
	if cx.stack[last].argType() == StackUint64 {
		cx.stack[last].Uint = uint64(bits.Len64(cx.stack[last].Uint))
		return
	}
	length := len(cx.stack[last].Bytes)
	idx := 0
	for i, b := range cx.stack[last].Bytes {
		if b != 0 {
			idx = bits.Len8(b) + (8 * (length - i - 1))
			break
		}

	}
	cx.stack[last].Bytes = nil
	cx.stack[last].Uint = uint64(idx)
}

func opExpImpl(base uint64, exp uint64) (uint64, error) {
	// These checks are slightly repetive but the clarity of
	// avoiding nested checks seems worth it.
	if exp == 0 && base == 0 {
		return 0, errors.New("0^0 is undefined")
	}
	if base == 0 {
		return 0, nil
	}
	if exp == 0 || base == 1 {
		return 1, nil
	}
	// base is now at least 2, so exp can not be 64
	if exp >= 64 {
		return 0, fmt.Errorf("%d^%d overflow", base, exp)
	}
	answer := base
	// safe to cast exp, because it is known to fit in int (it's < 64)
	for i := 1; i < int(exp); i++ {
		next := answer * base
		if next/answer != base {
			return 0, fmt.Errorf("%d^%d overflow", base, exp)
		}
		answer = next
	}
	return answer, nil
}

func opExp(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1

	exp := cx.stack[last].Uint
	base := cx.stack[prev].Uint
	val, err := opExpImpl(base, exp)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack[prev].Uint = val
	cx.stack = cx.stack[:last]
}

func opExpwImpl(base uint64, exp uint64) (*big.Int, error) {
	// These checks are slightly repetive but the clarity of
	// avoiding nested checks seems worth it.
	if exp == 0 && base == 0 {
		return &big.Int{}, errors.New("0^0 is undefined")
	}
	if base == 0 {
		return &big.Int{}, nil
	}
	if exp == 0 || base == 1 {
		return new(big.Int).SetUint64(1), nil
	}
	// base is now at least 2, so exp can not be 128
	if exp >= 128 {
		return &big.Int{}, fmt.Errorf("%d^%d overflow", base, exp)
	}

	answer := new(big.Int).SetUint64(base)
	bigbase := new(big.Int).SetUint64(base)
	// safe to cast exp, because it is known to fit in int (it's < 128)
	for i := 1; i < int(exp); i++ {
		next := answer.Mul(answer, bigbase)
		answer = next
		if answer.BitLen() > 128 {
			return &big.Int{}, fmt.Errorf("%d^%d overflow", base, exp)
		}
	}
	return answer, nil

}

func opExpw(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1

	exp := cx.stack[last].Uint
	base := cx.stack[prev].Uint
	val, err := opExpwImpl(base, exp)
	if err != nil {
		cx.err = err
		return
	}
	hi := new(big.Int).Rsh(val, 64).Uint64()
	lo := val.Uint64()

	cx.stack[prev].Uint = hi
	cx.stack[last].Uint = lo
}

func opBytesBinOp(cx *EvalContext, result *big.Int, op func(x, y *big.Int) *big.Int) {
	last := len(cx.stack) - 1
	prev := last - 1

	if len(cx.stack[last].Bytes) > MaxByteMathSize || len(cx.stack[prev].Bytes) > MaxByteMathSize {
		cx.err = errors.New("math attempted on large byte-array")
		return
	}

	rhs := new(big.Int).SetBytes(cx.stack[last].Bytes)
	lhs := new(big.Int).SetBytes(cx.stack[prev].Bytes)
	op(lhs, rhs) // op's receiver has already been bound to result
	if result.Sign() < 0 {
		cx.err = errors.New("byte math would have negative result")
		return
	}
	cx.stack[prev].Bytes = result.Bytes()
	cx.stack = cx.stack[:last]
}

func opBytesPlus(cx *EvalContext) {
	result := new(big.Int)
	opBytesBinOp(cx, result, result.Add)
}

func opBytesMinus(cx *EvalContext) {
	result := new(big.Int)
	opBytesBinOp(cx, result, result.Sub)
}

func opBytesDiv(cx *EvalContext) {
	result := new(big.Int)
	checkDiv := func(x, y *big.Int) *big.Int {
		if y.BitLen() == 0 {
			cx.err = errors.New("division by zero")
			return new(big.Int)
		}
		return result.Div(x, y)
	}
	opBytesBinOp(cx, result, checkDiv)
}

func opBytesMul(cx *EvalContext) {
	result := new(big.Int)
	opBytesBinOp(cx, result, result.Mul)
}

func opBytesLt(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1

	if len(cx.stack[last].Bytes) > MaxByteMathSize || len(cx.stack[prev].Bytes) > MaxByteMathSize {
		cx.err = errors.New("math attempted on large byte-array")
		return
	}

	rhs := new(big.Int).SetBytes(cx.stack[last].Bytes)
	lhs := new(big.Int).SetBytes(cx.stack[prev].Bytes)
	cx.stack[prev].Bytes = nil
	if lhs.Cmp(rhs) < 0 {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opBytesGt(cx *EvalContext) {
	opSwap(cx)
	opBytesLt(cx)
}

func opBytesLe(cx *EvalContext) {
	opBytesGt(cx)
	opNot(cx)
}

func opBytesGe(cx *EvalContext) {
	opBytesLt(cx)
	opNot(cx)
}

func opBytesEq(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1

	if len(cx.stack[last].Bytes) > MaxByteMathSize || len(cx.stack[prev].Bytes) > MaxByteMathSize {
		cx.err = errors.New("math attempted on large byte-array")
		return
	}

	rhs := new(big.Int).SetBytes(cx.stack[last].Bytes)
	lhs := new(big.Int).SetBytes(cx.stack[prev].Bytes)
	cx.stack[prev].Bytes = nil
	if lhs.Cmp(rhs) == 0 {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opBytesNeq(cx *EvalContext) {
	opBytesEq(cx)
	opNot(cx)
}

func opBytesModulo(cx *EvalContext) {
	result := new(big.Int)
	checkMod := func(x, y *big.Int) *big.Int {
		if y.BitLen() == 0 {
			cx.err = errors.New("modulo by zero")
			return new(big.Int)
		}
		return result.Mod(x, y)
	}
	opBytesBinOp(cx, result, checkMod)
}

func zpad(smaller []byte, size int) []byte {
	padded := make([]byte, size)
	extra := size - len(smaller)  // how much was added?
	copy(padded[extra:], smaller) // slide original contents to the right
	return padded
}

// Return two slices, representing the top two slices on the stack.
// They can be returned in either order, but the first slice returned
// must be newly allocated, and already in place at the top of stack
// (the original top having been popped).
func opBytesBinaryLogicPrep(cx *EvalContext) ([]byte, []byte) {
	last := len(cx.stack) - 1
	prev := last - 1

	llen := len(cx.stack[last].Bytes)
	plen := len(cx.stack[prev].Bytes)

	var fresh, other []byte
	if llen > plen {
		fresh, other = zpad(cx.stack[prev].Bytes, llen), cx.stack[last].Bytes
	} else {
		fresh, other = zpad(cx.stack[last].Bytes, plen), cx.stack[prev].Bytes
	}
	cx.stack[prev].Bytes = fresh
	cx.stack = cx.stack[:last]
	return fresh, other
}

func opBytesBitOr(cx *EvalContext) {
	a, b := opBytesBinaryLogicPrep(cx)
	for i := range a {
		a[i] = a[i] | b[i]
	}
}

func opBytesBitAnd(cx *EvalContext) {
	a, b := opBytesBinaryLogicPrep(cx)
	for i := range a {
		a[i] = a[i] & b[i]
	}
}

func opBytesBitXor(cx *EvalContext) {
	a, b := opBytesBinaryLogicPrep(cx)
	for i := range a {
		a[i] = a[i] ^ b[i]
	}
}

func opBytesBitNot(cx *EvalContext) {
	last := len(cx.stack) - 1

	fresh := make([]byte, len(cx.stack[last].Bytes))
	for i, b := range cx.stack[last].Bytes {
		fresh[i] = ^b
	}
	cx.stack[last].Bytes = fresh
}

func opBytesZero(cx *EvalContext) {
	last := len(cx.stack) - 1
	length := cx.stack[last].Uint
	if length > MaxStringSize {
		cx.err = fmt.Errorf("bzero attempted to create a too large string")
		return
	}
	cx.stack[last].Bytes = make([]byte, length)
}

func opIntConstBlock(cx *EvalContext) {
	cx.intc, cx.nextpc, cx.err = parseIntcblock(cx.program, cx.pc)
}

func opIntConstN(cx *EvalContext, n uint) {
	if n >= uint(len(cx.intc)) {
		cx.err = fmt.Errorf("intc [%d] beyond %d constants", n, len(cx.intc))
		return
	}
	cx.stack = append(cx.stack, stackValue{Uint: cx.intc[n]})
}
func opIntConstLoad(cx *EvalContext) {
	n := uint(cx.program[cx.pc+1])
	opIntConstN(cx, n)
}
func opIntConst0(cx *EvalContext) {
	opIntConstN(cx, 0)
}
func opIntConst1(cx *EvalContext) {
	opIntConstN(cx, 1)
}
func opIntConst2(cx *EvalContext) {
	opIntConstN(cx, 2)
}
func opIntConst3(cx *EvalContext) {
	opIntConstN(cx, 3)
}

func opPushInt(cx *EvalContext) {
	val, bytesUsed := binary.Uvarint(cx.program[cx.pc+1:])
	if bytesUsed <= 0 {
		cx.err = fmt.Errorf("could not decode int at pc=%d", cx.pc+1)
		return
	}
	sv := stackValue{Uint: val}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 1 + bytesUsed
}

func opByteConstBlock(cx *EvalContext) {
	cx.bytec, cx.nextpc, cx.err = parseBytecBlock(cx.program, cx.pc)
}

func opByteConstN(cx *EvalContext, n uint) {
	if n >= uint(len(cx.bytec)) {
		cx.err = fmt.Errorf("bytec [%d] beyond %d constants", n, len(cx.bytec))
		return
	}
	cx.stack = append(cx.stack, stackValue{Bytes: cx.bytec[n]})
}
func opByteConstLoad(cx *EvalContext) {
	n := uint(cx.program[cx.pc+1])
	opByteConstN(cx, n)
}
func opByteConst0(cx *EvalContext) {
	opByteConstN(cx, 0)
}
func opByteConst1(cx *EvalContext) {
	opByteConstN(cx, 1)
}
func opByteConst2(cx *EvalContext) {
	opByteConstN(cx, 2)
}
func opByteConst3(cx *EvalContext) {
	opByteConstN(cx, 3)
}

func opPushBytes(cx *EvalContext) {
	pos := cx.pc + 1
	length, bytesUsed := binary.Uvarint(cx.program[pos:])
	if bytesUsed <= 0 {
		cx.err = fmt.Errorf("could not decode length at pc=%d", pos)
		return
	}
	pos += bytesUsed
	end := uint64(pos) + length
	if end > uint64(len(cx.program)) || end < uint64(pos) {
		cx.err = fmt.Errorf("pushbytes too long at pc=%d", pos)
		return
	}
	sv := stackValue{Bytes: cx.program[pos:end]}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = int(end)
}

func opArgN(cx *EvalContext, n uint64) {
	if n >= uint64(len(cx.Txn.Lsig.Args)) {
		cx.err = fmt.Errorf("cannot load arg[%d] of %d", n, len(cx.Txn.Lsig.Args))
		return
	}
	val := nilToEmpty(cx.Txn.Lsig.Args[n])
	cx.stack = append(cx.stack, stackValue{Bytes: val})
}

func opArg(cx *EvalContext) {
	n := uint64(cx.program[cx.pc+1])
	opArgN(cx, n)
}
func opArg0(cx *EvalContext) {
	opArgN(cx, 0)
}
func opArg1(cx *EvalContext) {
	opArgN(cx, 1)
}
func opArg2(cx *EvalContext) {
	opArgN(cx, 2)
}
func opArg3(cx *EvalContext) {
	opArgN(cx, 3)
}
func opArgs(cx *EvalContext) {
	last := len(cx.stack) - 1
	n := cx.stack[last].Uint
	// Pop the index and push the result back on the stack.
	cx.stack = cx.stack[:last]
	opArgN(cx, n)
}

func branchTarget(cx *EvalContext) (int, error) {
	offset := int16(uint16(cx.program[cx.pc+1])<<8 | uint16(cx.program[cx.pc+2]))
	if offset < 0 && cx.version < backBranchEnabledVersion {
		return 0, fmt.Errorf("negative branch offset %x", offset)
	}
	target := cx.pc + 3 + int(offset)
	var branchTooFar bool
	if cx.version >= 2 {
		// branching to exactly the end of the program (target == len(cx.program)), the next pc after the last instruction, is okay and ends normally
		branchTooFar = target > len(cx.program) || target < 0
	} else {
		branchTooFar = target >= len(cx.program) || target < 0
	}
	if branchTooFar {
		return 0, errors.New("branch target beyond end of program")
	}

	return target, nil
}

// checks any branch that is {op} {int16 be offset}
func checkBranch(cx *EvalContext) error {
	cx.nextpc = cx.pc + 3
	target, err := branchTarget(cx)
	if err != nil {
		return err
	}
	if target < cx.nextpc {
		// If a branch goes backwards, we should have already noted that an instruction began at that location.
		if _, ok := cx.instructionStarts[target]; !ok {
			return fmt.Errorf("back branch target %d is not an aligned instruction", target)
		}
	}
	cx.branchTargets[target] = true
	return nil
}
func opBnz(cx *EvalContext) {
	last := len(cx.stack) - 1
	cx.nextpc = cx.pc + 3
	isNonZero := cx.stack[last].Uint != 0
	cx.stack = cx.stack[:last] // pop
	if isNonZero {
		target, err := branchTarget(cx)
		if err != nil {
			cx.err = err
			return
		}
		cx.nextpc = target
	}
}

func opBz(cx *EvalContext) {
	last := len(cx.stack) - 1
	cx.nextpc = cx.pc + 3
	isZero := cx.stack[last].Uint == 0
	cx.stack = cx.stack[:last] // pop
	if isZero {
		target, err := branchTarget(cx)
		if err != nil {
			cx.err = err
			return
		}
		cx.nextpc = target
	}
}

func opB(cx *EvalContext) {
	target, err := branchTarget(cx)
	if err != nil {
		cx.err = err
		return
	}
	cx.nextpc = target
}

func opCallSub(cx *EvalContext) {
	cx.callstack = append(cx.callstack, cx.pc+3)
	opB(cx)
}

func opRetSub(cx *EvalContext) {
	top := len(cx.callstack) - 1
	if top < 0 {
		cx.err = errors.New("retsub with empty callstack")
		return
	}
	target := cx.callstack[top]
	cx.callstack = cx.callstack[:top]
	cx.nextpc = target
}

func opPop(cx *EvalContext) {
	last := len(cx.stack) - 1
	cx.stack = cx.stack[:last]
}

func opDup(cx *EvalContext) {
	last := len(cx.stack) - 1
	sv := cx.stack[last]
	cx.stack = append(cx.stack, sv)
}

func opDup2(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack = append(cx.stack, cx.stack[prev:]...)
}

func opDig(cx *EvalContext) {
	depth := int(uint(cx.program[cx.pc+1]))
	idx := len(cx.stack) - 1 - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand dig
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		cx.err = fmt.Errorf("dig %d with stack size = %d", depth, len(cx.stack))
		return
	}
	sv := cx.stack[idx]
	cx.stack = append(cx.stack, sv)
}

func opCover(cx *EvalContext) {
	depth := int(cx.program[cx.pc+1])
	topIdx := len(cx.stack) - 1
	idx := topIdx - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand cover
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		cx.err = fmt.Errorf("cover %d with stack size = %d", depth, len(cx.stack))
		return
	}
	sv := cx.stack[topIdx]
	copy(cx.stack[idx+1:], cx.stack[idx:])
	cx.stack[idx] = sv
}

func opUncover(cx *EvalContext) {
	depth := int(cx.program[cx.pc+1])
	topIdx := len(cx.stack) - 1
	idx := topIdx - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand uncover
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		cx.err = fmt.Errorf("uncover %d with stack size = %d", depth, len(cx.stack))
		return
	}

	sv := cx.stack[idx]
	copy(cx.stack[idx:], cx.stack[idx+1:])
	cx.stack[topIdx] = sv
}

func (cx *EvalContext) assetHoldingToValue(holding *basics.AssetHolding, fs assetHoldingFieldSpec) (sv stackValue, err error) {
	switch fs.field {
	case AssetBalance:
		sv.Uint = holding.Amount
	case AssetFrozen:
		sv.Uint = boolToUint(holding.Frozen)
	default:
		err = fmt.Errorf("invalid asset_holding_get field %d", fs.field)
		return
	}

	if !typecheck(fs.ftype, sv.argType()) {
		err = fmt.Errorf("%s expected field type is %s but got %s", fs.field.String(), fs.ftype.String(), sv.argType().String())
	}
	return
}

func (cx *EvalContext) assetParamsToValue(params *basics.AssetParams, creator basics.Address, fs assetParamsFieldSpec) (sv stackValue, err error) {
	switch fs.field {
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
	case AssetCreator:
		sv.Bytes = creator[:]
	default:
		err = fmt.Errorf("invalid asset_params_get field %d", fs.field)
		return
	}

	if !typecheck(fs.ftype, sv.argType()) {
		err = fmt.Errorf("%s expected field type is %s but got %s", fs.field.String(), fs.ftype.String(), sv.argType().String())
	}
	return
}

func (cx *EvalContext) appParamsToValue(params *basics.AppParams, fs appParamsFieldSpec) (sv stackValue, err error) {
	switch fs.field {
	case AppApprovalProgram:
		sv.Bytes = params.ApprovalProgram[:]
	case AppClearStateProgram:
		sv.Bytes = params.ClearStateProgram[:]
	case AppGlobalNumUint:
		sv.Uint = params.GlobalStateSchema.NumUint
	case AppGlobalNumByteSlice:
		sv.Uint = params.GlobalStateSchema.NumByteSlice
	case AppLocalNumUint:
		sv.Uint = params.LocalStateSchema.NumUint
	case AppLocalNumByteSlice:
		sv.Uint = params.LocalStateSchema.NumByteSlice
	case AppExtraProgramPages:
		sv.Uint = uint64(params.ExtraProgramPages)
	default:
		// The pseudo fields AppCreator and AppAddress are handled before this method
		err = fmt.Errorf("invalid app_params_get field %d", fs.field)
		return
	}

	if !typecheck(fs.ftype, sv.argType()) {
		err = fmt.Errorf("%s expected field type is %s but got %s", fs.field.String(), fs.ftype.String(), sv.argType().String())
	}
	return
}

// TxnFieldToTealValue is a thin wrapper for txnFieldToStack for external use
func TxnFieldToTealValue(txn *transactions.Transaction, groupIndex int, field TxnField, arrayFieldIdx uint64) (basics.TealValue, error) {
	if groupIndex < 0 {
		return basics.TealValue{}, fmt.Errorf("negative groupIndex %d", groupIndex)
	}
	cx := EvalContext{EvalParams: EvalParams{GroupIndex: uint64(groupIndex)}}
	fs := txnFieldSpecByField[field]
	sv, err := cx.txnFieldToStack(txn, fs, arrayFieldIdx, uint64(groupIndex))
	return sv.toTealValue(), err
}

func (cx *EvalContext) getTxID(txn *transactions.Transaction, groupIndex uint64) transactions.Txid {
	// Initialize txidCache if necessary
	if cx.txidCache == nil {
		cx.txidCache = make(map[uint64]transactions.Txid, len(cx.TxnGroup))
	}

	// Hashes are expensive, so we cache computed TxIDs
	txid, ok := cx.txidCache[groupIndex]
	if !ok {
		txid = txn.ID()
		cx.txidCache[groupIndex] = txid
	}

	return txid
}

func (cx *EvalContext) itxnFieldToStack(itxn *transactions.SignedTxnWithAD, fs txnFieldSpec, arrayFieldIdx uint64) (sv stackValue, err error) {
	if fs.effects {
		switch fs.field {
		case Logs:
			if arrayFieldIdx >= uint64(len(itxn.EvalDelta.Logs)) {
				err = fmt.Errorf("invalid Logs index %d", arrayFieldIdx)
				return
			}
			sv.Bytes = nilToEmpty([]byte(itxn.EvalDelta.Logs[arrayFieldIdx]))
		case NumLogs:
			sv.Uint = uint64(len(itxn.EvalDelta.Logs))
		case CreatedAssetID:
			sv.Uint = uint64(itxn.ApplyData.ConfigAsset)
		case CreatedApplicationID:
			sv.Uint = uint64(itxn.ApplyData.ApplicationID)
		default:
			err = fmt.Errorf("invalid txn field %d", fs.field)
		}
		return
	}

	if fs.field == GroupIndex || fs.field == TxID {
		err = fmt.Errorf("illegal field for inner transaction %s", fs.field)
	} else {
		sv, err = cx.txnFieldToStack(&itxn.Txn, fs, arrayFieldIdx, 0)
	}
	return
}

func (cx *EvalContext) txnFieldToStack(txn *transactions.Transaction, fs txnFieldSpec, arrayFieldIdx uint64, groupIndex uint64) (sv stackValue, err error) {
	if fs.effects {
		return sv, errors.New("Unable to obtain effects from top-level transactions")
	}
	err = nil
	switch fs.field {
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
	case Nonparticipation:
		sv.Uint = boolToUint(txn.Nonparticipation)
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
		sv.Uint = groupIndex
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

	case Assets:
		if arrayFieldIdx >= uint64(len(txn.ForeignAssets)) {
			err = fmt.Errorf("invalid Assets index %d", arrayFieldIdx)
			return
		}
		sv.Uint = uint64(txn.ForeignAssets[arrayFieldIdx])
	case NumAssets:
		sv.Uint = uint64(len(txn.ForeignAssets))

	case Applications:
		if arrayFieldIdx == 0 {
			// special case: current app id
			sv.Uint = uint64(txn.ApplicationID)
		} else {
			if arrayFieldIdx > uint64(len(txn.ForeignApps)) {
				err = fmt.Errorf("invalid Applications index %d", arrayFieldIdx)
				return
			}
			sv.Uint = uint64(txn.ForeignApps[arrayFieldIdx-1])
		}
	case NumApplications:
		sv.Uint = uint64(len(txn.ForeignApps))

	case GlobalNumUint:
		sv.Uint = uint64(txn.GlobalStateSchema.NumUint)
	case GlobalNumByteSlice:
		sv.Uint = uint64(txn.GlobalStateSchema.NumByteSlice)

	case LocalNumUint:
		sv.Uint = uint64(txn.LocalStateSchema.NumUint)
	case LocalNumByteSlice:
		sv.Uint = uint64(txn.LocalStateSchema.NumByteSlice)

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
	case ExtraProgramPages:
		sv.Uint = uint64(txn.ExtraProgramPages)
	default:
		err = fmt.Errorf("invalid txn field %d", fs.field)
		return
	}

	txnFieldType := TxnFieldTypes[fs.field]
	if !typecheck(txnFieldType, sv.argType()) {
		err = fmt.Errorf("%s expected field type is %s but got %s", fs.field.String(), txnFieldType.String(), sv.argType().String())
	}
	return
}

func opTxn(cx *EvalContext) {
	field := TxnField(cx.program[cx.pc+1])
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
	sv, err := cx.txnFieldToStack(&cx.Txn.Txn, fs, 0, cx.GroupIndex)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
}

func opTxna(cx *EvalContext) {
	field := TxnField(cx.program[cx.pc+1])
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
	arrayFieldIdx := uint64(cx.program[cx.pc+2])
	sv, err := cx.txnFieldToStack(&cx.Txn.Txn, fs, arrayFieldIdx, cx.GroupIndex)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
}

func opTxnas(cx *EvalContext) {
	last := len(cx.stack) - 1

	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if !ok {
		cx.err = fmt.Errorf("txnas unsupported field %d", field)
		return
	}
	arrayFieldIdx := cx.stack[last].Uint
	sv, err := cx.txnFieldToStack(&cx.Txn.Txn, fs, arrayFieldIdx, cx.GroupIndex)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack[last] = sv
}

func opGtxn(cx *EvalContext) {
	gtxid := cx.program[cx.pc+1]
	if int(gtxid) >= len(cx.TxnGroup) {
		cx.err = fmt.Errorf("gtxn lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := TxnField(cx.program[cx.pc+2])
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
	if field == GroupIndex {
		// GroupIndex; asking this when we just specified it is _dumb_, but oh well
		sv.Uint = uint64(gtxid)
	} else {
		sv, err = cx.txnFieldToStack(tx, fs, 0, uint64(gtxid))
		if err != nil {
			cx.err = err
			return
		}
	}
	cx.stack = append(cx.stack, sv)
}

func opGtxna(cx *EvalContext) {
	gtxid := int(uint(cx.program[cx.pc+1]))
	if gtxid >= len(cx.TxnGroup) {
		cx.err = fmt.Errorf("gtxna lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := TxnField(cx.program[cx.pc+2])
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
	arrayFieldIdx := uint64(cx.program[cx.pc+3])
	sv, err := cx.txnFieldToStack(tx, fs, arrayFieldIdx, uint64(gtxid))
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
}

func opGtxnas(cx *EvalContext) {
	last := len(cx.stack) - 1

	gtxid := cx.program[cx.pc+1]
	if int(gtxid) >= len(cx.TxnGroup) {
		cx.err = fmt.Errorf("gtxnas lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := TxnField(cx.program[cx.pc+2])
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if !ok {
		cx.err = fmt.Errorf("gtxnas unsupported field %d", field)
		return
	}
	arrayFieldIdx := cx.stack[last].Uint
	sv, err := cx.txnFieldToStack(tx, fs, arrayFieldIdx, uint64(gtxid))
	if err != nil {
		cx.err = err
		return
	}
	cx.stack[last] = sv
}

func opGtxns(cx *EvalContext) {
	last := len(cx.stack) - 1
	gtxid := cx.stack[last].Uint
	if gtxid >= uint64(len(cx.TxnGroup)) {
		cx.err = fmt.Errorf("gtxns lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := TxnField(cx.program[cx.pc+1])
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
	if field == GroupIndex {
		// GroupIndex; asking this when we just specified it is _dumb_, but oh well
		sv.Uint = gtxid
	} else {
		sv, err = cx.txnFieldToStack(tx, fs, 0, gtxid)
		if err != nil {
			cx.err = err
			return
		}
	}
	cx.stack[last] = sv
}

func opGtxnsa(cx *EvalContext) {
	last := len(cx.stack) - 1
	gtxid := cx.stack[last].Uint
	if gtxid >= uint64(len(cx.TxnGroup)) {
		cx.err = fmt.Errorf("gtxnsa lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if !ok {
		cx.err = fmt.Errorf("gtxnsa unsupported field %d", field)
		return
	}
	arrayFieldIdx := uint64(cx.program[cx.pc+2])
	sv, err := cx.txnFieldToStack(tx, fs, arrayFieldIdx, gtxid)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack[last] = sv
}

func opGtxnsas(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1

	gtxid := cx.stack[prev].Uint
	if gtxid >= uint64(len(cx.TxnGroup)) {
		cx.err = fmt.Errorf("gtxnsas lookup TxnGroup[%d] but it only has %d", gtxid, len(cx.TxnGroup))
		return
	}
	tx := &cx.TxnGroup[gtxid].Txn
	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid txn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if !ok {
		cx.err = fmt.Errorf("gtxnsas unsupported field %d", field)
		return
	}
	arrayFieldIdx := cx.stack[last].Uint
	sv, err := cx.txnFieldToStack(tx, fs, arrayFieldIdx, gtxid)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack[prev] = sv
	cx.stack = cx.stack[:last]
}

func opItxn(cx *EvalContext) {
	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid itxn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if ok {
		cx.err = fmt.Errorf("invalid itxn field %d", field)
		return
	}

	if len(cx.InnerTxns) == 0 {
		cx.err = fmt.Errorf("no inner transaction available %d", field)
		return
	}

	itxn := &cx.InnerTxns[len(cx.InnerTxns)-1]
	sv, err := cx.itxnFieldToStack(itxn, fs, 0)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
}

func opItxna(cx *EvalContext) {
	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid itxn field %d", field)
		return
	}
	_, ok = txnaFieldSpecByField[field]
	if !ok {
		cx.err = fmt.Errorf("itxna unsupported field %d", field)
		return
	}
	arrayFieldIdx := uint64(cx.program[cx.pc+2])

	if len(cx.InnerTxns) == 0 {
		cx.err = fmt.Errorf("no inner transaction available %d", field)
		return
	}

	itxn := &cx.InnerTxns[len(cx.InnerTxns)-1]
	sv, err := cx.itxnFieldToStack(itxn, fs, arrayFieldIdx)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
}

func opGaidImpl(cx *EvalContext, groupIdx uint64, opName string) (sv stackValue, err error) {
	if groupIdx >= uint64(len(cx.TxnGroup)) {
		err = fmt.Errorf("%s lookup TxnGroup[%d] but it only has %d", opName, groupIdx, len(cx.TxnGroup))
		return
	} else if groupIdx > cx.GroupIndex {
		err = fmt.Errorf("%s can't get creatable ID of txn ahead of the current one (index %d) in the transaction group", opName, groupIdx)
		return
	} else if groupIdx == cx.GroupIndex {
		err = fmt.Errorf("%s is only for accessing creatable IDs of previous txns, use `global CurrentApplicationID` instead to access the current app's creatable ID", opName)
		return
	} else if txn := cx.TxnGroup[groupIdx].Txn; !(txn.Type == protocol.ApplicationCallTx || txn.Type == protocol.AssetConfigTx) {
		err = fmt.Errorf("can't use %s on txn that is not an app call nor an asset config txn with index %d", opName, groupIdx)
		return
	}

	cid, err := cx.getCreatableID(groupIdx)
	if cid == 0 {
		err = fmt.Errorf("%s can't read creatable ID from txn with group index %d because the txn did not create anything", opName, groupIdx)
		return
	}

	sv = stackValue{
		Uint: cid,
	}
	return
}

func opGaid(cx *EvalContext) {
	groupIdx := cx.program[cx.pc+1]
	sv, err := opGaidImpl(cx, uint64(groupIdx), "gaid")
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = append(cx.stack, sv)
}

func opGaids(cx *EvalContext) {
	last := len(cx.stack) - 1
	groupIdx := cx.stack[last].Uint
	sv, err := opGaidImpl(cx, groupIdx, "gaids")
	if err != nil {
		cx.err = err
		return
	}

	cx.stack[last] = sv
}

func (cx *EvalContext) getRound() (rnd uint64, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}
	return uint64(cx.Ledger.Round()), nil
}

func (cx *EvalContext) getLatestTimestamp() (timestamp uint64, err error) {
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

func (cx *EvalContext) getApplicationID() (uint64, error) {
	if cx.Ledger == nil {
		return 0, fmt.Errorf("ledger not available")
	}
	return uint64(cx.Ledger.ApplicationID()), nil
}

func (cx *EvalContext) getApplicationAddress() (basics.Address, error) {
	if cx.Ledger == nil {
		return basics.Address{}, fmt.Errorf("ledger not available")
	}

	// Initialize appAddrCache if necessary
	if cx.appAddrCache == nil {
		cx.appAddrCache = make(map[basics.AppIndex]basics.Address)
	}

	appID := cx.Ledger.ApplicationID()
	// Hashes are expensive, so we cache computed app addrs
	appAddr, ok := cx.appAddrCache[appID]
	if !ok {
		appAddr = appID.Address()
		cx.appAddrCache[appID] = appAddr
	}

	return appAddr, nil
}

func (cx *EvalContext) getCreatableID(groupIndex uint64) (cid uint64, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}
	gi := int(groupIndex)
	if gi < 0 {
		return 0, fmt.Errorf("groupIndex %d too high", groupIndex)
	}
	return uint64(cx.Ledger.GetCreatableID(gi)), nil
}

func (cx *EvalContext) getCreatorAddress() ([]byte, error) {
	if cx.Ledger == nil {
		return nil, fmt.Errorf("ledger not available")
	}
	_, creator, err := cx.Ledger.AppParams(cx.Ledger.ApplicationID())
	if err != nil {
		return nil, fmt.Errorf("No params for current app")
	}
	return creator[:], nil
}

func (cx *EvalContext) getGroupID() []byte {
	return cx.Txn.Txn.Group[:]
}

var zeroAddress basics.Address

func (cx *EvalContext) globalFieldToValue(fs globalFieldSpec) (sv stackValue, err error) {
	switch fs.field {
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
	case CurrentApplicationAddress:
		var addr basics.Address
		addr, err = cx.getApplicationAddress()
		sv.Bytes = addr[:]
	case CreatorAddress:
		sv.Bytes, err = cx.getCreatorAddress()
	case GroupID:
		sv.Bytes = cx.getGroupID()
	default:
		err = fmt.Errorf("invalid global field %d", fs.field)
	}

	if !typecheck(fs.ftype, sv.argType()) {
		err = fmt.Errorf("%s expected field type is %s but got %s", fs.field.String(), fs.ftype.String(), sv.argType().String())
	}

	return sv, err
}

func opGlobal(cx *EvalContext) {
	globalField := GlobalField(cx.program[cx.pc+1])
	fs, ok := globalFieldSpecByField[globalField]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid global field %d", globalField)
		return
	}
	if (cx.runModeFlags & fs.mode) == 0 {
		cx.err = fmt.Errorf("global[%d] not allowed in current mode", globalField)
		return
	}

	sv, err := cx.globalFieldToValue(fs)
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = append(cx.stack, sv)
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
func (cx *EvalContext) programHash() crypto.Digest {
	if cx.programHashCached == (crypto.Digest{}) {
		cx.programHashCached = crypto.HashObj(Program(cx.program))
	}
	return cx.programHashCached
}

func opEd25519verify(cx *EvalContext) {
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

// leadingZeros needs to be replaced by big.Int.FillBytes
func leadingZeros(size int, b *big.Int) ([]byte, error) {
	data := b.Bytes()
	if size < len(data) {
		return nil, fmt.Errorf("insufficient buffer size: %d < %d", size, len(data))
	}
	if size == len(data) {
		return data, nil
	}

	buf := make([]byte, size)
	copy(buf[size-len(data):], data)
	return buf, nil
}

func opEcdsaVerify(cx *EvalContext) {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField[ecdsaCurve]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid curve %d", ecdsaCurve)
		return
	}

	if fs.field != Secp256k1 {
		cx.err = fmt.Errorf("unsupported curve %d", fs.field)
		return
	}

	last := len(cx.stack) - 1 // index of PK y
	prev := last - 1          // index of PK x
	pprev := prev - 1         // index of signature s
	fourth := pprev - 1       // index of signature r
	fifth := fourth - 1       // index of data

	pkY := cx.stack[last].Bytes
	pkX := cx.stack[prev].Bytes
	sigS := cx.stack[pprev].Bytes
	sigR := cx.stack[fourth].Bytes
	msg := cx.stack[fifth].Bytes

	x := new(big.Int).SetBytes(pkX)
	y := new(big.Int).SetBytes(pkY)
	pubkey := secp256k1.S256().Marshal(x, y)

	signature := make([]byte, 0, len(sigR)+len(sigS))
	signature = append(signature, sigR...)
	signature = append(signature, sigS...)

	result := secp256k1.VerifySignature(pubkey, msg, signature)

	if result {
		cx.stack[fifth].Uint = 1
	} else {
		cx.stack[fifth].Uint = 0
	}
	cx.stack[fifth].Bytes = nil
	cx.stack = cx.stack[:fourth]
}

func opEcdsaPkDecompress(cx *EvalContext) {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField[ecdsaCurve]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid curve %d", ecdsaCurve)
		return
	}

	if fs.field != Secp256k1 {
		cx.err = fmt.Errorf("unsupported curve %d", fs.field)
		return
	}

	last := len(cx.stack) - 1 // compressed PK

	pubkey := cx.stack[last].Bytes
	x, y := secp256k1.DecompressPubkey(pubkey)
	if x == nil {
		cx.err = fmt.Errorf("invalid pubkey")
		return
	}

	var err error
	cx.stack[last].Uint = 0
	cx.stack[last].Bytes, err = leadingZeros(32, x)
	if err != nil {
		cx.err = fmt.Errorf("x component zeroing failed: %s", err.Error())
		return
	}

	var sv stackValue
	sv.Bytes, err = leadingZeros(32, y)
	if err != nil {
		cx.err = fmt.Errorf("y component zeroing failed: %s", err.Error())
		return
	}

	cx.stack = append(cx.stack, sv)
}

func opEcdsaPkRecover(cx *EvalContext) {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField[ecdsaCurve]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid curve %d", ecdsaCurve)
		return
	}

	if fs.field != Secp256k1 {
		cx.err = fmt.Errorf("unsupported curve %d", fs.field)
		return
	}

	last := len(cx.stack) - 1 // index of signature s
	prev := last - 1          // index of signature r
	pprev := prev - 1         // index of recovery id
	fourth := pprev - 1       // index of data

	sigS := cx.stack[last].Bytes
	sigR := cx.stack[prev].Bytes
	recid := cx.stack[pprev].Uint
	msg := cx.stack[fourth].Bytes

	if recid > 3 {
		cx.err = fmt.Errorf("invalid recovery id: %d", recid)
		return
	}

	signature := make([]byte, 0, len(sigR)+len(sigS)+1)
	signature = append(signature, sigR...)
	signature = append(signature, sigS...)
	signature = append(signature, uint8(recid))

	pk, err := secp256k1.RecoverPubkey(msg, signature)
	if err != nil {
		cx.err = fmt.Errorf("pubkey recover failed: %s", err.Error())
		return
	}
	x, y := secp256k1.S256().Unmarshal(pk)
	if x == nil {
		cx.err = fmt.Errorf("pubkey unmarshal failed")
		return
	}

	cx.stack[fourth].Uint = 0
	cx.stack[fourth].Bytes, err = leadingZeros(32, x)
	if err != nil {
		cx.err = fmt.Errorf("x component zeroing failed: %s", err.Error())
		return
	}
	cx.stack[pprev].Uint = 0
	cx.stack[pprev].Bytes, err = leadingZeros(32, y)
	if err != nil {
		cx.err = fmt.Errorf("y component zeroing failed: %s", err.Error())
		return
	}
	cx.stack = cx.stack[:prev]
}

func opLoad(cx *EvalContext) {
	n := cx.program[cx.pc+1]
	cx.stack = append(cx.stack, cx.scratch[n])
}

func opLoads(cx *EvalContext) {
	last := len(cx.stack) - 1
	n := cx.stack[last].Uint
	if n >= uint64(len(cx.scratch)) {
		cx.err = fmt.Errorf("invalid Scratch index %d", n)
		return
	}
	cx.stack[last] = cx.scratch[n]
}

func opStore(cx *EvalContext) {
	n := cx.program[cx.pc+1]
	last := len(cx.stack) - 1
	cx.scratch[n] = cx.stack[last]
	cx.stack = cx.stack[:last]
}

func opStores(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	n := cx.stack[prev].Uint
	if n >= uint64(len(cx.scratch)) {
		cx.err = fmt.Errorf("invalid Scratch index %d", n)
		return
	}
	cx.scratch[n] = cx.stack[last]
	cx.stack = cx.stack[:prev]
}

func opGloadImpl(cx *EvalContext, groupIdx uint64, scratchIdx byte, opName string) (scratchValue stackValue, err error) {
	if groupIdx >= uint64(len(cx.TxnGroup)) {
		err = fmt.Errorf("%s lookup TxnGroup[%d] but it only has %d", opName, groupIdx, len(cx.TxnGroup))
		return
	} else if int(scratchIdx) >= len(cx.scratch) {
		err = fmt.Errorf("invalid Scratch index %d", scratchIdx)
		return
	} else if txn := cx.TxnGroup[groupIdx].Txn; txn.Type != protocol.ApplicationCallTx {
		err = fmt.Errorf("can't use %s on non-app call txn with index %d", opName, groupIdx)
		return
	} else if groupIdx == cx.GroupIndex {
		err = fmt.Errorf("can't use %s on self, use load instead", opName)
		return
	} else if groupIdx > cx.GroupIndex {
		err = fmt.Errorf("%s can't get future scratch space from txn with index %d", opName, groupIdx)
		return
	}

	scratchValue = cx.PastSideEffects[groupIdx].getScratchValue(scratchIdx)
	return
}

func opGload(cx *EvalContext) {
	groupIdx := uint64(cx.program[cx.pc+1])
	scratchIdx := cx.program[cx.pc+2]
	scratchValue, err := opGloadImpl(cx, groupIdx, scratchIdx, "gload")
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = append(cx.stack, scratchValue)
}

func opGloads(cx *EvalContext) {
	last := len(cx.stack) - 1
	groupIdx := cx.stack[last].Uint
	scratchIdx := cx.program[cx.pc+1]
	scratchValue, err := opGloadImpl(cx, groupIdx, scratchIdx, "gloads")
	if err != nil {
		cx.err = err
		return
	}

	cx.stack[last] = scratchValue
}

func opConcat(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	a := cx.stack[prev].Bytes
	b := cx.stack[last].Bytes
	newlen := len(a) + len(b)
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

func opSubstring(cx *EvalContext) {
	last := len(cx.stack) - 1
	start := cx.program[cx.pc+1]
	end := cx.program[cx.pc+2]
	cx.stack[last].Bytes, cx.err = substring(cx.stack[last].Bytes, int(start), int(end))
}

func opSubstring3(cx *EvalContext) {
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

func opGetBit(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	idx := cx.stack[last].Uint
	target := cx.stack[prev]

	var bit uint64
	if target.argType() == StackUint64 {
		if idx > 63 {
			cx.err = errors.New("getbit index > 63 with with Uint")
			return
		}
		mask := uint64(1) << idx
		bit = (target.Uint & mask) >> idx
	} else {
		// indexing into a byteslice
		byteIdx := idx / 8
		if byteIdx >= uint64(len(target.Bytes)) {
			cx.err = errors.New("getbit index beyond byteslice")
			return
		}
		byteVal := target.Bytes[byteIdx]

		bitIdx := idx % 8
		// We saying that bit 9 (the 10th bit), for example,
		// is the 2nd bit in the second byte, and that "2nd
		// bit" here means almost-highest-order bit, because
		// we're thinking of the bits in the byte itself as
		// being big endian. So this looks "reversed"
		mask := byte(0x80) >> bitIdx
		bit = uint64((byteVal & mask) >> (7 - bitIdx))
	}
	cx.stack[prev].Uint = bit
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
}

func opSetBit(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	pprev := prev - 1

	bit := cx.stack[last].Uint
	idx := cx.stack[prev].Uint
	target := cx.stack[pprev]

	if bit > 1 {
		cx.err = errors.New("setbit value > 1")
		return
	}

	if target.argType() == StackUint64 {
		if idx > 63 {
			cx.err = errors.New("setbit index > 63 with Uint")
			return
		}
		mask := uint64(1) << idx
		if bit == uint64(1) {
			cx.stack[pprev].Uint |= mask // manipulate stack in place
		} else {
			cx.stack[pprev].Uint &^= mask // manipulate stack in place
		}
	} else {
		// indexing into a byteslice
		byteIdx := idx / 8
		if byteIdx >= uint64(len(target.Bytes)) {
			cx.err = errors.New("setbit index beyond byteslice")
			return
		}

		bitIdx := idx % 8
		// We saying that bit 9 (the 10th bit), for example,
		// is the 2nd bit in the second byte, and that "2nd
		// bit" here means almost-highest-order bit, because
		// we're thinking of the bits in the byte itself as
		// being big endian. So this looks "reversed"
		mask := byte(0x80) >> bitIdx
		// Copy to avoid modifying shared slice
		scratch := append([]byte(nil), target.Bytes...)
		if bit == uint64(1) {
			scratch[byteIdx] |= mask
		} else {
			scratch[byteIdx] &^= mask
		}
		cx.stack[pprev].Bytes = scratch
	}
	cx.stack = cx.stack[:prev]
}

func opGetByte(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1

	idx := cx.stack[last].Uint
	target := cx.stack[prev]

	if idx >= uint64(len(target.Bytes)) {
		cx.err = errors.New("getbyte index beyond array length")
		return
	}
	cx.stack[prev].Uint = uint64(target.Bytes[idx])
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
}

func opSetByte(cx *EvalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	pprev := prev - 1
	if cx.stack[last].Uint > 255 {
		cx.err = errors.New("setbyte value > 255")
		return
	}
	if cx.stack[prev].Uint >= uint64(len(cx.stack[pprev].Bytes)) {
		cx.err = errors.New("setbyte index beyond array length")
		return
	}
	// Copy to avoid modifying shared slice
	cx.stack[pprev].Bytes = append([]byte(nil), cx.stack[pprev].Bytes...)
	cx.stack[pprev].Bytes[cx.stack[prev].Uint] = byte(cx.stack[last].Uint)
	cx.stack = cx.stack[:prev]
}

func opExtractImpl(x []byte, start, length int) (out []byte, err error) {
	out = x
	end := start + length
	if start > len(x) || end > len(x) {
		err = errors.New("extract range beyond length of string")
		return
	}
	out = x[start:end]
	return
}

func opExtract(cx *EvalContext) {
	last := len(cx.stack) - 1
	startIdx := cx.program[cx.pc+1]
	lengthIdx := cx.program[cx.pc+2]
	// Shortcut: if length is 0, take bytes from start index to the end
	length := int(lengthIdx)
	if length == 0 {
		length = len(cx.stack[last].Bytes) - int(startIdx)
	}
	cx.stack[last].Bytes, cx.err = opExtractImpl(cx.stack[last].Bytes, int(startIdx), length)
}

func opExtract3(cx *EvalContext) {
	last := len(cx.stack) - 1 // length
	prev := last - 1          // start
	byteArrayIdx := prev - 1  // bytes
	startIdx := cx.stack[prev].Uint
	lengthIdx := cx.stack[last].Uint
	if startIdx > math.MaxInt32 || lengthIdx > math.MaxInt32 {
		cx.err = errors.New("extract range beyond length of string")
		return
	}
	cx.stack[byteArrayIdx].Bytes, cx.err = opExtractImpl(cx.stack[byteArrayIdx].Bytes, int(startIdx), int(lengthIdx))
	cx.stack = cx.stack[:prev]
}

// We convert the bytes manually here because we need to accept "short" byte arrays.
// A single byte is a legal uint64 decoded this way.
func convertBytesToInt(x []byte) (out uint64) {
	out = uint64(0)
	for _, b := range x {
		out = out << 8
		out = out | (uint64(b) & 0x0ff)
	}
	return
}

func opExtractNBytes(cx *EvalContext, n int) {
	last := len(cx.stack) - 1 // start
	prev := last - 1          // bytes
	startIdx := cx.stack[last].Uint
	cx.stack[prev].Bytes, cx.err = opExtractImpl(cx.stack[prev].Bytes, int(startIdx), n) // extract n bytes

	cx.stack[prev].Uint = convertBytesToInt(cx.stack[prev].Bytes)
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
}

func opExtract16Bits(cx *EvalContext) {
	opExtractNBytes(cx, 2) // extract 2 bytes
}

func opExtract32Bits(cx *EvalContext) {
	opExtractNBytes(cx, 4) // extract 4 bytes
}

func opExtract64Bits(cx *EvalContext) {
	opExtractNBytes(cx, 8) // extract 8 bytes
}

// accountReference yields the address and Accounts offset designated
// by a stackValue. If the stackValue is the app account, it need not
// be in the Accounts array, therefore len(Accounts) + 1 is returned
// as the index. This unusual convention is based on the existing
// convention that 0 is the sender, 1-len(Accounts) are indexes into
// Accounts array, and so len+1 is the next available value.  This
// will allow encoding into EvalDelta efficiently when it becomes
// necessary (when apps change local state on their own account).
func (cx *EvalContext) accountReference(account stackValue) (basics.Address, uint64, error) {
	if account.argType() == StackUint64 {
		addr, err := cx.Txn.Txn.AddressByIndex(account.Uint, cx.Txn.Txn.Sender)
		return addr, account.Uint, err
	}
	addr, err := account.address()
	if err != nil {
		return addr, 0, err
	}
	idx, err := cx.Txn.Txn.IndexByAddress(addr, cx.Txn.Txn.Sender)

	if err != nil {
		// Application address is acceptable. index is meaningless though
		appAddr, _ := cx.getApplicationAddress()
		if appAddr == addr {
			return addr, uint64(len(cx.Txn.Txn.Accounts) + 1), nil
		}
	}

	return addr, idx, err
}

type opQuery func(basics.Address, *config.ConsensusParams) (basics.MicroAlgos, error)

func opBalanceQuery(cx *EvalContext, query opQuery, item string) error {
	last := len(cx.stack) - 1 // account (index or actual address)

	addr, _, err := cx.accountReference(cx.stack[last])
	if err != nil {
		return err
	}

	microAlgos, err := query(addr, cx.Proto)
	if err != nil {
		return fmt.Errorf("failed to fetch %s of %v: %w", item, addr, err)
	}

	cx.stack[last].Bytes = nil
	cx.stack[last].Uint = microAlgos.Raw
	return nil
}
func opBalance(cx *EvalContext) {
	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	balanceQuery := func(addr basics.Address, _ *config.ConsensusParams) (basics.MicroAlgos, error) {
		return cx.Ledger.Balance(addr)
	}
	err := opBalanceQuery(cx, balanceQuery, "balance")
	if err != nil {
		cx.err = err
	}
}
func opMinBalance(cx *EvalContext) {
	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	err := opBalanceQuery(cx, cx.Ledger.MinBalance, "minimum balance")
	if err != nil {
		cx.err = err
	}
}

func opAppOptedIn(cx *EvalContext) {
	last := len(cx.stack) - 1 // app
	prev := last - 1          // account

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, _, err := cx.accountReference(cx.stack[prev])
	if err != nil {
		cx.err = err
		return
	}

	app, err := appReference(cx, cx.stack[last].Uint, false)
	if err != nil {
		cx.err = err
		return
	}

	optedIn, err := cx.Ledger.OptedIn(addr, app)
	if err != nil {
		cx.err = err
		return
	}

	cx.stack[prev].Bytes = nil
	if optedIn {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}

	cx.stack = cx.stack[:last]
}

func opAppLocalGet(cx *EvalContext) {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // account

	key := cx.stack[last].Bytes

	result, _, err := opAppLocalGetImpl(cx, 0, key, cx.stack[prev])
	if err != nil {
		cx.err = err
		return
	}

	cx.stack[prev] = result
	cx.stack = cx.stack[:last]
}

func opAppLocalGetEx(cx *EvalContext) {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // app id
	pprev := prev - 1         // account

	key := cx.stack[last].Bytes
	appID := cx.stack[prev].Uint

	result, ok, err := opAppLocalGetImpl(cx, appID, key, cx.stack[pprev])
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

func opAppLocalGetImpl(cx *EvalContext, appID uint64, key []byte, acct stackValue) (result stackValue, ok bool, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}

	addr, accountIdx, err := cx.accountReference(acct)
	if err != nil {
		return
	}

	app, err := appReference(cx, appID, false)
	if err != nil {
		return
	}

	tv, ok, err := cx.Ledger.GetLocal(addr, app, string(key), accountIdx)
	if err != nil {
		cx.err = err
		return
	}

	if ok {
		result, err = stackValueFromTealValue(&tv)
	}
	return
}

func opAppGetGlobalStateImpl(cx *EvalContext, appIndex uint64, key []byte) (result stackValue, ok bool, err error) {
	if cx.Ledger == nil {
		err = fmt.Errorf("ledger not available")
		return
	}

	app, err := appReference(cx, appIndex, true)
	if err != nil {
		return
	}
	tv, ok, err := cx.Ledger.GetGlobal(app, string(key))

	if err != nil {
		return
	}

	if ok {
		result, err = stackValueFromTealValue(&tv)
	}
	return
}

func opAppGlobalGet(cx *EvalContext) {
	last := len(cx.stack) - 1 // state key

	key := cx.stack[last].Bytes

	result, _, err := opAppGetGlobalStateImpl(cx, 0, key)
	if err != nil {
		cx.err = err
		return
	}

	cx.stack[last] = result
}

func opAppGlobalGetEx(cx *EvalContext) {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // app

	key := cx.stack[last].Bytes

	result, ok, err := opAppGetGlobalStateImpl(cx, cx.stack[prev].Uint, key)
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

func opAppLocalPut(cx *EvalContext) {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // state key
	pprev := prev - 1         // account

	sv := cx.stack[last]
	key := string(cx.stack[prev].Bytes)

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, accountIdx, err := cx.accountReference(cx.stack[pprev])
	if err == nil {
		err = cx.Ledger.SetLocal(addr, key, sv.toTealValue(), accountIdx)
	}

	if err != nil {
		cx.err = err
		return
	}

	cx.stack = cx.stack[:pprev]
}

func opAppGlobalPut(cx *EvalContext) {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // state key

	sv := cx.stack[last]
	key := string(cx.stack[prev].Bytes)

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	err := cx.Ledger.SetGlobal(key, sv.toTealValue())
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = cx.stack[:prev]
}

func opAppLocalDel(cx *EvalContext) {
	last := len(cx.stack) - 1 // key
	prev := last - 1          // account

	key := string(cx.stack[last].Bytes)

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	addr, accountIdx, err := cx.accountReference(cx.stack[prev])
	if err == nil {
		err = cx.Ledger.DelLocal(addr, key, accountIdx)
	}
	if err != nil {
		cx.err = err
		return
	}

	cx.stack = cx.stack[:prev]
}

func opAppGlobalDel(cx *EvalContext) {
	last := len(cx.stack) - 1 // key

	key := string(cx.stack[last].Bytes)

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	err := cx.Ledger.DelGlobal(key)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = cx.stack[:last]
}

// We have a difficult naming problem here. In some opcodes, TEAL
// allows (and used to require) ASAs and Apps to to be referenced by
// their "index" in an app call txn's foeign-apps or foreign-assets
// arrays.  That was a small integer, no more than 2 or so, and was
// often called an "index".  But it was not a basics.AssetIndex or
// basics.ApplicationIndex.

func appReference(cx *EvalContext, ref uint64, foreign bool) (basics.AppIndex, error) {
	if cx.version >= directRefEnabledVersion {
		if ref == 0 {
			return cx.Ledger.ApplicationID(), nil
		}
		if ref <= uint64(len(cx.Txn.Txn.ForeignApps)) {
			return basics.AppIndex(cx.Txn.Txn.ForeignApps[ref-1]), nil
		}
		for _, appID := range cx.Txn.Txn.ForeignApps {
			if appID == basics.AppIndex(ref) {
				return appID, nil
			}
		}
		// It should be legal to use your own app id, which
		// can't be in ForeignApps during creation, because it
		// is unknown then.  But it can be discovered in the
		// app code.  It's tempting to combine this with the
		// == 0 test, above, but it must come after the check
		// for being below len(ForeignApps)
		if ref == uint64(cx.Ledger.ApplicationID()) {
			return cx.Ledger.ApplicationID(), nil
		}
	} else {
		// Old rules
		if foreign {
			// In old versions, a foreign reference must be an index in ForeignAssets or 0
			if ref == 0 {
				return cx.Ledger.ApplicationID(), nil
			}
			if ref <= uint64(len(cx.Txn.Txn.ForeignApps)) {
				return basics.AppIndex(cx.Txn.Txn.ForeignApps[ref-1]), nil
			}
		} else {
			// Otherwise it's direct
			return basics.AppIndex(ref), nil
		}
	}
	return basics.AppIndex(0), fmt.Errorf("invalid App reference %d", ref)
}

func asaReference(cx *EvalContext, ref uint64, foreign bool) (basics.AssetIndex, error) {
	if cx.version >= directRefEnabledVersion {
		// In recent versions, accept either kind of ASA reference
		if ref < uint64(len(cx.Txn.Txn.ForeignAssets)) {
			return basics.AssetIndex(cx.Txn.Txn.ForeignAssets[ref]), nil
		}
		for _, assetID := range cx.Txn.Txn.ForeignAssets {
			if assetID == basics.AssetIndex(ref) {
				return assetID, nil
			}
		}
	} else {
		// Old rules
		if foreign {
			// In old versions, a foreign reference must be an index in ForeignAssets
			if ref < uint64(len(cx.Txn.Txn.ForeignAssets)) {
				return basics.AssetIndex(cx.Txn.Txn.ForeignAssets[ref]), nil
			}
		} else {
			// Otherwise it's direct
			return basics.AssetIndex(ref), nil
		}
	}
	return basics.AssetIndex(0), fmt.Errorf("invalid Asset reference %d", ref)

}

func opAssetHoldingGet(cx *EvalContext) {
	last := len(cx.stack) - 1 // asset
	prev := last - 1          // account

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	holdingField := AssetHoldingField(cx.program[cx.pc+1])
	fs, ok := assetHoldingFieldSpecByField[holdingField]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid asset_holding_get field %d", holdingField)
		return
	}

	addr, _, err := cx.accountReference(cx.stack[prev])
	if err != nil {
		cx.err = err
		return
	}

	asset, err := asaReference(cx, cx.stack[last].Uint, false)
	if err != nil {
		cx.err = err
		return
	}

	var exist uint64 = 0
	var value stackValue
	if holding, err := cx.Ledger.AssetHolding(addr, asset); err == nil {
		// the holding exist, read the value
		exist = 1
		value, err = cx.assetHoldingToValue(&holding, fs)
		if err != nil {
			cx.err = err
			return
		}
	}

	cx.stack[prev] = value
	cx.stack[last].Uint = exist
}

func opAssetParamsGet(cx *EvalContext) {
	last := len(cx.stack) - 1 // asset

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	paramField := AssetParamsField(cx.program[cx.pc+1])
	fs, ok := assetParamsFieldSpecByField[paramField]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid asset_params_get field %d", paramField)
		return
	}

	asset, err := asaReference(cx, cx.stack[last].Uint, true)
	if err != nil {
		cx.err = err
		return
	}

	var exist uint64 = 0
	var value stackValue
	if params, creator, err := cx.Ledger.AssetParams(asset); err == nil {
		// params exist, read the value
		exist = 1
		value, err = cx.assetParamsToValue(&params, creator, fs)
		if err != nil {
			cx.err = err
			return
		}
	}

	cx.stack[last] = value
	cx.stack = append(cx.stack, stackValue{Uint: exist})
}

func opAppParamsGet(cx *EvalContext) {
	last := len(cx.stack) - 1 // app

	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	paramField := AppParamsField(cx.program[cx.pc+1])
	fs, ok := appParamsFieldSpecByField[paramField]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid app_params_get field %d", paramField)
		return
	}

	app, err := appReference(cx, cx.stack[last].Uint, true)
	if err != nil {
		cx.err = err
		return
	}

	var exist uint64 = 0
	var value stackValue
	if params, creator, err := cx.Ledger.AppParams(app); err == nil {
		// params exist, read the value
		exist = 1

		switch fs.field {
		case AppCreator:
			value.Bytes = creator[:]
		case AppAddress:
			address := app.Address()
			value.Bytes = address[:]
		default:
			value, err = cx.appParamsToValue(&params, fs)
		}
		if err != nil {
			cx.err = err
			return
		}
	}

	cx.stack[last] = value
	cx.stack = append(cx.stack, stackValue{Uint: exist})
}

func opLog(cx *EvalContext) {
	last := len(cx.stack) - 1

	if len(cx.Logs) == MaxLogCalls {
		cx.err = fmt.Errorf("too many log calls in program. up to %d is allowed", MaxLogCalls)
		return
	}
	log := cx.stack[last]
	cx.logSize += len(log.Bytes)
	if cx.logSize > MaxLogSize {
		cx.err = fmt.Errorf("program logs too large. %d bytes >  %d bytes limit", cx.logSize, MaxLogSize)
		return
	}
	cx.Logs = append(cx.Logs, string(log.Bytes))
	cx.stack = cx.stack[:last]
}

func authorizedSender(cx *EvalContext, addr basics.Address) bool {
	appAddr, err := cx.getApplicationAddress()
	if err != nil {
		return false
	}
	authorizer, err := cx.Ledger.Authorizer(addr)
	if err != nil {
		return false
	}
	return appAddr == authorizer
}

// addInnerTxn appends a fresh SignedTxn to subtxns, populated with reasonable
// defaults.
func addInnerTxn(cx *EvalContext) error {
	addr, err := cx.getApplicationAddress()
	if err != nil {
		return err
	}

	// For compatibility with v5, in which failures only occurred in the submit,
	// we only fail here if we are OVER the MaxInnerTransactions limit.  Thus
	// this allows construction of one more Inner than is actually allowed, and
	// will fail in submit. (But we do want the check here, so this can't become
	// unbounded.)  The MaxTxGroupSize check can be, and is, precise.
	if len(cx.InnerTxns)+len(cx.subtxns) > cx.Proto.MaxInnerTransactions ||
		len(cx.subtxns) >= cx.Proto.MaxTxGroupSize {
		return errors.New("attempt to create too many inner transactions")
	}

	stxn := transactions.SignedTxn{}

	groupFee := basics.MulSaturate(cx.Proto.MinTxnFee, uint64(len(cx.subtxns)+1))
	groupPaid := uint64(0)
	for _, ptxn := range cx.subtxns {
		groupPaid = basics.AddSaturate(groupPaid, ptxn.Txn.Fee.Raw)
	}

	fee := uint64(0)
	if groupPaid < groupFee {
		fee = groupFee - groupPaid

		if cx.FeeCredit != nil {
			// Use credit to shrink the default populated fee, but don't change
			// FeeCredit here, because they might never itxn_submit, or they
			// might change the fee.  Do it in itxn_submit.
			fee = basics.SubSaturate(fee, *cx.FeeCredit)
		}
	}

	stxn.Txn.Header = transactions.Header{
		Sender:     addr,
		Fee:        basics.MicroAlgos{Raw: fee},
		FirstValid: cx.Txn.Txn.FirstValid,
		LastValid:  cx.Txn.Txn.LastValid,
	}
	cx.subtxns = append(cx.subtxns, stxn)
	return nil
}

func opTxBegin(cx *EvalContext) {
	if len(cx.subtxns) > 0 {
		cx.err = errors.New("itxn_begin without itxn_submit")
		return
	}
	cx.err = addInnerTxn(cx)
}

func opTxNext(cx *EvalContext) {
	if len(cx.subtxns) == 0 {
		cx.err = errors.New("itxn_next without itxn_begin")
		return
	}
	cx.err = addInnerTxn(cx)
}

// availableAccount is used instead of accountReference for more recent opcodes
// that don't need (or want!) to allow low numbers to represent the account at
// that index in Accounts array.
func (cx *EvalContext) availableAccount(sv stackValue) (basics.Address, error) {
	if sv.argType() != StackBytes || len(sv.Bytes) != crypto.DigestSize {
		return basics.Address{}, fmt.Errorf("not an address")
	}

	addr, _, err := cx.accountReference(sv)
	return addr, err
}

// availableAsset is used instead of asaReference for more recent opcodes that
// don't need (or want!) to allow low numbers to represent the asset at that
// index in ForeignAssets array.
func (cx *EvalContext) availableAsset(sv stackValue) (basics.AssetIndex, error) {
	aid, err := sv.uint()
	if err != nil {
		return basics.AssetIndex(0), err
	}
	// Ensure that aid is in Foreign Assets
	for _, assetID := range cx.Txn.Txn.ForeignAssets {
		if assetID == basics.AssetIndex(aid) {
			return basics.AssetIndex(aid), nil
		}
	}
	return basics.AssetIndex(0), fmt.Errorf("invalid Asset reference %d", aid)
}

func (cx *EvalContext) stackIntoTxnField(sv stackValue, fs txnFieldSpec, txn *transactions.Transaction) (err error) {
	switch fs.field {
	case Type:
		if sv.Bytes == nil {
			err = fmt.Errorf("Type arg not a byte array")
			return
		}
		txType := string(sv.Bytes)
		ver, ok := innerTxnTypes[txType]
		if ok && ver <= cx.version {
			txn.Type = protocol.TxType(txType)
		} else {
			err = fmt.Errorf("%s is not a valid Type for itxn_field", txType)
		}
	case TypeEnum:
		var i uint64
		i, err = sv.uint()
		if err != nil {
			return
		}
		// i != 0 is so that the error reports 0 instead of Unknown
		if i != 0 && i < uint64(len(TxnTypeNames)) {
			ver, ok := innerTxnTypes[TxnTypeNames[i]]
			if ok && ver <= cx.version {
				txn.Type = protocol.TxType(TxnTypeNames[i])
			} else {
				err = fmt.Errorf("%s is not a valid Type for itxn_field", TxnTypeNames[i])
			}
		} else {
			err = fmt.Errorf("%d is not a valid TypeEnum", i)
		}
	case Sender:
		txn.Sender, err = cx.availableAccount(sv)
	case Fee:
		txn.Fee.Raw, err = sv.uint()
	// FirstValid, LastValid unsettable: little motivation (maybe a app call
	// wants to inspect?)  If we set, make sure they are legal, both for current
	// round, and separation by MaxLifetime (check lifetime in submit, not here)
	case Note:
		if len(sv.Bytes) > cx.Proto.MaxTxnNoteBytes {
			err = fmt.Errorf("%s may not exceed %d bytes", fs.field, cx.Proto.MaxTxnNoteBytes)
		} else {
			txn.Note = make([]byte, len(sv.Bytes))
			copy(txn.Note[:], sv.Bytes)
		}
	// GenesisID, GenesisHash unsettable: surely makes no sense
	// Group unsettable: Can't make groups from AVM (yet?)
	// Lease unsettable: This seems potentially useful.

	case RekeyTo:
		txn.RekeyTo, err = sv.address()

	// KeyReg
	case VotePK:
		if len(sv.Bytes) != 32 {
			err = fmt.Errorf("%s must be 32 bytes", fs.field)
		} else {
			copy(txn.VotePK[:], sv.Bytes)
		}
	case SelectionPK:
		if len(sv.Bytes) != 32 {
			err = fmt.Errorf("%s must be 32 bytes", fs.field)
		} else {
			copy(txn.SelectionPK[:], sv.Bytes)
		}
	case VoteFirst:
		var round uint64
		round, err = sv.uint()
		txn.VoteFirst = basics.Round(round)
	case VoteLast:
		var round uint64
		round, err = sv.uint()
		txn.VoteLast = basics.Round(round)
	case VoteKeyDilution:
		txn.VoteKeyDilution, err = sv.uint()
	case Nonparticipation:
		txn.Nonparticipation, err = sv.bool()

	// Payment
	case Receiver:
		txn.Receiver, err = cx.availableAccount(sv)
	case Amount:
		txn.Amount.Raw, err = sv.uint()
	case CloseRemainderTo:
		txn.CloseRemainderTo, err = cx.availableAccount(sv)
	// AssetTransfer
	case XferAsset:
		txn.XferAsset, err = cx.availableAsset(sv)
	case AssetAmount:
		txn.AssetAmount, err = sv.uint()
	case AssetSender:
		txn.AssetSender, err = cx.availableAccount(sv)
	case AssetReceiver:
		txn.AssetReceiver, err = cx.availableAccount(sv)
	case AssetCloseTo:
		txn.AssetCloseTo, err = cx.availableAccount(sv)
	// AssetConfig
	case ConfigAsset:
		txn.ConfigAsset, err = cx.availableAsset(sv)
	case ConfigAssetTotal:
		txn.AssetParams.Total, err = sv.uint()
	case ConfigAssetDecimals:
		var decimals uint64
		decimals, err = sv.uint()
		if err == nil {
			if decimals > uint64(cx.Proto.MaxAssetDecimals) {
				err = fmt.Errorf("too many decimals (%d)", decimals)
			} else {
				txn.AssetParams.Decimals = uint32(decimals)
			}
		}
	case ConfigAssetDefaultFrozen:
		txn.AssetParams.DefaultFrozen, err = sv.bool()
	case ConfigAssetUnitName:
		txn.AssetParams.UnitName, err = sv.string(cx.Proto.MaxAssetUnitNameBytes)
	case ConfigAssetName:
		txn.AssetParams.AssetName, err = sv.string(cx.Proto.MaxAssetNameBytes)
	case ConfigAssetURL:
		txn.AssetParams.URL, err = sv.string(cx.Proto.MaxAssetURLBytes)
	case ConfigAssetMetadataHash:
		if len(sv.Bytes) != 32 {
			err = fmt.Errorf("%s must be 32 bytes", fs.field)
		} else {
			copy(txn.AssetParams.MetadataHash[:], sv.Bytes)
		}
	case ConfigAssetManager:
		txn.AssetParams.Manager, err = sv.address()
	case ConfigAssetReserve:
		txn.AssetParams.Reserve, err = sv.address()
	case ConfigAssetFreeze:
		txn.AssetParams.Freeze, err = sv.address()
	case ConfigAssetClawback:
		txn.AssetParams.Clawback, err = sv.address()
	// Freeze
	case FreezeAsset:
		txn.FreezeAsset, err = cx.availableAsset(sv)
	case FreezeAssetAccount:
		txn.FreezeAccount, err = cx.availableAccount(sv)
	case FreezeAssetFrozen:
		txn.AssetFrozen, err = sv.bool()

	// appl needs to wait. Can't call AVM from AVM.

	default:
		return fmt.Errorf("invalid itxn_field %s", fs.field)
	}
	return
}

func opTxField(cx *EvalContext) {
	itx := len(cx.subtxns) - 1
	if itx < 0 {
		cx.err = errors.New("itxn_field without itxn_begin")
		return
	}
	last := len(cx.stack) - 1
	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField[field]
	if !ok || fs.itxVersion == 0 || fs.itxVersion > cx.version {
		cx.err = fmt.Errorf("invalid itxn_field %s", field)
		return
	}
	sv := cx.stack[last]
	cx.err = cx.stackIntoTxnField(sv, fs, &cx.subtxns[itx].Txn)
	cx.stack = cx.stack[:last] // pop
}

func opTxSubmit(cx *EvalContext) {
	if cx.Ledger == nil {
		cx.err = fmt.Errorf("ledger not available")
		return
	}

	// Should never trigger, since itxn_next checks these too.
	if len(cx.InnerTxns)+len(cx.subtxns) > cx.Proto.MaxInnerTransactions ||
		len(cx.subtxns) > cx.Proto.MaxTxGroupSize {
		cx.err = errors.New("too many inner transactions")
		return
	}

	if len(cx.subtxns) == 0 {
		cx.err = errors.New("itxn_submit without itxn_begin")
		return
	}

	// Check fees across the group first. Allows fee pooling in inner groups.
	groupFee := basics.MulSaturate(cx.Proto.MinTxnFee, uint64(len(cx.subtxns)))
	groupPaid := uint64(0)
	for _, ptxn := range cx.subtxns {
		groupPaid = basics.AddSaturate(groupPaid, ptxn.Txn.Fee.Raw)
	}
	if groupPaid < groupFee {
		// See if the FeeCredit is enough to cover the shortfall
		shortfall := groupFee - groupPaid
		if cx.FeeCredit == nil || *cx.FeeCredit < shortfall {
			cx.err = fmt.Errorf("fee too small %#v", cx.subtxns)
			return
		}
		*cx.FeeCredit -= shortfall
	} else {
		overpay := groupPaid - groupFee
		if cx.FeeCredit == nil {
			cx.FeeCredit = new(uint64)
		}
		*cx.FeeCredit = basics.AddSaturate(*cx.FeeCredit, overpay)
	}

	for itx := range cx.subtxns {
		// The goal is to follow the same invariants used by the
		// transaction pool. Namely that any transaction that makes it
		// to Perform (which is equivalent to eval.applyTransaction)
		// is authorized, and WellFormed.
		if !authorizedSender(cx, cx.subtxns[itx].Txn.Sender) {
			cx.err = fmt.Errorf("unauthorized")
			return
		}

		// Recall that WellFormed does not care about individual
		// transaction fees because of fee pooling. So we check below.
		cx.err = cx.subtxns[itx].Txn.WellFormed(*cx.Specials, *cx.Proto)
		if cx.err != nil {
			return
		}

		ad, err := cx.Ledger.Perform(&cx.subtxns[itx].Txn, *cx.Specials)
		if err != nil {
			cx.err = err
			return
		}

		cx.InnerTxns = append(cx.InnerTxns, transactions.SignedTxnWithAD{
			SignedTxn: cx.subtxns[itx],
			ApplyData: ad,
		})
	}
	cx.subtxns = nil
}

// PcDetails return PC and disassembled instructions at PC up to 2 opcodes back
func (cx *EvalContext) PcDetails() (pc int, dis string) {
	const maxNumAdditionalOpcodes = 2
	text, ds, err := disassembleInstrumented(cx.program, nil)
	if err != nil {
		return cx.pc, dis
	}

	for i := 0; i < len(ds.pcOffset); i++ {
		if ds.pcOffset[i].PC == cx.pc {
			start := 0
			if i >= maxNumAdditionalOpcodes {
				start = i - maxNumAdditionalOpcodes
			}

			startTextPos := ds.pcOffset[start].Offset
			endTextPos := len(text)
			if i+1 < len(ds.pcOffset) {
				endTextPos = ds.pcOffset[i+1].Offset
			}

			dis = text[startTextPos:endTextPos]
			break
		}
	}
	return cx.pc, dis
}

func base64Decode(encoded []byte, encoding *base64.Encoding) ([]byte, error) {
	decoded := make([]byte, encoding.DecodedLen(len(encoded)))
	n, err := encoding.Strict().Decode(decoded, encoded)
	if err != nil {
		return decoded[:0], err
	}
	return decoded[:n], err
}

func opBase64Decode(cx *EvalContext) {
	last := len(cx.stack) - 1
	encodingField := Base64Encoding(cx.program[cx.pc+1])
	fs, ok := base64EncodingSpecByField[encodingField]
	if !ok || fs.version > cx.version {
		cx.err = fmt.Errorf("invalid base64_decode encoding %d", encodingField)
		return
	}

	encoding := base64.URLEncoding
	if encodingField == StdEncoding {
		encoding = base64.StdEncoding
	}
	cx.stack[last].Bytes, cx.err = base64Decode(cx.stack[last].Bytes, encoding)
}
