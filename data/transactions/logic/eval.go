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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// evalMaxVersion is the max version we can interpret and run
const evalMaxVersion = LogicVersion

// The constants below control opcode evaluation and MAY NOT be changed without
// gating them by version. Old programs need to retain their old behavior.

// maxStringSize is the limit of byte string length in an AVM value
const maxStringSize = 4096

// maxByteMathSize is the limit of byte strings supplied as input to byte math opcodes
const maxByteMathSize = 64

// maxLogSize is the limit of total log size from n log calls in a program
const maxLogSize = 1024

// maxLogCalls is the limit of total log calls during a program execution
const maxLogCalls = 32

// maxAppCallDepth is the limit on inner appl call depth
// To be clear, 0 would prevent inner appls, 1 would mean inner app calls cannot
// make inner appls. So the total app depth can be 1 higher than this number, if
// you count the top-level app call.
const maxAppCallDepth = 8

// maxStackDepth should not change unless controlled by a teal version change
const maxStackDepth = 1000

// stackValue is the type for the operand stack.
// Each stackValue is either a valid []byte value or a uint64 value.
// If (.Bytes != nil) the stackValue is a []byte value, otherwise uint64 value.
type stackValue struct {
	Uint  uint64
	Bytes []byte
}

func (sv stackValue) argType() StackType {
	if sv.Bytes != nil {
		return StackBytes
	}
	return StackUint64
}

func (sv stackValue) typeName() string {
	if sv.Bytes != nil {
		return "[]byte"
	}
	return "uint64"
}

func (sv stackValue) String() string {
	if sv.Bytes != nil {
		return hex.EncodeToString(sv.Bytes)
	}
	return fmt.Sprintf("%d 0x%x", sv.Uint, sv.Uint)
}

func (sv stackValue) address() (addr basics.Address, err error) {
	if len(sv.Bytes) != len(addr) {
		return basics.Address{}, errors.New("not an address")
	}
	copy(addr[:], sv.Bytes)
	return
}

func (sv stackValue) uint() (uint64, error) {
	if sv.Bytes != nil {
		return 0, errors.New("not a uint64")
	}
	return sv.Uint, nil
}

func (sv stackValue) uintMaxed(max uint64) (uint64, error) {
	if sv.Bytes != nil {
		return 0, fmt.Errorf("%#v is not a uint64", sv.Bytes)
	}
	if sv.Uint > max {
		return 0, fmt.Errorf("%d is larger than max=%d", sv.Uint, max)
	}
	return sv.Uint, nil
}

func (sv stackValue) bool() (bool, error) {
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

func (sv stackValue) string(limit int) (string, error) {
	if sv.Bytes == nil {
		return "", errors.New("not a byte array")
	}
	if len(sv.Bytes) > limit {
		return "", errors.New("value is too long")
	}
	return string(sv.Bytes), nil
}

func (sv stackValue) toTealValue() (tv basics.TealValue) {
	if sv.argType() == StackBytes {
		return basics.TealValue{Type: basics.TealBytesType, Bytes: string(sv.Bytes)}
	}
	return basics.TealValue{Type: basics.TealUintType, Uint: sv.Uint}
}

func stackValueFromTealValue(tv basics.TealValue) (sv stackValue, err error) {
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
func ComputeMinTealVersion(group []transactions.SignedTxnWithAD) uint64 {
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

// LedgerForLogic represents ledger API for Stateful TEAL program
type LedgerForLogic interface {
	AccountData(addr basics.Address) (ledgercore.AccountData, error)
	Authorizer(addr basics.Address) (basics.Address, error)
	Round() basics.Round
	LatestTimestamp() int64

	AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error)
	AssetParams(aidx basics.AssetIndex) (basics.AssetParams, basics.Address, error)
	AppParams(aidx basics.AppIndex) (basics.AppParams, basics.Address, error)
	OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error)

	GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (value basics.TealValue, exists bool, err error)
	SetLocal(addr basics.Address, appIdx basics.AppIndex, key string, value basics.TealValue, accountIdx uint64) error
	DelLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) error

	GetGlobal(appIdx basics.AppIndex, key string) (value basics.TealValue, exists bool, err error)
	SetGlobal(appIdx basics.AppIndex, key string, value basics.TealValue) error
	DelGlobal(appIdx basics.AppIndex, key string) error

	Perform(gi int, ep *EvalParams) error
	Counter() uint64
}

// resources contains a list of apps and assets. It's used to track the apps and
// assets created by a txgroup, for "free" access.
type resources struct {
	asas []basics.AssetIndex
	apps []basics.AppIndex
}

// EvalParams contains data that comes into condition evaluation.
type EvalParams struct {
	Proto *config.ConsensusParams

	Trace *strings.Builder

	TxnGroup []transactions.SignedTxnWithAD

	pastScratch []*scratchSpace

	logger logging.Logger

	Ledger LedgerForLogic

	// optional debugger
	Debugger DebuggerHook

	// MinTealVersion is the minimum allowed TEAL version of this program.
	// The program must reject if its version is less than this version. If
	// MinTealVersion is nil, we will compute it ourselves
	MinTealVersion *uint64

	// Amount "overpaid" by the transactions of the group.  Often 0.  When
	// positive, it can be spent by inner transactions.  Shared across a group's
	// txns, so that it can be updated (including upward, by overpaying inner
	// transactions). nil is treated as 0 (used before fee pooling is enabled).
	FeeCredit *uint64

	Specials *transactions.SpecialAddresses

	// Total pool of app call budget in a group transaction (nil before budget pooling enabled)
	PooledApplicationBudget *int

	// Total allowable inner txns in a group transaction (nil before inner pooling enabled)
	pooledAllowedInners *int

	// created contains resources that may be used for "created" - they need not be in
	// a foreign array. They remain empty until createdResourcesVersion.
	created *resources

	// Caching these here means the hashes can be shared across the TxnGroup
	// (and inners, because the cache is shared with the inner EvalParams)
	appAddrCache map[basics.AppIndex]basics.Address

	// Cache the txid hashing, but do *not* share this into inner EvalParams, as
	// the key is just the index in the txgroup.
	txidCache      map[int]transactions.Txid
	innerTxidCache map[int]transactions.Txid

	// The calling context, if this is an inner app call
	caller *EvalContext
}

func copyWithClearAD(txgroup []transactions.SignedTxnWithAD) []transactions.SignedTxnWithAD {
	copy := make([]transactions.SignedTxnWithAD, len(txgroup))
	for i := range txgroup {
		copy[i].SignedTxn = txgroup[i].SignedTxn
		// leave copy[i].ApplyData clear
	}
	return copy
}

// NewEvalParams creates an EvalParams to use while evaluating a top-level txgroup
func NewEvalParams(txgroup []transactions.SignedTxnWithAD, proto *config.ConsensusParams, specials *transactions.SpecialAddresses) *EvalParams {
	apps := 0
	for _, tx := range txgroup {
		if tx.Txn.Type == protocol.ApplicationCallTx {
			apps++
		}
	}

	// Make a simpler EvalParams that is good enough to evaluate LogicSigs.
	if apps == 0 {
		return &EvalParams{
			TxnGroup: txgroup,
			Proto:    proto,
			Specials: specials,
		}
	}

	minTealVersion := ComputeMinTealVersion(txgroup)

	var pooledApplicationBudget *int
	var pooledAllowedInners *int

	credit := feeCredit(txgroup, proto.MinTxnFee)

	if proto.EnableAppCostPooling && apps > 0 {
		pooledApplicationBudget = new(int)
		*pooledApplicationBudget = apps * proto.MaxAppProgramCost
	}

	if proto.EnableInnerTransactionPooling && apps > 0 {
		pooledAllowedInners = new(int)
		*pooledAllowedInners = proto.MaxTxGroupSize * proto.MaxInnerTransactions
	}

	return &EvalParams{
		TxnGroup:                copyWithClearAD(txgroup),
		Proto:                   proto,
		Specials:                specials,
		pastScratch:             make([]*scratchSpace, len(txgroup)),
		MinTealVersion:          &minTealVersion,
		FeeCredit:               &credit,
		PooledApplicationBudget: pooledApplicationBudget,
		pooledAllowedInners:     pooledAllowedInners,
		created:                 &resources{},
		appAddrCache:            make(map[basics.AppIndex]basics.Address),
	}
}

// feeCredit returns the extra fee supplied in this top-level txgroup compared
// to required minfee.  It can make assumptions about overflow because the group
// is known OK according to TxnGroupBatchVerify. (In essence the group is
// "WellFormed")
func feeCredit(txgroup []transactions.SignedTxnWithAD, minFee uint64) uint64 {
	minFeeCount := uint64(0)
	feesPaid := uint64(0)
	for _, stxn := range txgroup {
		if stxn.Txn.Type != protocol.CompactCertTx {
			minFeeCount++
		}
		feesPaid = basics.AddSaturate(feesPaid, stxn.Txn.Fee.Raw)
	}
	// Overflow is impossible, because TxnGroupBatchVerify checked.
	feeNeeded := minFee * minFeeCount

	return feesPaid - feeNeeded
}

// NewInnerEvalParams creates an EvalParams to be used while evaluating an inner group txgroup
func NewInnerEvalParams(txg []transactions.SignedTxnWithAD, caller *EvalContext) *EvalParams {
	minTealVersion := ComputeMinTealVersion(txg)
	// Can't happen currently, since earliest inner callable version is higher
	// than any minimum imposed otherwise.  But is correct to inherit a stronger
	// restriction from above, in case of future restriction.
	if minTealVersion < *caller.MinTealVersion {
		minTealVersion = *caller.MinTealVersion
	}

	// Unlike NewEvalParams, do not add fee credit here. opTxSubmit has already done so.

	if caller.Proto.EnableAppCostPooling {
		for _, tx := range txg {
			if tx.Txn.Type == protocol.ApplicationCallTx {
				*caller.PooledApplicationBudget += caller.Proto.MaxAppProgramCost
			}
		}
	}

	ep := &EvalParams{
		Proto:                   caller.Proto,
		Trace:                   caller.Trace,
		TxnGroup:                txg,
		pastScratch:             make([]*scratchSpace, len(txg)),
		MinTealVersion:          &minTealVersion,
		FeeCredit:               caller.FeeCredit,
		Specials:                caller.Specials,
		PooledApplicationBudget: caller.PooledApplicationBudget,
		pooledAllowedInners:     caller.pooledAllowedInners,
		Ledger:                  caller.Ledger,
		created:                 caller.created,
		appAddrCache:            caller.appAddrCache,
		caller:                  caller,
	}
	return ep
}

type evalFunc func(cx *EvalContext) error
type checkFunc func(cx *EvalContext) error

type runMode uint64

const (
	// modeSig is LogicSig execution
	modeSig runMode = 1 << iota

	// modeApp is application/contract execution
	modeApp

	// local constant, run in any mode
	modeAny = modeSig | modeApp
)

func (r runMode) Any() bool {
	return r == modeAny
}

func (r runMode) String() string {
	switch r {
	case modeSig:
		return "Signature"
	case modeApp:
		return "Application"
	case modeAny:
		return "Any"
	default:
	}
	return "Unknown"
}

func (ep *EvalParams) log() logging.Logger {
	if ep.logger != nil {
		return ep.logger
	}
	return logging.Base()
}

// RecordAD notes ApplyData information that was derived outside of the logic
// package. For example, after a acfg transaction is processed, the AD created
// by the acfg is added to the EvalParams this way.
func (ep *EvalParams) RecordAD(gi int, ad transactions.ApplyData) {
	if ep.created == nil {
		// This is a simplified ep. It won't be used for app evaluation, and
		// shares the TxnGroup memory with the caller.  Don't touch anything!
		return
	}
	ep.TxnGroup[gi].ApplyData = ad
	if aid := ad.ConfigAsset; aid != 0 {
		ep.created.asas = append(ep.created.asas, aid)
	}
	if aid := ad.ApplicationID; aid != 0 {
		ep.created.apps = append(ep.created.apps, aid)
	}
}

type scratchSpace [256]stackValue

// EvalContext is the execution context of AVM bytecode.  It contains the full
// state of the running program, and tracks some of the things that the program
// has done, like log messages and inner transactions.
type EvalContext struct {
	*EvalParams

	// determines eval mode: runModeSignature or runModeApplication
	runModeFlags runMode

	// the index of the transaction being evaluated
	groupIndex int
	// the transaction being evaluated (initialized from groupIndex + ep.TxnGroup)
	txn *transactions.SignedTxnWithAD

	// Txn.EvalDelta maintains a summary of changes as we go.  We used to
	// compute this from the ledger after a full eval.  But now apps can call
	// apps.  When they do, all of the changes accumulate into the parent's
	// ledger, but Txn.EvalDelta should only have the changes from *this*
	// call. (The changes caused by children are deeper inside - in the
	// EvalDeltas of the InnerTxns inside this EvalDelta) Nice bonus - by
	// keeping the running changes, the debugger can be changed to display them
	// as the app runs.

	stack     []stackValue
	callstack []int

	appID   basics.AppIndex
	program []byte
	pc      int
	nextpc  int
	intc    []uint64
	bytec   [][]byte
	version uint64
	scratch scratchSpace

	subtxns []transactions.SignedTxnWithAD // place to build for itxn_submit
	cost    int                            // cost incurred so far
	logSize int                            // total log size so far

	// Set of PC values that branches we've seen so far might
	// go. So, if checkStep() skips one, that branch is trying to
	// jump into the middle of a multibyte instruction
	branchTargets map[int]bool

	// Set of PC values that we have begun a checkStep() with. So
	// if a back jump is going to a value that isn't here, it's
	// jumping into the middle of multibyte instruction.
	instructionStarts map[int]bool

	programHashCached crypto.Digest

	// Stores state & disassembly for the optional debugger
	debugState *DebugState
}

// StackType describes the type of a value on the operand stack
type StackType byte

const (
	// StackNone in an OpSpec shows that the op pops or yields nothing
	StackNone StackType = iota

	// StackAny in an OpSpec shows that the op pops or yield any type
	StackAny

	// StackUint64 in an OpSpec shows that the op pops or yields a uint64
	StackUint64

	// StackBytes in an OpSpec shows that the op pops or yields a []byte
	StackBytes
)

// StackTypes is an alias for a list of StackType with syntactic sugar
type StackTypes []StackType

func parseStackTypes(spec string) StackTypes {
	if spec == "" {
		return nil
	}
	types := make(StackTypes, len(spec))
	for i, letter := range spec {
		switch letter {
		case 'a':
			types[i] = StackAny
		case 'b':
			types[i] = StackBytes
		case 'i':
			types[i] = StackUint64
		case 'x':
			types[i] = StackNone
		default:
			panic(spec)
		}
	}
	return types
}

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

// Typed tells whether the StackType is a specific concrete type.
func (st StackType) Typed() bool {
	switch st {
	case StackUint64, StackBytes:
		return true
	}
	return false
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

// ClearStateBudgetError allows evaluation to signal that the caller should
// reject the transaction.  Normally, an error in evaluation would not cause a
// ClearState txn to fail. However, callers fail a txn for ClearStateBudgetError
// because the transaction has not provided enough budget to let ClearState do
// its job.
type ClearStateBudgetError struct {
	offered int
}

func (e ClearStateBudgetError) Error() string {
	return fmt.Sprintf("Attempted ClearState execution with low OpcodeBudget %d", e.offered)
}

// EvalContract executes stateful TEAL program as the gi'th transaction in params
func EvalContract(program []byte, gi int, aid basics.AppIndex, params *EvalParams) (bool, *EvalContext, error) {
	if params.Ledger == nil {
		return false, nil, errors.New("no ledger in contract eval")
	}
	if aid == 0 {
		return false, nil, errors.New("0 appId in contract eval")
	}
	cx := EvalContext{
		EvalParams:   params,
		runModeFlags: modeApp,
		groupIndex:   gi,
		txn:          &params.TxnGroup[gi],
		appID:        aid,
	}

	if cx.Proto.IsolateClearState && cx.txn.Txn.OnCompletion == transactions.ClearStateOC {
		if cx.PooledApplicationBudget != nil && *cx.PooledApplicationBudget < cx.Proto.MaxAppProgramCost {
			return false, nil, ClearStateBudgetError{*cx.PooledApplicationBudget}
		}
	}

	if cx.Trace != nil && cx.caller != nil {
		fmt.Fprintf(cx.Trace, "--- enter %d %s %v\n", aid, cx.txn.Txn.OnCompletion, cx.txn.Txn.ApplicationArgs)
	}
	pass, err := eval(program, &cx)
	if cx.Trace != nil && cx.caller != nil {
		fmt.Fprintf(cx.Trace, "--- exit  %d accept=%t\n", aid, pass)
	}

	// Save scratch for `gload`. We used to copy, but cx.scratch is quite large,
	// about 8k, and caused measurable CPU and memory demands.  Of course, these
	// should never be changed by later transactions.
	cx.pastScratch[cx.groupIndex] = &cx.scratch

	return pass, &cx, err
}

// EvalApp is a lighter weight interface that doesn't return the EvalContext
func EvalApp(program []byte, gi int, aid basics.AppIndex, params *EvalParams) (bool, error) {
	pass, _, err := EvalContract(program, gi, aid, params)
	return pass, err
}

// EvalSignature evaluates the logicsig of the ith transaction in params.
// A program passes successfully if it finishes with one int element on the stack that is non-zero.
func EvalSignature(gi int, params *EvalParams) (pass bool, err error) {
	cx := EvalContext{
		EvalParams:   params,
		runModeFlags: modeSig,
		groupIndex:   gi,
		txn:          &params.TxnGroup[gi],
	}
	return eval(cx.txn.Lsig.Logic, &cx)
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
			if cx.Trace != nil {
				errstr += cx.Trace.String()
			}
			err = PanicError{x, errstr}
			cx.EvalParams.log().Errorf("recovered panic in Eval: %w", err)
		}
	}()

	defer func() {
		// Ensure we update the debugger before exiting
		if cx.Debugger != nil {
			errDbg := cx.Debugger.Complete(cx.refreshDebugState(err))
			if err == nil {
				err = errDbg
			}
		}
	}()

	if (cx.EvalParams.Proto == nil) || (cx.EvalParams.Proto.LogicSigVersion == 0) {
		err = errLogicSigNotSupported
		return
	}
	if cx.txn.Lsig.Args != nil && len(cx.txn.Lsig.Args) > transactions.EvalMaxArgs {
		err = errTooManyArgs
		return
	}

	version, vlen, err := versionCheck(program, cx.EvalParams)
	if err != nil {
		return false, err
	}

	cx.version = version
	cx.pc = vlen
	// 16 is chosen to avoid growth for small programs, and so that repeated
	// doublings lead to a number just a bit above 1000, the max stack height.
	cx.stack = make([]stackValue, 0, 16)
	cx.program = program
	cx.txn.EvalDelta.GlobalDelta = basics.StateDelta{}
	cx.txn.EvalDelta.LocalDeltas = make(map[uint64]basics.StateDelta)

	if cx.Debugger != nil {
		cx.debugState = makeDebugState(cx)
		if derr := cx.Debugger.Register(cx.refreshDebugState(err)); derr != nil {
			return false, derr
		}
	}

	for (err == nil) && (cx.pc < len(cx.program)) {
		if cx.Debugger != nil {
			if derr := cx.Debugger.Update(cx.refreshDebugState(err)); derr != nil {
				return false, derr
			}
		}

		err = cx.step()
	}
	if err != nil {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "%3d %s\n", cx.pc, err)
		}

		return false, err
	}
	if len(cx.stack) != 1 {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "end stack:\n")
			for i, sv := range cx.stack {
				fmt.Fprintf(cx.Trace, "[%d] %s\n", i, sv)
			}
		}
		return false, fmt.Errorf("stack len is %d instead of 1", len(cx.stack))
	}
	if cx.stack[0].Bytes != nil {
		return false, errors.New("stack finished with bytes not int")
	}

	return cx.stack[0].Uint != 0, nil
}

// CheckContract should be faster than EvalContract.  It can perform
// static checks and reject programs that are invalid. Prior to v4,
// these static checks include a cost estimate that must be low enough
// (controlled by params.Proto).
func CheckContract(program []byte, params *EvalParams) error {
	return check(program, params, modeApp)
}

// CheckSignature should be faster than EvalSignature.  It can perform static
// checks and reject programs that are invalid. Prior to v4, these static checks
// include a cost estimate that must be low enough (controlled by params.Proto).
func CheckSignature(gi int, params *EvalParams) error {
	return check(params.TxnGroup[gi].Lsig.Logic, params, modeSig)
}

func check(program []byte, params *EvalParams, mode runMode) (err error) {
	defer func() {
		if x := recover(); x != nil {
			buf := make([]byte, 16*1024)
			stlen := runtime.Stack(buf, false)
			errstr := string(buf[:stlen])
			if params.Trace != nil {
				errstr += params.Trace.String()
			}
			err = PanicError{x, errstr}
			params.log().Errorf("recovered panic in Check: %s", err)
		}
	}()
	if (params.Proto == nil) || (params.Proto.LogicSigVersion == 0) {
		return errLogicSigNotSupported
	}

	version, vlen, err := versionCheck(program, params)
	if err != nil {
		return err
	}

	var cx EvalContext
	cx.version = version
	cx.pc = vlen
	cx.EvalParams = params
	cx.runModeFlags = mode
	cx.program = program
	cx.branchTargets = make(map[int]bool)
	cx.instructionStarts = make(map[int]bool)

	maxCost := cx.remainingBudget()
	staticCost := 0
	for cx.pc < len(cx.program) {
		prevpc := cx.pc
		stepCost, err := cx.checkStep()
		if err != nil {
			return fmt.Errorf("pc=%3d %w", cx.pc, err)
		}
		staticCost += stepCost
		if version < backBranchEnabledVersion && staticCost > maxCost {
			return fmt.Errorf("pc=%3d static cost budget of %d exceeded", cx.pc, maxCost)
		}
		if cx.pc <= prevpc {
			// Recall, this is advancing through opcodes
			// without evaluation. It always goes forward,
			// even if we're in v4 and the jump would go
			// back.
			return fmt.Errorf("pc=%3d pc did not advance", cx.pc)
		}
	}
	return nil
}

func versionCheck(program []byte, params *EvalParams) (uint64, int, error) {
	version, vlen, err := transactions.ProgramVersion(program)
	if err != nil {
		return 0, 0, err
	}
	if version > evalMaxVersion {
		return 0, 0, fmt.Errorf("program version %d greater than max supported version %d", version, evalMaxVersion)
	}
	if version > params.Proto.LogicSigVersion {
		return 0, 0, fmt.Errorf("program version %d greater than protocol supported version %d", version, params.Proto.LogicSigVersion)
	}

	if params.MinTealVersion == nil {
		minVersion := ComputeMinTealVersion(params.TxnGroup)
		params.MinTealVersion = &minVersion
	}
	if version < *params.MinTealVersion {
		return 0, 0, fmt.Errorf("program version must be >= %d for this transaction group, but have version %d", *params.MinTealVersion, version)
	}
	return version, vlen, nil
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

func (cx *EvalContext) remainingBudget() int {
	if cx.runModeFlags == modeSig {
		return int(cx.Proto.LogicSigMaxCost) - cx.cost
	}

	// restrict clear state programs from using more than standard unpooled budget
	// cx.Txn is not set during check()
	if cx.Proto.IsolateClearState && cx.txn != nil && cx.txn.Txn.OnCompletion == transactions.ClearStateOC {
		// Need not confirm that *cx.PooledApplicationBudget is also >0, as
		// ClearState programs are only run if *cx.PooledApplicationBudget >
		// MaxAppProgramCost at the start.
		return cx.Proto.MaxAppProgramCost - cx.cost
	}

	if cx.PooledApplicationBudget != nil {
		return *cx.PooledApplicationBudget
	}
	return cx.Proto.MaxAppProgramCost - cx.cost
}

func (cx *EvalContext) remainingInners() int {
	if cx.Proto.EnableInnerTransactionPooling && cx.pooledAllowedInners != nil {
		return *cx.pooledAllowedInners
	}
	// Before EnableInnerTransactionPooling, MaxInnerTransactions was the amount
	// allowed in a single txn. No consensus version should enable inner app
	// calls without turning on EnableInnerTransactionPoolin, else inner calls
	// could keep branching with "width" MaxInnerTransactions
	return cx.Proto.MaxInnerTransactions - len(cx.txn.EvalDelta.InnerTxns)
}

func (cx *EvalContext) step() error {
	opcode := cx.program[cx.pc]
	spec := &opsByOpcode[cx.version][opcode]

	// this check also ensures TEAL versioning: v2 opcodes are not in opsByOpcode[1] array
	if spec.op == nil {
		return fmt.Errorf("%3d illegal opcode 0x%02x", cx.pc, opcode)
	}
	if (cx.runModeFlags & spec.Modes) == 0 {
		return fmt.Errorf("%s not allowed in current mode", spec.Name)
	}

	// check args for stack underflow and types
	if len(cx.stack) < len(spec.Arg.Types) {
		return fmt.Errorf("stack underflow in %s", spec.Name)
	}
	first := len(cx.stack) - len(spec.Arg.Types)
	for i, argType := range spec.Arg.Types {
		if !opCompat(argType, cx.stack[first+i].argType()) {
			return fmt.Errorf("%s arg %d wanted %s but got %s", spec.Name, i, argType, cx.stack[first+i].typeName())
		}
	}

	deets := &spec.OpDetails
	if deets.Size != 0 && (cx.pc+deets.Size > len(cx.program)) {
		return fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, spec.Name)
	}

	// It's something like a 5-10% overhead on our simplest instructions to make
	// the Cost() call without the FullCost.compute() short-circuit, even
	// though Cost() tries to exit fast. Use BenchmarkUintMath to test changes.
	opcost := deets.FullCost.compute(cx.stack)
	if opcost <= 0 {
		opcost = deets.Cost(cx.program, cx.pc, cx.stack)
		if opcost <= 0 {
			return fmt.Errorf("%3d %s returned 0 cost", cx.pc, spec.Name)
		}
	}
	cx.cost += opcost
	if cx.PooledApplicationBudget != nil {
		*cx.PooledApplicationBudget -= opcost
	}

	if cx.remainingBudget() < 0 {
		// We're not going to execute the instruction, so give the cost back.
		// This only matters if this is an inner ClearState - the caller should
		// not be over debited. (Normally, failure causes total txtree failure.)
		cx.cost -= opcost
		if cx.PooledApplicationBudget != nil {
			*cx.PooledApplicationBudget += opcost
		}
		return fmt.Errorf("pc=%3d dynamic cost budget exceeded, executing %s: local program cost was %d",
			cx.pc, spec.Name, cx.cost)
	}

	preheight := len(cx.stack)
	err := spec.op(cx)

	if err == nil {
		postheight := len(cx.stack)
		if postheight-preheight != len(spec.Return.Types)-len(spec.Arg.Types) && !spec.AlwaysExits() {
			return fmt.Errorf("%s changed stack height improperly %d != %d",
				spec.Name, postheight-preheight, len(spec.Return.Types)-len(spec.Arg.Types))
		}
		first = postheight - len(spec.Return.Types)
		for i, argType := range spec.Return.Types {
			stackType := cx.stack[first+i].argType()
			if !opCompat(argType, stackType) {
				if spec.AlwaysExits() { // We test in the loop because it's the uncommon case.
					break
				}
				return fmt.Errorf("%s produced %s but intended %s", spec.Name, cx.stack[first+i].typeName(), argType)
			}
			if stackType == StackBytes && len(cx.stack[first+i].Bytes) > maxStringSize {
				return fmt.Errorf("%s produced a too big (%d) byte-array", spec.Name, len(cx.stack[first+i].Bytes))
			}
		}
	}

	// Delay checking and returning `err` so we have a chance to Trace the last instruction

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
		sourceLine, inner := disassemble(dstate, spec)
		if inner != nil {
			if err != nil { // don't override an error from evaluation
				return err
			}
			return inner
		}
		var stackString string
		if len(cx.stack) == 0 {
			stackString = "<empty stack>"
		} else {
			num := 1
			if len(spec.Return.Types) > 1 {
				num = len(spec.Return.Types)
			}
			// check for nil error here, because we might not return
			// values if we encounter an error in the opcode
			if err == nil {
				if len(cx.stack) < num {
					return fmt.Errorf("stack underflow: expected %d, have %d", num, len(cx.stack))
				}
				for i := 1; i <= num; i++ {
					stackString += fmt.Sprintf("(%s) ", cx.stack[len(cx.stack)-i])
				}
			}
		}
		fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, sourceLine, stackString)
	}

	if err != nil {
		return err
	}

	if len(cx.stack) > maxStackDepth {
		return errors.New("stack overflow")
	}
	if cx.nextpc != 0 {
		cx.pc = cx.nextpc
		cx.nextpc = 0
	} else {
		cx.pc += deets.Size
	}
	return nil
}

// oneBlank is a boring stack provided to deets.Cost during checkStep. It is
// good enough to allow Cost() to not crash. It would be incorrect to provide
// this stack if there were linear cost opcodes before backBranchEnabledVersion,
// because the static cost would be wrong. But then again, a static cost model
// wouldn't work before backBranchEnabledVersion, so such an opcode is already
// unacceptable. TestLinearOpcodes ensures.
var oneBlank = []stackValue{{Bytes: []byte{}}}

func (cx *EvalContext) checkStep() (int, error) {
	cx.instructionStarts[cx.pc] = true
	opcode := cx.program[cx.pc]
	spec := &opsByOpcode[cx.version][opcode]
	if spec.op == nil {
		return 0, fmt.Errorf("illegal opcode 0x%02x", opcode)
	}
	if (cx.runModeFlags & spec.Modes) == 0 {
		return 0, fmt.Errorf("%s not allowed in current mode", spec.Name)
	}
	deets := spec.OpDetails
	if deets.Size != 0 && (cx.pc+deets.Size > len(cx.program)) {
		return 0, fmt.Errorf("%s program ends short of immediate values", spec.Name)
	}
	opcost := deets.Cost(cx.program, cx.pc, oneBlank)
	if opcost <= 0 {
		return 0, fmt.Errorf("%s reported non-positive cost", spec.Name)
	}
	prevpc := cx.pc
	if deets.check != nil {
		err := deets.check(cx)
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
	for pc := prevpc + 1; pc < cx.pc; pc++ {
		if _, ok := cx.branchTargets[pc]; ok {
			return 0, fmt.Errorf("branch target %d is not an aligned instruction", pc)
		}
	}
	return opcost, nil
}

func opErr(cx *EvalContext) error {
	return errors.New("err opcode executed")
}

func opReturn(cx *EvalContext) error {
	// Achieve the end condition:
	// Take the last element on the stack and make it the return value (only element on the stack)
	// Move the pc to the end of the program
	last := len(cx.stack) - 1
	cx.stack[0] = cx.stack[last]
	cx.stack = cx.stack[:1]
	cx.nextpc = len(cx.program)
	return nil
}

func opAssert(cx *EvalContext) error {
	last := len(cx.stack) - 1
	if cx.stack[last].Uint != 0 {
		cx.stack = cx.stack[:last]
		return nil
	}
	return fmt.Errorf("assert failed pc=%d", cx.pc)
}

func opSwap(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[last], cx.stack[prev] = cx.stack[prev], cx.stack[last]
	return nil
}

func opSelect(cx *EvalContext) error {
	last := len(cx.stack) - 1 // condition on top
	prev := last - 1          // true is one down
	pprev := prev - 1         // false below that

	if cx.stack[last].Uint != 0 {
		cx.stack[pprev] = cx.stack[prev]
	}
	cx.stack = cx.stack[:prev]
	return nil
}

func opSHA256(cx *EvalContext) error {
	last := len(cx.stack) - 1
	hash := sha256.Sum256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
	return nil
}

// The NIST SHA3-256 is implemented for compatibility with ICON
func opSHA3_256(cx *EvalContext) error {
	last := len(cx.stack) - 1
	hash := sha3.Sum256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
	return nil
}

// The Keccak256 variant of SHA-3 is implemented for compatibility with Ethereum
func opKeccak256(cx *EvalContext) error {
	last := len(cx.stack) - 1
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(cx.stack[last].Bytes)
	hv := make([]byte, 0, hasher.Size())
	hv = hasher.Sum(hv)
	cx.stack[last].Bytes = hv
	return nil
}

// This is the hash commonly used in Algorand in crypto/util.go Hash()
//
// It is explicitly implemented here in terms of the specific hash for
// stability and portability in case the rest of Algorand ever moves
// to a different default hash. For stability of this language, at
// that time a new opcode should be made with the new hash.
func opSHA512_256(cx *EvalContext) error {
	last := len(cx.stack) - 1
	hash := sha512.Sum512_256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
	return nil
}

func opPlus(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	sum, carry := bits.Add64(cx.stack[prev].Uint, cx.stack[last].Uint, 0)
	if carry > 0 {
		return errors.New("+ overflowed")
	}
	cx.stack[prev].Uint = sum
	cx.stack = cx.stack[:last]
	return nil
}

func opAddw(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	sum, carry := bits.Add64(cx.stack[prev].Uint, cx.stack[last].Uint, 0)
	cx.stack[prev].Uint = carry
	cx.stack[last].Uint = sum
	return nil
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

func opDivModw(cx *EvalContext) error {
	loDen := len(cx.stack) - 1
	hiDen := loDen - 1
	if cx.stack[loDen].Uint == 0 && cx.stack[hiDen].Uint == 0 {
		return errors.New("/ 0")
	}
	loNum := loDen - 2
	hiNum := loDen - 3
	hiQuo, loQuo, hiRem, loRem :=
		opDivModwImpl(cx.stack[hiNum].Uint, cx.stack[loNum].Uint, cx.stack[hiDen].Uint, cx.stack[loDen].Uint)
	cx.stack[hiNum].Uint = hiQuo
	cx.stack[loNum].Uint = loQuo
	cx.stack[hiDen].Uint = hiRem
	cx.stack[loDen].Uint = loRem
	return nil
}

func opMinus(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > cx.stack[prev].Uint {
		return errors.New("- would result negative")
	}
	cx.stack[prev].Uint -= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opDiv(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		return errors.New("/ 0")
	}
	cx.stack[prev].Uint /= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opModulo(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		return errors.New("% 0")
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint % cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	high, low := bits.Mul64(cx.stack[prev].Uint, cx.stack[last].Uint)
	if high > 0 {
		return errors.New("* overflowed")
	}
	cx.stack[prev].Uint = low
	cx.stack = cx.stack[:last]
	return nil
}

func opMulw(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	high, low := bits.Mul64(cx.stack[prev].Uint, cx.stack[last].Uint)
	cx.stack[prev].Uint = high
	cx.stack[last].Uint = low
	return nil
}

func opDivw(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	pprev := last - 2
	hi := cx.stack[pprev].Uint
	lo := cx.stack[prev].Uint
	y := cx.stack[last].Uint
	// These two clauses catch what will cause panics in bits.Div64, so we get
	// nicer errors.
	if y == 0 {
		return errors.New("divw 0")
	}
	if y <= hi {
		return fmt.Errorf("divw overflow: %d <= %d", y, hi)
	}
	quo, _ := bits.Div64(hi, lo, y)
	cx.stack = cx.stack[:prev] // pop 2
	cx.stack[pprev].Uint = quo
	return nil
}

func opLt(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint < cx.stack[last].Uint
	cx.stack[prev].Uint = boolToUint(cond)
	cx.stack = cx.stack[:last]
	return nil
}

// opSwap, opLt, and opNot always succeed (return nil). So error checking elided in Gt,Le,Ge

func opGt(cx *EvalContext) error {
	opSwap(cx)
	return opLt(cx)
}

func opLe(cx *EvalContext) error {
	opGt(cx)
	return opNot(cx)
}

func opGe(cx *EvalContext) error {
	opLt(cx)
	return opNot(cx)
}

func opAnd(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := (cx.stack[prev].Uint != 0) && (cx.stack[last].Uint != 0)
	cx.stack[prev].Uint = boolToUint(cond)
	cx.stack = cx.stack[:last]
	return nil
}

func opOr(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := (cx.stack[prev].Uint != 0) || (cx.stack[last].Uint != 0)
	cx.stack[prev].Uint = boolToUint(cond)
	cx.stack = cx.stack[:last]
	return nil
}

func opEq(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	ta := cx.stack[prev].argType()
	tb := cx.stack[last].argType()
	if ta != tb {
		return fmt.Errorf("cannot compare (%s to %s)", cx.stack[prev].typeName(), cx.stack[last].typeName())
	}
	var cond bool
	if ta == StackBytes {
		cond = bytes.Equal(cx.stack[prev].Bytes, cx.stack[last].Bytes)
	} else {
		cond = cx.stack[prev].Uint == cx.stack[last].Uint
	}
	cx.stack[prev].Uint = boolToUint(cond)
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
	return nil
}

func opNeq(cx *EvalContext) error {
	err := opEq(cx)
	if err != nil {
		return err
	}
	return opNot(cx)
}

func opNot(cx *EvalContext) error {
	last := len(cx.stack) - 1
	cond := cx.stack[last].Uint == 0
	cx.stack[last].Uint = boolToUint(cond)
	return nil
}

func opLen(cx *EvalContext) error {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = uint64(len(cx.stack[last].Bytes))
	cx.stack[last].Bytes = nil
	return nil
}

func opItob(cx *EvalContext) error {
	last := len(cx.stack) - 1
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, cx.stack[last].Uint)
	// cx.stack[last].Uint is not cleared out as optimization
	// stackValue.argType() checks Bytes field first
	cx.stack[last].Bytes = ibytes
	return nil
}

func opBtoi(cx *EvalContext) error {
	last := len(cx.stack) - 1
	ibytes := cx.stack[last].Bytes
	if len(ibytes) > 8 {
		return fmt.Errorf("btoi arg too long, got [%d]bytes", len(ibytes))
	}
	value := uint64(0)
	for _, b := range ibytes {
		value = value << 8
		value = value | (uint64(b) & 0x0ff)
	}
	cx.stack[last].Uint = value
	cx.stack[last].Bytes = nil
	return nil
}

func opBitOr(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint | cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opBitAnd(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint & cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opBitXor(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint ^ cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opBitNot(cx *EvalContext) error {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = cx.stack[last].Uint ^ 0xffffffffffffffff
	return nil
}

func opShiftLeft(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > 63 {
		return fmt.Errorf("shl arg too big, (%d)", cx.stack[last].Uint)
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint << cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opShiftRight(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > 63 {
		return fmt.Errorf("shr arg too big, (%d)", cx.stack[last].Uint)
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint >> cx.stack[last].Uint
	cx.stack = cx.stack[:last]
	return nil
}

func opSqrt(cx *EvalContext) error {
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
	return nil
}

func opBitLen(cx *EvalContext) error {
	last := len(cx.stack) - 1
	if cx.stack[last].argType() == StackUint64 {
		cx.stack[last].Uint = uint64(bits.Len64(cx.stack[last].Uint))
		return nil
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
	return nil
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

func opExp(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1

	exp := cx.stack[last].Uint
	base := cx.stack[prev].Uint
	val, err := opExpImpl(base, exp)
	if err != nil {
		return err
	}
	cx.stack[prev].Uint = val
	cx.stack = cx.stack[:last]
	return nil
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
		answer.Mul(answer, bigbase)
		if answer.BitLen() > 128 {
			return &big.Int{}, fmt.Errorf("%d^%d overflow", base, exp)
		}
	}
	return answer, nil
}

func opExpw(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1

	exp := cx.stack[last].Uint
	base := cx.stack[prev].Uint
	val, err := opExpwImpl(base, exp)
	if err != nil {
		return err
	}
	hi := new(big.Int).Rsh(val, 64).Uint64()
	lo := val.Uint64()

	cx.stack[prev].Uint = hi
	cx.stack[last].Uint = lo
	return nil
}

func opBytesBinOp(cx *EvalContext, result *big.Int, op func(x, y *big.Int) *big.Int) error {
	last := len(cx.stack) - 1
	prev := last - 1

	if len(cx.stack[last].Bytes) > maxByteMathSize || len(cx.stack[prev].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	rhs := new(big.Int).SetBytes(cx.stack[last].Bytes)
	lhs := new(big.Int).SetBytes(cx.stack[prev].Bytes)
	op(lhs, rhs) // op's receiver has already been bound to result
	if result.Sign() < 0 {
		return errors.New("byte math would have negative result")
	}
	cx.stack[prev].Bytes = result.Bytes()
	cx.stack = cx.stack[:last]
	return nil
}

func opBytesPlus(cx *EvalContext) error {
	result := new(big.Int)
	return opBytesBinOp(cx, result, result.Add)
}

func opBytesMinus(cx *EvalContext) error {
	result := new(big.Int)
	return opBytesBinOp(cx, result, result.Sub)
}

func opBytesDiv(cx *EvalContext) error {
	result := new(big.Int)
	var inner error
	checkDiv := func(x, y *big.Int) *big.Int {
		if y.BitLen() == 0 {
			inner = errors.New("division by zero")
			return new(big.Int)
		}
		return result.Div(x, y)
	}
	err := opBytesBinOp(cx, result, checkDiv)
	if err != nil {
		return err
	}
	return inner
}

func opBytesMul(cx *EvalContext) error {
	result := new(big.Int)
	return opBytesBinOp(cx, result, result.Mul)
}

func opBytesSqrt(cx *EvalContext) error {
	last := len(cx.stack) - 1

	if len(cx.stack[last].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	val := new(big.Int).SetBytes(cx.stack[last].Bytes)
	val.Sqrt(val)
	cx.stack[last].Bytes = val.Bytes()
	return nil
}

func opBytesLt(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1

	if len(cx.stack[last].Bytes) > maxByteMathSize || len(cx.stack[prev].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	rhs := new(big.Int).SetBytes(cx.stack[last].Bytes)
	lhs := new(big.Int).SetBytes(cx.stack[prev].Bytes)
	cx.stack[prev].Bytes = nil
	cx.stack[prev].Uint = boolToUint(lhs.Cmp(rhs) < 0)
	cx.stack = cx.stack[:last]
	return nil
}

func opBytesGt(cx *EvalContext) error {
	opSwap(cx)
	return opBytesLt(cx)
}

func opBytesLe(cx *EvalContext) error {
	err := opBytesGt(cx)
	if err != nil {
		return err
	}
	return opNot(cx)
}

func opBytesGe(cx *EvalContext) error {
	err := opBytesLt(cx)
	if err != nil {
		return err
	}
	return opNot(cx)
}

func opBytesEq(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1

	if len(cx.stack[last].Bytes) > maxByteMathSize || len(cx.stack[prev].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	rhs := new(big.Int).SetBytes(cx.stack[last].Bytes)
	lhs := new(big.Int).SetBytes(cx.stack[prev].Bytes)
	cx.stack[prev].Bytes = nil
	cx.stack[prev].Uint = boolToUint(lhs.Cmp(rhs) == 0)
	cx.stack = cx.stack[:last]
	return nil
}

func opBytesNeq(cx *EvalContext) error {
	err := opBytesEq(cx)
	if err != nil {
		return err
	}
	return opNot(cx)
}

func opBytesModulo(cx *EvalContext) error {
	result := new(big.Int)
	var inner error
	checkMod := func(x, y *big.Int) *big.Int {
		if y.BitLen() == 0 {
			inner = errors.New("modulo by zero")
			return new(big.Int)
		}
		return result.Mod(x, y)
	}
	err := opBytesBinOp(cx, result, checkMod)
	if err != nil {
		return err
	}
	return inner
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

func opBytesBitOr(cx *EvalContext) error {
	a, b := opBytesBinaryLogicPrep(cx)
	for i := range a {
		a[i] = a[i] | b[i]
	}
	return nil
}

func opBytesBitAnd(cx *EvalContext) error {
	a, b := opBytesBinaryLogicPrep(cx)
	for i := range a {
		a[i] = a[i] & b[i]
	}
	return nil
}

func opBytesBitXor(cx *EvalContext) error {
	a, b := opBytesBinaryLogicPrep(cx)
	for i := range a {
		a[i] = a[i] ^ b[i]
	}
	return nil
}

func opBytesBitNot(cx *EvalContext) error {
	last := len(cx.stack) - 1

	fresh := make([]byte, len(cx.stack[last].Bytes))
	for i, b := range cx.stack[last].Bytes {
		fresh[i] = ^b
	}
	cx.stack[last].Bytes = fresh
	return nil
}

func opBytesZero(cx *EvalContext) error {
	last := len(cx.stack) - 1
	length := cx.stack[last].Uint
	if length > maxStringSize {
		return fmt.Errorf("bzero attempted to create a too large string")
	}
	cx.stack[last].Bytes = make([]byte, length)
	return nil
}

func opIntConstBlock(cx *EvalContext) error {
	var err error
	cx.intc, cx.nextpc, err = parseIntcblock(cx.program, cx.pc+1)
	return err
}

func opIntConstN(cx *EvalContext, n byte) error {
	if int(n) >= len(cx.intc) {
		return fmt.Errorf("intc [%d] beyond %d constants", n, len(cx.intc))
	}
	cx.stack = append(cx.stack, stackValue{Uint: cx.intc[n]})
	return nil
}
func opIntConstLoad(cx *EvalContext) error {
	n := cx.program[cx.pc+1]
	return opIntConstN(cx, n)
}
func opIntConst0(cx *EvalContext) error {
	return opIntConstN(cx, 0)
}
func opIntConst1(cx *EvalContext) error {
	return opIntConstN(cx, 1)
}
func opIntConst2(cx *EvalContext) error {
	return opIntConstN(cx, 2)
}
func opIntConst3(cx *EvalContext) error {
	return opIntConstN(cx, 3)
}

func opPushInt(cx *EvalContext) error {
	pos := cx.pc + 1
	val, bytesUsed := binary.Uvarint(cx.program[pos:])
	if bytesUsed <= 0 {
		return fmt.Errorf("could not decode int at program[%d]", pos)
	}
	sv := stackValue{Uint: val}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = pos + bytesUsed
	return nil
}

func opByteConstBlock(cx *EvalContext) error {
	var err error
	cx.bytec, cx.nextpc, err = parseBytecBlock(cx.program, cx.pc+1)
	return err
}

func opByteConstN(cx *EvalContext, n uint) error {
	if n >= uint(len(cx.bytec)) {
		return fmt.Errorf("bytec [%d] beyond %d constants", n, len(cx.bytec))
	}
	cx.stack = append(cx.stack, stackValue{Bytes: cx.bytec[n]})
	return nil
}
func opByteConstLoad(cx *EvalContext) error {
	n := uint(cx.program[cx.pc+1])
	return opByteConstN(cx, n)
}
func opByteConst0(cx *EvalContext) error {
	return opByteConstN(cx, 0)
}
func opByteConst1(cx *EvalContext) error {
	return opByteConstN(cx, 1)
}
func opByteConst2(cx *EvalContext) error {
	return opByteConstN(cx, 2)
}
func opByteConst3(cx *EvalContext) error {
	return opByteConstN(cx, 3)
}

func opPushBytes(cx *EvalContext) error {
	pos := cx.pc + 1
	length, bytesUsed := binary.Uvarint(cx.program[pos:])
	if bytesUsed <= 0 {
		return fmt.Errorf("could not decode length at program[%d]", pos)
	}
	pos += bytesUsed
	end := uint64(pos) + length
	if end > uint64(len(cx.program)) || end < uint64(pos) {
		return fmt.Errorf("pushbytes too long at program[%d]", pos)
	}
	sv := stackValue{Bytes: cx.program[pos:end]}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = int(end)
	return nil
}

func opArgN(cx *EvalContext, n uint64) error {
	if n >= uint64(len(cx.txn.Lsig.Args)) {
		return fmt.Errorf("cannot load arg[%d] of %d", n, len(cx.txn.Lsig.Args))
	}
	val := nilToEmpty(cx.txn.Lsig.Args[n])
	cx.stack = append(cx.stack, stackValue{Bytes: val})
	return nil
}

func opArg(cx *EvalContext) error {
	n := uint64(cx.program[cx.pc+1])
	return opArgN(cx, n)
}
func opArg0(cx *EvalContext) error {
	return opArgN(cx, 0)
}
func opArg1(cx *EvalContext) error {
	return opArgN(cx, 1)
}
func opArg2(cx *EvalContext) error {
	return opArgN(cx, 2)
}
func opArg3(cx *EvalContext) error {
	return opArgN(cx, 3)
}
func opArgs(cx *EvalContext) error {
	last := len(cx.stack) - 1
	n := cx.stack[last].Uint
	// Pop the index and push the result back on the stack.
	cx.stack = cx.stack[:last]
	return opArgN(cx, n)
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
		return 0, fmt.Errorf("branch target %d outside of program", target)
	}

	return target, nil
}

// checks any branch that is {op} {int16 be offset}
func checkBranch(cx *EvalContext) error {
	target, err := branchTarget(cx)
	if err != nil {
		return err
	}
	if target < cx.pc+3 {
		// If a branch goes backwards, we should have already noted that an instruction began at that location.
		if _, ok := cx.instructionStarts[target]; !ok {
			return fmt.Errorf("back branch target %d is not an aligned instruction", target)
		}
	}
	cx.branchTargets[target] = true
	return nil
}
func opBnz(cx *EvalContext) error {
	last := len(cx.stack) - 1
	cx.nextpc = cx.pc + 3
	isNonZero := cx.stack[last].Uint != 0
	cx.stack = cx.stack[:last] // pop
	if isNonZero {
		target, err := branchTarget(cx)
		if err != nil {
			return err
		}
		cx.nextpc = target
	}
	return nil
}

func opBz(cx *EvalContext) error {
	last := len(cx.stack) - 1
	cx.nextpc = cx.pc + 3
	isZero := cx.stack[last].Uint == 0
	cx.stack = cx.stack[:last] // pop
	if isZero {
		target, err := branchTarget(cx)
		if err != nil {
			return err
		}
		cx.nextpc = target
	}
	return nil
}

func opB(cx *EvalContext) error {
	target, err := branchTarget(cx)
	if err != nil {
		return err
	}
	cx.nextpc = target
	return nil
}

func opCallSub(cx *EvalContext) error {
	cx.callstack = append(cx.callstack, cx.pc+3)
	return opB(cx)
}

func opRetSub(cx *EvalContext) error {
	top := len(cx.callstack) - 1
	if top < 0 {
		return errors.New("retsub with empty callstack")
	}
	target := cx.callstack[top]
	cx.callstack = cx.callstack[:top]
	cx.nextpc = target
	return nil
}

func opPop(cx *EvalContext) error {
	last := len(cx.stack) - 1
	cx.stack = cx.stack[:last]
	return nil
}

func opDup(cx *EvalContext) error {
	last := len(cx.stack) - 1
	sv := cx.stack[last]
	cx.stack = append(cx.stack, sv)
	return nil
}

func opDup2(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack = append(cx.stack, cx.stack[prev:]...)
	return nil
}

func opDig(cx *EvalContext) error {
	depth := int(cx.program[cx.pc+1])
	idx := len(cx.stack) - 1 - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand dig
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		return fmt.Errorf("dig %d with stack size = %d", depth, len(cx.stack))
	}
	sv := cx.stack[idx]
	cx.stack = append(cx.stack, sv)
	return nil
}

func opCover(cx *EvalContext) error {
	depth := int(cx.program[cx.pc+1])
	topIdx := len(cx.stack) - 1
	idx := topIdx - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand cover
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		return fmt.Errorf("cover %d with stack size = %d", depth, len(cx.stack))
	}
	sv := cx.stack[topIdx]
	copy(cx.stack[idx+1:], cx.stack[idx:])
	cx.stack[idx] = sv
	return nil
}

func opUncover(cx *EvalContext) error {
	depth := int(cx.program[cx.pc+1])
	topIdx := len(cx.stack) - 1
	idx := topIdx - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand uncover
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		return fmt.Errorf("uncover %d with stack size = %d", depth, len(cx.stack))
	}

	sv := cx.stack[idx]
	copy(cx.stack[idx:], cx.stack[idx+1:])
	cx.stack[topIdx] = sv
	return nil
}

func (cx *EvalContext) assetHoldingToValue(holding *basics.AssetHolding, fs assetHoldingFieldSpec) (sv stackValue, err error) {
	switch fs.field {
	case AssetBalance:
		sv.Uint = holding.Amount
	case AssetFrozen:
		sv.Uint = boolToUint(holding.Frozen)
	default:
		return sv, fmt.Errorf("invalid asset_holding_get field %d", fs.field)
	}

	if fs.ftype != sv.argType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.argType())
	}
	return sv, nil
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
		return sv, fmt.Errorf("invalid asset_params_get field %d", fs.field)
	}

	if fs.ftype != sv.argType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.argType())
	}
	return sv, nil
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
		return sv, fmt.Errorf("invalid app_params_get field %d", fs.field)
	}

	if fs.ftype != sv.argType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.argType())
	}
	return sv, nil
}

// TxnFieldToTealValue is a thin wrapper for txnFieldToStack for external use
func TxnFieldToTealValue(txn *transactions.Transaction, groupIndex int, field TxnField, arrayFieldIdx uint64, inner bool) (basics.TealValue, error) {
	if groupIndex < 0 {
		return basics.TealValue{}, fmt.Errorf("negative groupIndex %d", groupIndex)
	}
	var cx EvalContext
	stxnad := &transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: *txn}}
	fs, ok := txnFieldSpecByField(field)
	if !ok {
		return basics.TealValue{}, fmt.Errorf("invalid field %s", field)
	}
	sv, err := cx.txnFieldToStack(stxnad, &fs, arrayFieldIdx, groupIndex, inner)
	return sv.toTealValue(), err
}

// currentTxID is a convenience method to get the Txid for the txn being evaluated
func (cx *EvalContext) currentTxID() transactions.Txid {
	if cx.Proto.UnifyInnerTxIDs {
		// can't just return cx.txn.ID() because I might be an inner txn
		return cx.getTxID(&cx.txn.Txn, cx.groupIndex, false)
	}

	// original behavior, for backwards comatability
	return cx.txn.ID()
}

// getTxIDNotUnified is a backwards-compatible getTxID used when the consensus param UnifyInnerTxIDs
// is false. DO NOT call directly, and DO NOT change its behavior
func (cx *EvalContext) getTxIDNotUnified(txn *transactions.Transaction, groupIndex int) transactions.Txid {
	if cx.EvalParams.txidCache == nil {
		cx.EvalParams.txidCache = make(map[int]transactions.Txid, len(cx.TxnGroup))
	}

	txid, ok := cx.EvalParams.txidCache[groupIndex]
	if !ok {
		if cx.caller != nil {
			innerOffset := len(cx.caller.txn.EvalDelta.InnerTxns)
			txid = txn.InnerID(cx.caller.txn.ID(), innerOffset+groupIndex)
		} else {
			txid = txn.ID()
		}
		cx.EvalParams.txidCache[groupIndex] = txid
	}

	return txid
}

func (cx *EvalContext) getTxID(txn *transactions.Transaction, groupIndex int, inner bool) transactions.Txid {
	// inner indicates that groupIndex is an index into the most recent inner txn group

	if cx.EvalParams == nil { // Special case, called through TxnFieldToTealValue. No EvalParams, no caching.
		return txn.ID()
	}

	if !cx.Proto.UnifyInnerTxIDs {
		// original behavior, for backwards comatability
		return cx.getTxIDNotUnified(txn, groupIndex)
	}

	if inner {
		// Initialize innerTxidCache if necessary
		if cx.EvalParams.innerTxidCache == nil {
			cx.EvalParams.innerTxidCache = make(map[int]transactions.Txid)
		}

		txid, ok := cx.EvalParams.innerTxidCache[groupIndex]
		if !ok {
			// We're referencing an inner and the current txn is the parent
			myTxid := cx.currentTxID()
			lastGroupLen := len(cx.getLastInnerGroup())
			// innerIndex is the referenced inner txn's index in cx.txn.EvalDelta.InnerTxns
			innerIndex := len(cx.txn.EvalDelta.InnerTxns) - lastGroupLen + groupIndex
			txid = txn.InnerID(myTxid, innerIndex)
			cx.EvalParams.innerTxidCache[groupIndex] = txid
		}

		return txid
	}

	// Initialize txidCache if necessary
	if cx.EvalParams.txidCache == nil {
		cx.EvalParams.txidCache = make(map[int]transactions.Txid, len(cx.TxnGroup))
	}

	txid, ok := cx.EvalParams.txidCache[groupIndex]
	if !ok {
		if cx.caller != nil {
			// We're referencing a peer txn, not my inner, but I am an inner
			parentTxid := cx.caller.currentTxID()
			innerIndex := len(cx.caller.txn.EvalDelta.InnerTxns) + groupIndex
			txid = txn.InnerID(parentTxid, innerIndex)
		} else {
			// We're referencing a peer txn and I am not an inner
			txid = txn.ID()
		}
		cx.EvalParams.txidCache[groupIndex] = txid
	}

	return txid
}

func (cx *EvalContext) txnFieldToStack(stxn *transactions.SignedTxnWithAD, fs *txnFieldSpec, arrayFieldIdx uint64, groupIndex int, inner bool) (sv stackValue, err error) {
	if fs.effects {
		if cx.runModeFlags == modeSig {
			return sv, fmt.Errorf("txn[%s] not allowed in current mode", fs.field)
		}
		if cx.version < txnEffectsVersion && !inner {
			return sv, errors.New("Unable to obtain effects from top-level transactions")
		}
	}
	if inner {
		// Before we had inner apps, we did not allow these, since we had no inner groups.
		if cx.version < innerAppsEnabledVersion && (fs.field == GroupIndex || fs.field == TxID) {
			err = fmt.Errorf("illegal field for inner transaction %s", fs.field)
			return
		}
	}
	err = nil
	txn := &stxn.SignedTxn.Txn
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
	case StateProofPK:
		sv.Bytes = txn.StateProofPK[:]
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
		sv.Uint = txnTypeMap[string(txn.Type)]
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
		txid := cx.getTxID(txn, groupIndex, inner)
		sv.Bytes = txid[:]
	case Lease:
		sv.Bytes = txn.Lease[:]
	case ApplicationID:
		sv.Uint = uint64(txn.ApplicationID)
	case OnCompletion:
		sv.Uint = uint64(txn.OnCompletion)

	case ApplicationArgs:
		if arrayFieldIdx >= uint64(len(txn.ApplicationArgs)) {
			return sv, fmt.Errorf("invalid ApplicationArgs index %d", arrayFieldIdx)
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
				return sv, fmt.Errorf("invalid Accounts index %d", arrayFieldIdx)
			}
			sv.Bytes = txn.Accounts[arrayFieldIdx-1][:]
		}
	case NumAccounts:
		sv.Uint = uint64(len(txn.Accounts))

	case Assets:
		if arrayFieldIdx >= uint64(len(txn.ForeignAssets)) {
			return sv, fmt.Errorf("invalid Assets index %d", arrayFieldIdx)
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
				return sv, fmt.Errorf("invalid Applications index %d", arrayFieldIdx)
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

	case Logs:
		if arrayFieldIdx >= uint64(len(stxn.EvalDelta.Logs)) {
			return sv, fmt.Errorf("invalid Logs index %d", arrayFieldIdx)
		}
		sv.Bytes = nilToEmpty([]byte(stxn.EvalDelta.Logs[arrayFieldIdx]))
	case NumLogs:
		sv.Uint = uint64(len(stxn.EvalDelta.Logs))
	case LastLog:
		if logs := len(stxn.EvalDelta.Logs); logs > 0 {
			sv.Bytes = nilToEmpty([]byte(stxn.EvalDelta.Logs[logs-1]))
		} else {
			sv.Bytes = nilToEmpty(nil)
		}
	case CreatedAssetID:
		sv.Uint = uint64(stxn.ApplyData.ConfigAsset)
	case CreatedApplicationID:
		sv.Uint = uint64(stxn.ApplyData.ApplicationID)

	default:
		return sv, fmt.Errorf("invalid txn field %s", fs.field)
	}

	if fs.ftype != sv.argType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.argType())
	}
	return sv, nil
}

func (cx *EvalContext) fetchField(field TxnField, expectArray bool) (*txnFieldSpec, error) {
	fs, ok := txnFieldSpecByField(field)
	if !ok || fs.version > cx.version {
		return nil, fmt.Errorf("invalid txn field %d", field)
	}
	if expectArray != fs.array {
		if expectArray {
			return nil, fmt.Errorf("unsupported array field %d", field)
		}
		return nil, fmt.Errorf("invalid txn field %d", field)
	}
	return &fs, nil
}

type txnSource int

const (
	srcGroup txnSource = iota
	srcInner
	srcInnerGroup
)

// opTxnImpl implements all of the txn variants.  Each form of txn opcode should
// be able to get its work done with one call here, after collecting the args in
// the most straightforward way possible. They ought to do no error checking, so
// that it is all collected here.
func (cx *EvalContext) opTxnImpl(gi uint64, src txnSource, field TxnField, ai uint64, expectArray bool) (sv stackValue, err error) {
	fs, err := cx.fetchField(field, expectArray)
	if err != nil {
		return sv, err
	}

	var group []transactions.SignedTxnWithAD
	switch src {
	case srcGroup:
		if fs.effects && gi >= uint64(cx.groupIndex) {
			// Test mode so that error is clearer
			if cx.runModeFlags == modeSig {
				return sv, fmt.Errorf("txn[%s] not allowed in current mode", fs.field)
			}
			return sv, fmt.Errorf("txn effects can only be read from past txns %d %d", gi, cx.groupIndex)
		}
		group = cx.TxnGroup
	case srcInner:
		group = cx.getLastInner()
	case srcInnerGroup:
		group = cx.getLastInnerGroup()
	}

	// We cast the length up, rather than gi down, in case gi overflows `int`.
	if gi >= uint64(len(group)) {
		return sv, fmt.Errorf("txn index %d, len(group) is %d", gi, len(group))
	}
	tx := &group[gi]

	// int(gi) is safe because gi < len(group). Slices in Go cannot exceed `int`
	sv, err = cx.txnFieldToStack(tx, fs, ai, int(gi), src != srcGroup)
	if err != nil {
		return sv, err
	}

	return sv, nil
}

func opTxn(cx *EvalContext) error {
	gi := uint64(cx.groupIndex)
	field := TxnField(cx.program[cx.pc+1])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, 0, false)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opTxna(cx *EvalContext) error {
	gi := uint64(cx.groupIndex)
	field := TxnField(cx.program[cx.pc+1])
	ai := uint64(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opTxnas(cx *EvalContext) error {
	last := len(cx.stack) - 1

	gi := uint64(cx.groupIndex)
	field := TxnField(cx.program[cx.pc+1])
	ai := cx.stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack[last] = sv
	return nil
}

func opGtxn(cx *EvalContext) error {
	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, 0, false)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opGtxna(cx *EvalContext) error {
	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])
	ai := uint64(cx.program[cx.pc+3])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opGtxnas(cx *EvalContext) error {
	last := len(cx.stack) - 1

	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])
	ai := cx.stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack[last] = sv
	return nil
}

func opGtxns(cx *EvalContext) error {
	last := len(cx.stack) - 1

	gi := cx.stack[last].Uint
	field := TxnField(cx.program[cx.pc+1])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, 0, false)
	if err != nil {
		return err
	}

	cx.stack[last] = sv
	return nil
}

func opGtxnsa(cx *EvalContext) error {
	last := len(cx.stack) - 1

	gi := cx.stack[last].Uint
	field := TxnField(cx.program[cx.pc+1])
	ai := uint64(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack[last] = sv
	return nil
}

func opGtxnsas(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1

	gi := cx.stack[prev].Uint
	field := TxnField(cx.program[cx.pc+1])
	ai := cx.stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack[prev] = sv
	cx.stack = cx.stack[:last]
	return nil
}

func opItxn(cx *EvalContext) error {
	field := TxnField(cx.program[cx.pc+1])

	sv, err := cx.opTxnImpl(0, srcInner, field, 0, false)
	if err != nil {
		return err
	}
	cx.stack = append(cx.stack, sv)
	return nil
}

func opItxna(cx *EvalContext) error {
	field := TxnField(cx.program[cx.pc+1])
	ai := uint64(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(0, srcInner, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opItxnas(cx *EvalContext) error {
	last := len(cx.stack) - 1

	field := TxnField(cx.program[cx.pc+1])
	ai := cx.stack[last].Uint

	sv, err := cx.opTxnImpl(0, srcInner, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack[last] = sv
	return nil
}

func (cx *EvalContext) getLastInner() []transactions.SignedTxnWithAD {
	inners := cx.txn.EvalDelta.InnerTxns
	// If there are no inners yet, return empty slice, which will result in error
	if len(inners) == 0 {
		return inners
	}
	return inners[len(inners)-1:]
}

func (cx *EvalContext) getLastInnerGroup() []transactions.SignedTxnWithAD {
	inners := cx.txn.EvalDelta.InnerTxns
	// If there are no inners yet, return empty slice, which will result in error
	if len(inners) == 0 {
		return inners
	}
	gid := inners[len(inners)-1].Txn.Group
	// If last inner was a singleton, return it as a slice.
	if gid.IsZero() {
		return inners[len(inners)-1:]
	}
	// Look back for the first non-matching inner (by group) to find beginning
	for i := len(inners) - 2; i >= 0; i-- {
		if inners[i].Txn.Group != gid {
			return inners[i+1:]
		}
	}
	// All have the same (non-zero) group. Return all
	return inners
}

func opGitxn(cx *EvalContext) error {
	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(gi, srcInnerGroup, field, 0, false)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opGitxna(cx *EvalContext) error {
	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])
	ai := uint64(cx.program[cx.pc+3])

	sv, err := cx.opTxnImpl(gi, srcInnerGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opGitxnas(cx *EvalContext) error {
	last := len(cx.stack) - 1

	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])
	ai := cx.stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcInnerGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.stack[last] = sv
	return nil
}

func opGaidImpl(cx *EvalContext, giw uint64, opName string) (sv stackValue, err error) {
	if giw >= uint64(len(cx.TxnGroup)) {
		return sv, fmt.Errorf("%s lookup TxnGroup[%d] but it only has %d", opName, giw, len(cx.TxnGroup))
	}
	// Is now assured smalled than a len() so fits in int.
	gi := int(giw)
	if gi > cx.groupIndex {
		return sv, fmt.Errorf("%s can't get creatable ID of txn ahead of the current one (index %d) in the transaction group", opName, gi)
	}
	if gi == cx.groupIndex {
		return sv, fmt.Errorf("%s is only for accessing creatable IDs of previous txns, use `global CurrentApplicationID` instead to access the current app's creatable ID", opName)
	}
	if txn := cx.TxnGroup[gi].Txn; !(txn.Type == protocol.ApplicationCallTx || txn.Type == protocol.AssetConfigTx) {
		return sv, fmt.Errorf("can't use %s on txn that is not an app call nor an asset config txn with index %d", opName, gi)
	}

	if aid := cx.TxnGroup[gi].ApplyData.ConfigAsset; aid != 0 {
		return stackValue{Uint: uint64(aid)}, nil
	}
	if aid := cx.TxnGroup[gi].ApplyData.ApplicationID; aid != 0 {
		return stackValue{Uint: uint64(aid)}, nil
	}
	return sv, fmt.Errorf("%s: index %d did not create anything", opName, gi)
}

func opGaid(cx *EvalContext) error {
	gi := uint64(cx.program[cx.pc+1])
	sv, err := opGaidImpl(cx, gi, "gaid")
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opGaids(cx *EvalContext) error {
	last := len(cx.stack) - 1
	gi := cx.stack[last].Uint

	sv, err := opGaidImpl(cx, gi, "gaids")
	if err != nil {
		return err
	}

	cx.stack[last] = sv
	return nil
}

func (cx *EvalContext) getRound() uint64 {
	return uint64(cx.Ledger.Round())
}

func (cx *EvalContext) getLatestTimestamp() (uint64, error) {
	ts := cx.Ledger.LatestTimestamp()
	if ts < 0 {
		return 0, fmt.Errorf("latest timestamp %d < 0", ts)
	}
	return uint64(ts), nil
}

// getApplicationAddress memoizes app.Address() across a tx group's evaluation
func (cx *EvalContext) getApplicationAddress(app basics.AppIndex) basics.Address {
	/* Do not instantiate the cache here, that would mask a programming error.
	   The cache must be instantiated at EvalParams construction time, so that
	   proper sharing with inner EvalParams can work. */
	appAddr, ok := cx.appAddrCache[app]
	if !ok {
		appAddr = app.Address()
		cx.appAddrCache[app] = appAddr
	}

	return appAddr
}

func (cx *EvalContext) getCreatorAddress() ([]byte, error) {
	_, creator, err := cx.Ledger.AppParams(cx.appID)
	if err != nil {
		return nil, fmt.Errorf("No params for current app")
	}
	return creator[:], nil
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
		sv.Uint = cx.getRound()
	case LatestTimestamp:
		sv.Uint, err = cx.getLatestTimestamp()
	case CurrentApplicationID:
		sv.Uint = uint64(cx.appID)
	case CurrentApplicationAddress:
		addr := cx.getApplicationAddress(cx.appID)
		sv.Bytes = addr[:]
	case CreatorAddress:
		sv.Bytes, err = cx.getCreatorAddress()
	case GroupID:
		sv.Bytes = cx.txn.Txn.Group[:]
	case OpcodeBudget:
		sv.Uint = uint64(cx.remainingBudget())
	case CallerApplicationID:
		if cx.caller != nil {
			sv.Uint = uint64(cx.caller.appID)
		} else {
			sv.Uint = 0
		}
	case CallerApplicationAddress:
		if cx.caller != nil {
			addr := cx.caller.getApplicationAddress(cx.caller.appID)
			sv.Bytes = addr[:]
		} else {
			sv.Bytes = zeroAddress[:]
		}
	default:
		err = fmt.Errorf("invalid global field %d", fs.field)
	}

	if fs.ftype != sv.argType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.argType())
	}

	return sv, err
}

func opGlobal(cx *EvalContext) error {
	globalField := GlobalField(cx.program[cx.pc+1])
	fs, ok := globalFieldSpecByField(globalField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid global field %s", globalField)
	}
	if (cx.runModeFlags & fs.mode) == 0 {
		return fmt.Errorf("global[%s] not allowed in current mode", globalField)
	}

	sv, err := cx.globalFieldToValue(fs)
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, sv)
	return nil
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

func opEd25519Verify(cx *EvalContext) error {
	last := len(cx.stack) - 1 // index of PK
	prev := last - 1          // index of signature
	pprev := prev - 1         // index of data

	var sv crypto.SignatureVerifier
	if len(cx.stack[last].Bytes) != len(sv) {
		return errors.New("invalid public key")
	}
	copy(sv[:], cx.stack[last].Bytes)

	var sig crypto.Signature
	if len(cx.stack[prev].Bytes) != len(sig) {
		return errors.New("invalid signature")
	}
	copy(sig[:], cx.stack[prev].Bytes)

	msg := Msg{ProgramHash: cx.programHash(), Data: cx.stack[pprev].Bytes}
	cx.stack[pprev].Uint = boolToUint(sv.Verify(msg, sig, cx.Proto.EnableBatchVerification))
	cx.stack[pprev].Bytes = nil
	cx.stack = cx.stack[:prev]
	return nil
}

func opEd25519VerifyBare(cx *EvalContext) error {
	last := len(cx.stack) - 1 // index of PK
	prev := last - 1          // index of signature
	pprev := prev - 1         // index of data

	var sv crypto.SignatureVerifier
	if len(cx.stack[last].Bytes) != len(sv) {
		return errors.New("invalid public key")
	}
	copy(sv[:], cx.stack[last].Bytes)

	var sig crypto.Signature
	if len(cx.stack[prev].Bytes) != len(sig) {
		return errors.New("invalid signature")
	}
	copy(sig[:], cx.stack[prev].Bytes)

	cx.stack[pprev].Uint = boolToUint(sv.VerifyBytes(cx.stack[pprev].Bytes, sig, cx.Proto.EnableBatchVerification))
	cx.stack[pprev].Bytes = nil
	cx.stack = cx.stack[:prev]
	return nil
}

func leadingZeros(size int, b *big.Int) ([]byte, error) {
	byteLength := (b.BitLen() + 7) / 8
	if size < byteLength {
		return nil, fmt.Errorf("insufficient buffer size: %d < %d", size, byteLength)
	}
	buf := make([]byte, size)
	b.FillBytes(buf)
	return buf, nil
}

var ecdsaVerifyCosts = []int{
	Secp256k1: 1700,
	Secp256r1: 2500,
}

func opEcdsaVerify(cx *EvalContext) error {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField(ecdsaCurve)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid curve %d", ecdsaCurve)
	}

	if fs.field != Secp256k1 && fs.field != Secp256r1 {
		return fmt.Errorf("unsupported curve %d", fs.field)
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

	if len(msg) != 32 {
		return fmt.Errorf("the signed data must be 32 bytes long, not %d", len(msg))
	}

	x := new(big.Int).SetBytes(pkX)
	y := new(big.Int).SetBytes(pkY)

	var result bool
	if fs.field == Secp256k1 {
		signature := make([]byte, 0, len(sigR)+len(sigS))
		signature = append(signature, sigR...)
		signature = append(signature, sigS...)

		pubkey := secp256k1.S256().Marshal(x, y)
		result = secp256k1.VerifySignature(pubkey, msg, signature)
	} else if fs.field == Secp256r1 {
		r := new(big.Int).SetBytes(sigR)
		s := new(big.Int).SetBytes(sigS)

		pubkey := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		result = ecdsa.Verify(&pubkey, msg, r, s)
	}

	cx.stack[fifth].Uint = boolToUint(result)
	cx.stack[fifth].Bytes = nil
	cx.stack = cx.stack[:fourth]
	return nil
}

var ecdsaDecompressCosts = []int{
	Secp256k1: 650,
	Secp256r1: 2400,
}

func opEcdsaPkDecompress(cx *EvalContext) error {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField(ecdsaCurve)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid curve %d", ecdsaCurve)
	}

	if fs.field != Secp256k1 && fs.field != Secp256r1 {
		return fmt.Errorf("unsupported curve %d", fs.field)
	}

	last := len(cx.stack) - 1 // compressed PK

	pubkey := cx.stack[last].Bytes
	var x, y *big.Int
	if fs.field == Secp256k1 {
		x, y = secp256k1.DecompressPubkey(pubkey)
		if x == nil {
			return fmt.Errorf("invalid pubkey")
		}
	} else if fs.field == Secp256r1 {
		x, y = elliptic.UnmarshalCompressed(elliptic.P256(), pubkey)
		if x == nil {
			return fmt.Errorf("invalid compressed pubkey")
		}
	}

	var err error
	cx.stack[last].Uint = 0
	cx.stack[last].Bytes, err = leadingZeros(32, x)
	if err != nil {
		return fmt.Errorf("x component zeroing failed: %s", err.Error())
	}

	var sv stackValue
	sv.Bytes, err = leadingZeros(32, y)
	if err != nil {
		return fmt.Errorf("y component zeroing failed: %s", err.Error())
	}

	cx.stack = append(cx.stack, sv)
	return nil
}

func opEcdsaPkRecover(cx *EvalContext) error {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField(ecdsaCurve)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid curve %d", ecdsaCurve)
	}

	if fs.field != Secp256k1 {
		return fmt.Errorf("unsupported curve %d", fs.field)
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
		return fmt.Errorf("invalid recovery id: %d", recid)
	}

	signature := make([]byte, 0, len(sigR)+len(sigS)+1)
	signature = append(signature, sigR...)
	signature = append(signature, sigS...)
	signature = append(signature, uint8(recid))

	pk, err := secp256k1.RecoverPubkey(msg, signature)
	if err != nil {
		return fmt.Errorf("pubkey recover failed: %s", err.Error())
	}
	x, y := secp256k1.S256().Unmarshal(pk)
	if x == nil {
		return fmt.Errorf("pubkey unmarshal failed")
	}

	cx.stack[fourth].Uint = 0
	cx.stack[fourth].Bytes, err = leadingZeros(32, x)
	if err != nil {
		return fmt.Errorf("x component zeroing failed: %s", err.Error())
	}
	cx.stack[pprev].Uint = 0
	cx.stack[pprev].Bytes, err = leadingZeros(32, y)
	if err != nil {
		return fmt.Errorf("y component zeroing failed: %s", err.Error())
	}
	cx.stack = cx.stack[:prev]
	return nil
}

func opLoad(cx *EvalContext) error {
	n := cx.program[cx.pc+1]
	cx.stack = append(cx.stack, cx.scratch[n])
	return nil
}

func opLoads(cx *EvalContext) error {
	last := len(cx.stack) - 1
	n := cx.stack[last].Uint
	if n >= uint64(len(cx.scratch)) {
		return fmt.Errorf("invalid Scratch index %d", n)
	}
	cx.stack[last] = cx.scratch[n]
	return nil
}

func opStore(cx *EvalContext) error {
	n := cx.program[cx.pc+1]
	last := len(cx.stack) - 1
	cx.scratch[n] = cx.stack[last]
	cx.stack = cx.stack[:last]
	return nil
}

func opStores(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	n := cx.stack[prev].Uint
	if n >= uint64(len(cx.scratch)) {
		return fmt.Errorf("invalid Scratch index %d", n)
	}
	cx.scratch[n] = cx.stack[last]
	cx.stack = cx.stack[:prev]
	return nil
}

func opGloadImpl(cx *EvalContext, gi int, scratchIdx byte, opName string) (stackValue, error) {
	var none stackValue
	if gi >= len(cx.TxnGroup) {
		return none, fmt.Errorf("%s lookup TxnGroup[%d] but it only has %d", opName, gi, len(cx.TxnGroup))
	}
	if int(scratchIdx) >= len(cx.scratch) {
		return none, fmt.Errorf("invalid Scratch index %d", scratchIdx)
	}
	if cx.TxnGroup[gi].Txn.Type != protocol.ApplicationCallTx {
		return none, fmt.Errorf("can't use %s on non-app call txn with index %d", opName, gi)
	}
	if gi == cx.groupIndex {
		return none, fmt.Errorf("can't use %s on self, use load instead", opName)
	}
	if gi > cx.groupIndex {
		return none, fmt.Errorf("%s can't get future scratch space from txn with index %d", opName, gi)
	}

	return cx.pastScratch[gi][scratchIdx], nil
}

func opGload(cx *EvalContext) error {
	gi := int(cx.program[cx.pc+1])
	scratchIdx := cx.program[cx.pc+2]
	scratchValue, err := opGloadImpl(cx, gi, scratchIdx, "gload")
	if err != nil {
		return err
	}

	cx.stack = append(cx.stack, scratchValue)
	return nil
}

func opGloads(cx *EvalContext) error {
	last := len(cx.stack) - 1
	gi := cx.stack[last].Uint
	if gi >= uint64(len(cx.TxnGroup)) {
		return fmt.Errorf("gloads lookup TxnGroup[%d] but it only has %d", gi, len(cx.TxnGroup))
	}
	scratchIdx := cx.program[cx.pc+1]
	scratchValue, err := opGloadImpl(cx, int(gi), scratchIdx, "gloads")
	if err != nil {
		return err
	}

	cx.stack[last] = scratchValue
	return nil
}

func opGloadss(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1

	gi := cx.stack[prev].Uint
	if gi >= uint64(len(cx.TxnGroup)) {
		return fmt.Errorf("gloadss lookup TxnGroup[%d] but it only has %d", gi, len(cx.TxnGroup))
	}
	scratchIdx := cx.stack[last].Uint
	if scratchIdx >= 256 {
		return fmt.Errorf("gloadss scratch index >= 256 (%d)", scratchIdx)
	}
	scratchValue, err := opGloadImpl(cx, int(gi), byte(scratchIdx), "gloadss")
	if err != nil {
		return err
	}

	cx.stack[prev] = scratchValue
	cx.stack = cx.stack[:last]
	return nil
}

func opConcat(cx *EvalContext) error {
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
	return nil
}

func substring(x []byte, start, end int) ([]byte, error) {
	if end < start {
		return nil, errors.New("substring end before start")
	}
	if start > len(x) || end > len(x) {
		return nil, errors.New("substring range beyond length of string")
	}
	return x[start:end], nil
}

func opSubstring(cx *EvalContext) error {
	last := len(cx.stack) - 1
	start := cx.program[cx.pc+1]
	end := cx.program[cx.pc+2]
	bytes, err := substring(cx.stack[last].Bytes, int(start), int(end))
	cx.stack[last].Bytes = bytes
	return err
}

func opSubstring3(cx *EvalContext) error {
	last := len(cx.stack) - 1 // end
	prev := last - 1          // start
	pprev := prev - 1         // bytes
	start := cx.stack[prev].Uint
	end := cx.stack[last].Uint
	if start > math.MaxInt32 || end > math.MaxInt32 {
		return errors.New("substring range beyond length of string")
	}
	bytes, err := substring(cx.stack[pprev].Bytes, int(start), int(end))
	cx.stack[pprev].Bytes = bytes
	cx.stack = cx.stack[:prev]
	return err
}

func opGetBit(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	idx := cx.stack[last].Uint
	target := cx.stack[prev]

	var bit uint64
	if target.argType() == StackUint64 {
		if idx > 63 {
			return errors.New("getbit index > 63 with with Uint")
		}
		mask := uint64(1) << idx
		bit = (target.Uint & mask) >> idx
	} else {
		// indexing into a byteslice
		byteIdx := idx / 8
		if byteIdx >= uint64(len(target.Bytes)) {
			return errors.New("getbit index beyond byteslice")
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
	return nil
}

func opSetBit(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	pprev := prev - 1

	bit := cx.stack[last].Uint
	idx := cx.stack[prev].Uint
	target := cx.stack[pprev]

	if bit > 1 {
		return errors.New("setbit value > 1")
	}

	if target.argType() == StackUint64 {
		if idx > 63 {
			return errors.New("setbit index > 63 with Uint")
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
			return errors.New("setbit index beyond byteslice")
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
	return nil
}

func opGetByte(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1

	idx := cx.stack[last].Uint
	target := cx.stack[prev]

	if idx >= uint64(len(target.Bytes)) {
		return errors.New("getbyte index beyond array length")
	}
	cx.stack[prev].Uint = uint64(target.Bytes[idx])
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
	return nil
}

func opSetByte(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	pprev := prev - 1
	if cx.stack[last].Uint > 255 {
		return errors.New("setbyte value > 255")
	}
	if cx.stack[prev].Uint >= uint64(len(cx.stack[pprev].Bytes)) {
		return errors.New("setbyte index beyond array length")
	}
	// Copy to avoid modifying shared slice
	cx.stack[pprev].Bytes = append([]byte(nil), cx.stack[pprev].Bytes...)
	cx.stack[pprev].Bytes[cx.stack[prev].Uint] = byte(cx.stack[last].Uint)
	cx.stack = cx.stack[:prev]
	return nil
}

func opExtractImpl(x []byte, start, length int) ([]byte, error) {
	end := start + length
	if start > len(x) || end > len(x) {
		return nil, errors.New("extract range beyond length of string")
	}
	return x[start:end], nil
}

func opExtract(cx *EvalContext) error {
	last := len(cx.stack) - 1
	startIdx := cx.program[cx.pc+1]
	lengthIdx := cx.program[cx.pc+2]
	// Shortcut: if length is 0, take bytes from start index to the end
	length := int(lengthIdx)
	if length == 0 {
		length = len(cx.stack[last].Bytes) - int(startIdx)
	}
	bytes, err := opExtractImpl(cx.stack[last].Bytes, int(startIdx), length)
	cx.stack[last].Bytes = bytes
	return err
}

func opExtract3(cx *EvalContext) error {
	last := len(cx.stack) - 1 // length
	prev := last - 1          // start
	byteArrayIdx := prev - 1  // bytes
	startIdx := cx.stack[prev].Uint
	lengthIdx := cx.stack[last].Uint
	if startIdx > math.MaxInt32 || lengthIdx > math.MaxInt32 {
		return errors.New("extract range beyond length of string")
	}
	bytes, err := opExtractImpl(cx.stack[byteArrayIdx].Bytes, int(startIdx), int(lengthIdx))
	cx.stack[byteArrayIdx].Bytes = bytes
	cx.stack = cx.stack[:prev]
	return err
}

// We convert the bytes manually here because we need to accept "short" byte arrays.
// A single byte is a legal uint64 decoded this way.
func convertBytesToInt(x []byte) uint64 {
	out := uint64(0)
	for _, b := range x {
		out = out << 8
		out = out | (uint64(b) & 0x0ff)
	}
	return out
}

func opExtractNBytes(cx *EvalContext, n int) error {
	last := len(cx.stack) - 1 // start
	prev := last - 1          // bytes
	startIdx := cx.stack[last].Uint
	bytes, err := opExtractImpl(cx.stack[prev].Bytes, int(startIdx), n) // extract n bytes
	if err != nil {
		return err
	}
	cx.stack[prev].Uint = convertBytesToInt(bytes)
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
	return nil
}

func opExtract16Bits(cx *EvalContext) error {
	return opExtractNBytes(cx, 2) // extract 2 bytes
}

func opExtract32Bits(cx *EvalContext) error {
	return opExtractNBytes(cx, 4) // extract 4 bytes
}

func opExtract64Bits(cx *EvalContext) error {
	return opExtractNBytes(cx, 8) // extract 8 bytes
}

// accountReference yields the address and Accounts offset designated by a
// stackValue. If the stackValue is the app account or an account of an app in
// created.apps, and it is not be in the Accounts array, then len(Accounts) + 1
// is returned as the index. This would let us catch the mistake if the index is
// used for set/del. If the txn somehow "psychically" predicted the address, and
// therefore it IS in txn.Accounts, then happy day, we can set/del it.  Return
// the proper index.

// If we ever want apps to be able to change local state on these accounts
// (which includes this app's own account!), we will need a change to
// EvalDelta's on disk format, so that the addr can be encoded explicitly rather
// than by index into txn.Accounts.

func (cx *EvalContext) accountReference(account stackValue) (basics.Address, uint64, error) {
	if account.argType() == StackUint64 {
		addr, err := cx.txn.Txn.AddressByIndex(account.Uint, cx.txn.Txn.Sender)
		return addr, account.Uint, err
	}
	addr, err := account.address()
	if err != nil {
		return addr, 0, err
	}
	idx, err := cx.txn.Txn.IndexByAddress(addr, cx.txn.Txn.Sender)

	invalidIndex := uint64(len(cx.txn.Txn.Accounts) + 1)
	// Allow an address for an app that was created in group
	if err != nil && cx.version >= createdResourcesVersion {
		for _, appID := range cx.created.apps {
			createdAddress := cx.getApplicationAddress(appID)
			if addr == createdAddress {
				return addr, invalidIndex, nil
			}
		}
	}

	// this app's address is also allowed
	if err != nil {
		appAddr := cx.getApplicationAddress(cx.appID)
		if appAddr == addr {
			return addr, invalidIndex, nil
		}
	}

	return addr, idx, err
}

func (cx *EvalContext) mutableAccountReference(account stackValue) (basics.Address, uint64, error) {
	addr, accountIdx, err := cx.accountReference(account)
	if err == nil && accountIdx > uint64(len(cx.txn.Txn.Accounts)) {
		// There was no error, but accountReference has signaled that accountIdx
		// is not for mutable ops (because it can't encode it in EvalDelta)
		// This also tells us that account.address() will work.
		addr, _ := account.address()
		err = fmt.Errorf("invalid Account reference for mutation %s", addr)
	}
	return addr, accountIdx, err
}

func opBalance(cx *EvalContext) error {
	last := len(cx.stack) - 1 // account (index or actual address)

	addr, _, err := cx.accountReference(cx.stack[last])
	if err != nil {
		return err
	}

	account, err := cx.Ledger.AccountData(addr)
	if err != nil {
		return err
	}

	cx.stack[last].Bytes = nil
	cx.stack[last].Uint = account.MicroAlgos.Raw
	return nil
}

func opMinBalance(cx *EvalContext) error {
	last := len(cx.stack) - 1 // account (index or actual address)

	addr, _, err := cx.accountReference(cx.stack[last])
	if err != nil {
		return err
	}

	account, err := cx.Ledger.AccountData(addr)
	if err != nil {
		return err
	}

	cx.stack[last].Bytes = nil
	cx.stack[last].Uint = account.MinBalance(cx.Proto).Raw
	return nil
}

func opAppOptedIn(cx *EvalContext) error {
	last := len(cx.stack) - 1 // app
	prev := last - 1          // account

	addr, _, err := cx.accountReference(cx.stack[prev])
	if err != nil {
		return err
	}

	app, err := appReference(cx, cx.stack[last].Uint, false)
	if err != nil {
		return err
	}

	optedIn, err := cx.Ledger.OptedIn(addr, app)
	if err != nil {
		return err
	}

	cx.stack[prev].Uint = boolToUint(optedIn)
	cx.stack[prev].Bytes = nil

	cx.stack = cx.stack[:last]
	return nil
}

func opAppLocalGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // account

	key := cx.stack[last].Bytes

	result, _, err := opAppLocalGetImpl(cx, 0, key, cx.stack[prev])
	if err != nil {
		return err
	}

	cx.stack[prev] = result
	cx.stack = cx.stack[:last]
	return nil
}

func opAppLocalGetEx(cx *EvalContext) error {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // app id
	pprev := prev - 1         // account

	key := cx.stack[last].Bytes
	appID := cx.stack[prev].Uint

	result, ok, err := opAppLocalGetImpl(cx, appID, key, cx.stack[pprev])
	if err != nil {
		return err
	}

	var isOk stackValue
	if ok {
		isOk.Uint = 1
	}

	cx.stack[pprev] = result
	cx.stack[prev] = isOk
	cx.stack = cx.stack[:last]
	return nil
}

func opAppLocalGetImpl(cx *EvalContext, appID uint64, key []byte, acct stackValue) (result stackValue, ok bool, err error) {
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
		return
	}

	if ok {
		result, err = stackValueFromTealValue(tv)
	}
	return
}

func opAppGetGlobalStateImpl(cx *EvalContext, appIndex uint64, key []byte) (result stackValue, ok bool, err error) {
	app, err := appReference(cx, appIndex, true)
	if err != nil {
		return
	}

	tv, ok, err := cx.Ledger.GetGlobal(app, string(key))
	if err != nil {
		return
	}

	if ok {
		result, err = stackValueFromTealValue(tv)
	}
	return
}

func opAppGlobalGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // state key

	key := cx.stack[last].Bytes

	result, _, err := opAppGetGlobalStateImpl(cx, 0, key)
	if err != nil {
		return err
	}

	cx.stack[last] = result
	return nil
}

func opAppGlobalGetEx(cx *EvalContext) error {
	last := len(cx.stack) - 1 // state key
	prev := last - 1          // app

	key := cx.stack[last].Bytes

	result, ok, err := opAppGetGlobalStateImpl(cx, cx.stack[prev].Uint, key)
	if err != nil {
		return err
	}

	var isOk stackValue
	if ok {
		isOk.Uint = 1
	}

	cx.stack[prev] = result
	cx.stack[last] = isOk
	return nil
}

func opAppLocalPut(cx *EvalContext) error {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // state key
	pprev := prev - 1         // account

	sv := cx.stack[last]
	key := string(cx.stack[prev].Bytes)

	addr, accountIdx, err := cx.mutableAccountReference(cx.stack[pprev])
	if err != nil {
		return err
	}

	// if writing the same value, don't record in EvalDelta, matching ledger
	// behavior with previous BuildEvalDelta mechanism
	etv, ok, err := cx.Ledger.GetLocal(addr, cx.appID, key, accountIdx)
	if err != nil {
		return err
	}

	tv := sv.toTealValue()
	if !ok || tv != etv {
		if _, ok := cx.txn.EvalDelta.LocalDeltas[accountIdx]; !ok {
			cx.txn.EvalDelta.LocalDeltas[accountIdx] = basics.StateDelta{}
		}
		cx.txn.EvalDelta.LocalDeltas[accountIdx][key] = tv.ToValueDelta()
	}
	err = cx.Ledger.SetLocal(addr, cx.appID, key, tv, accountIdx)
	if err != nil {
		return err
	}

	cx.stack = cx.stack[:pprev]
	return nil
}

func opAppGlobalPut(cx *EvalContext) error {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // state key

	sv := cx.stack[last]
	key := string(cx.stack[prev].Bytes)

	// if writing the same value, don't record in EvalDelta, matching ledger
	// behavior with previous BuildEvalDelta mechanism
	etv, ok, err := cx.Ledger.GetGlobal(cx.appID, key)
	if err != nil {
		return err
	}
	tv := sv.toTealValue()
	if !ok || tv != etv {
		cx.txn.EvalDelta.GlobalDelta[key] = tv.ToValueDelta()
	}

	err = cx.Ledger.SetGlobal(cx.appID, key, tv)
	if err != nil {
		return err
	}

	cx.stack = cx.stack[:prev]
	return nil
}

func opAppLocalDel(cx *EvalContext) error {
	last := len(cx.stack) - 1 // key
	prev := last - 1          // account

	key := string(cx.stack[last].Bytes)

	addr, accountIdx, err := cx.mutableAccountReference(cx.stack[prev])
	if err != nil {
		return err
	}

	// if deleting a non-existent value, don't record in EvalDelta, matching
	// ledger behavior with previous BuildEvalDelta mechanism
	if _, ok, err := cx.Ledger.GetLocal(addr, cx.appID, key, accountIdx); ok {
		if err != nil {
			return err
		}
		if _, ok := cx.txn.EvalDelta.LocalDeltas[accountIdx]; !ok {
			cx.txn.EvalDelta.LocalDeltas[accountIdx] = basics.StateDelta{}
		}
		cx.txn.EvalDelta.LocalDeltas[accountIdx][key] = basics.ValueDelta{
			Action: basics.DeleteAction,
		}
	}

	err = cx.Ledger.DelLocal(addr, cx.appID, key, accountIdx)
	if err != nil {
		return err
	}

	cx.stack = cx.stack[:prev]
	return nil
}

func opAppGlobalDel(cx *EvalContext) error {
	last := len(cx.stack) - 1 // key

	key := string(cx.stack[last].Bytes)

	// if deleting a non-existent value, don't record in EvalDelta, matching
	// ledger behavior with previous BuildEvalDelta mechanism
	if _, ok, err := cx.Ledger.GetGlobal(cx.appID, key); ok {
		if err != nil {
			return err
		}
		cx.txn.EvalDelta.GlobalDelta[key] = basics.ValueDelta{
			Action: basics.DeleteAction,
		}
	}

	err := cx.Ledger.DelGlobal(cx.appID, key)
	if err != nil {
		return err
	}
	cx.stack = cx.stack[:last]
	return nil
}

// We have a difficult naming problem here. Some opcodes allow (and used to
// require) ASAs and Apps to to be referenced by their "index" in an app call
// txn's foreign-apps or foreign-assets arrays.  That was a small integer, no
// more than 2 or so, and was often called an "index".  But it was not a
// basics.AssetIndex or basics.ApplicationIndex.

func appReference(cx *EvalContext, ref uint64, foreign bool) (basics.AppIndex, error) {
	if cx.version >= directRefEnabledVersion {
		if ref == 0 || ref == uint64(cx.appID) {
			return cx.appID, nil
		}
		for _, appID := range cx.txn.Txn.ForeignApps {
			if appID == basics.AppIndex(ref) {
				return appID, nil
			}
		}
		// or was created in group
		if cx.version >= createdResourcesVersion {
			for _, appID := range cx.created.apps {
				if appID == basics.AppIndex(ref) {
					return appID, nil
				}
			}
		}
		// Allow use of indexes, but this comes last so that clear advice can be
		// given to anyone who cares about semantics in the first few rounds of
		// a new network - don't use indexes for references, use the App ID
		if ref <= uint64(len(cx.txn.Txn.ForeignApps)) {
			return basics.AppIndex(cx.txn.Txn.ForeignApps[ref-1]), nil
		}
	} else {
		// Old rules
		if ref == 0 { // Even back when expected to be a real ID, ref = 0 was current app
			return cx.appID, nil
		}
		if foreign {
			// In old versions, a foreign reference must be an index in ForeignAssets or 0
			if ref <= uint64(len(cx.txn.Txn.ForeignApps)) {
				return basics.AppIndex(cx.txn.Txn.ForeignApps[ref-1]), nil
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
		for _, assetID := range cx.txn.Txn.ForeignAssets {
			if assetID == basics.AssetIndex(ref) {
				return assetID, nil
			}
		}
		// or was created in group
		if cx.version >= createdResourcesVersion {
			for _, assetID := range cx.created.asas {
				if assetID == basics.AssetIndex(ref) {
					return assetID, nil
				}
			}
		}
		// Allow use of indexes, but this comes last so that clear advice can be
		// given to anyone who cares about semantics in the first few rounds of
		// a new network - don't use indexes for references, use the asa ID.
		if ref < uint64(len(cx.txn.Txn.ForeignAssets)) {
			return basics.AssetIndex(cx.txn.Txn.ForeignAssets[ref]), nil
		}
	} else {
		// Old rules
		if foreign {
			// In old versions, a foreign reference must be an index in ForeignAssets
			if ref < uint64(len(cx.txn.Txn.ForeignAssets)) {
				return basics.AssetIndex(cx.txn.Txn.ForeignAssets[ref]), nil
			}
		} else {
			// Otherwise it's direct
			return basics.AssetIndex(ref), nil
		}
	}
	return basics.AssetIndex(0), fmt.Errorf("invalid Asset reference %d", ref)

}

func opAssetHoldingGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // asset
	prev := last - 1          // account

	holdingField := AssetHoldingField(cx.program[cx.pc+1])
	fs, ok := assetHoldingFieldSpecByField(holdingField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid asset_holding_get field %d", holdingField)
	}

	addr, _, err := cx.accountReference(cx.stack[prev])
	if err != nil {
		return err
	}

	asset, err := asaReference(cx, cx.stack[last].Uint, false)
	if err != nil {
		return err
	}

	var exist uint64 = 0
	var value stackValue
	if holding, err := cx.Ledger.AssetHolding(addr, asset); err == nil {
		// the holding exist, read the value
		exist = 1
		value, err = cx.assetHoldingToValue(&holding, fs)
		if err != nil {
			return err
		}
	}

	cx.stack[prev] = value
	cx.stack[last].Uint = exist
	return nil
}

func opAssetParamsGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // asset

	paramField := AssetParamsField(cx.program[cx.pc+1])
	fs, ok := assetParamsFieldSpecByField(paramField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid asset_params_get field %d", paramField)
	}

	asset, err := asaReference(cx, cx.stack[last].Uint, true)
	if err != nil {
		return err
	}

	var exist uint64 = 0
	var value stackValue
	if params, creator, err := cx.Ledger.AssetParams(asset); err == nil {
		// params exist, read the value
		exist = 1
		value, err = cx.assetParamsToValue(&params, creator, fs)
		if err != nil {
			return err
		}
	}

	cx.stack[last] = value
	cx.stack = append(cx.stack, stackValue{Uint: exist})
	return nil
}

func opAppParamsGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // app

	paramField := AppParamsField(cx.program[cx.pc+1])
	fs, ok := appParamsFieldSpecByField(paramField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid app_params_get field %d", paramField)
	}

	app, err := appReference(cx, cx.stack[last].Uint, true)
	if err != nil {
		return err
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
			return err
		}
	}

	cx.stack[last] = value
	cx.stack = append(cx.stack, stackValue{Uint: exist})
	return nil
}

func opAcctParamsGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // acct

	addr, _, err := cx.accountReference(cx.stack[last])
	if err != nil {
		return err
	}

	paramField := AcctParamsField(cx.program[cx.pc+1])
	fs, ok := acctParamsFieldSpecByField(paramField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid acct_params_get field %d", paramField)
	}

	account, err := cx.Ledger.AccountData(addr)
	if err != nil {
		return err
	}

	exist := boolToUint(account.MicroAlgos.Raw > 0)

	var value stackValue

	switch fs.field {
	case AcctBalance:
		value.Uint = account.MicroAlgos.Raw
	case AcctMinBalance:
		value.Uint = account.MinBalance(cx.Proto).Raw
	case AcctAuthAddr:
		value.Bytes = account.AuthAddr[:]
	}
	cx.stack[last] = value
	cx.stack = append(cx.stack, stackValue{Uint: exist})
	return nil
}

func opLog(cx *EvalContext) error {
	last := len(cx.stack) - 1

	if len(cx.txn.EvalDelta.Logs) >= maxLogCalls {
		return fmt.Errorf("too many log calls in program. up to %d is allowed", maxLogCalls)
	}
	log := cx.stack[last]
	cx.logSize += len(log.Bytes)
	if cx.logSize > maxLogSize {
		return fmt.Errorf("program logs too large. %d bytes >  %d bytes limit", cx.logSize, maxLogSize)
	}
	cx.txn.EvalDelta.Logs = append(cx.txn.EvalDelta.Logs, string(log.Bytes))
	cx.stack = cx.stack[:last]
	return nil
}

func authorizedSender(cx *EvalContext, addr basics.Address) error {
	authorizer, err := cx.Ledger.Authorizer(addr)
	if err != nil {
		return err
	}
	if cx.getApplicationAddress(cx.appID) != authorizer {
		return fmt.Errorf("app %d (addr %s) unauthorized %s", cx.appID, cx.getApplicationAddress(cx.appID), authorizer)
	}
	return nil
}

// addInnerTxn appends a fresh SignedTxn to subtxns, populated with reasonable
// defaults.
func addInnerTxn(cx *EvalContext) error {
	addr := cx.getApplicationAddress(cx.appID)

	// For compatibility with v5, in which failures only occurred in the submit,
	// we only fail here if we are already over the max inner limit.  Thus this
	// allows construction of one more Inner than is actually allowed, and will
	// fail in submit. (But we do want the check here, so this can't become
	// unbounded.)  The MaxTxGroupSize check can be, and is, precise. (That is,
	// if we are at max group size, we can panic now, since we are trying to add
	// too many)
	if len(cx.subtxns) > cx.remainingInners() || len(cx.subtxns) >= cx.Proto.MaxTxGroupSize {
		return fmt.Errorf("too many inner transactions %d with %d left", len(cx.subtxns), cx.remainingInners())
	}

	stxn := transactions.SignedTxnWithAD{}

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
		FirstValid: cx.txn.Txn.FirstValid,
		LastValid:  cx.txn.Txn.LastValid,
	}
	cx.subtxns = append(cx.subtxns, stxn)
	return nil
}

func opTxBegin(cx *EvalContext) error {
	if len(cx.subtxns) > 0 {
		return errors.New("itxn_begin without itxn_submit")
	}
	if cx.Proto.IsolateClearState && cx.txn.Txn.OnCompletion == transactions.ClearStateOC {
		return errors.New("clear state programs can not issue inner transactions")
	}
	return addInnerTxn(cx)
}

func opItxnNext(cx *EvalContext) error {
	if len(cx.subtxns) == 0 {
		return errors.New("itxn_next without itxn_begin")
	}
	return addInnerTxn(cx)
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
	uint, err := sv.uint()
	if err != nil {
		return basics.AssetIndex(0), err
	}
	aid := basics.AssetIndex(uint)

	// Ensure that aid is in Foreign Assets
	for _, assetID := range cx.txn.Txn.ForeignAssets {
		if assetID == aid {
			return aid, nil
		}
	}
	// or was created in group
	if cx.version >= createdResourcesVersion {
		for _, assetID := range cx.created.asas {
			if assetID == aid {
				return aid, nil
			}
		}
	}

	return basics.AssetIndex(0), fmt.Errorf("invalid Asset reference %d", aid)
}

// availableApp is used instead of appReference for more recent (stateful)
// opcodes that don't need (or want!) to allow low numbers to represent the app
// at that index in ForeignApps array.
func (cx *EvalContext) availableApp(sv stackValue) (basics.AppIndex, error) {
	uint, err := sv.uint()
	if err != nil {
		return basics.AppIndex(0), err
	}
	aid := basics.AppIndex(uint)

	// Ensure that aid is in Foreign Apps
	for _, appID := range cx.txn.Txn.ForeignApps {
		if appID == aid {
			return aid, nil
		}
	}
	// or was created in group
	if cx.version >= createdResourcesVersion {
		for _, appID := range cx.created.apps {
			if appID == aid {
				return aid, nil
			}
		}
	}
	// Or, it can be the current app
	if cx.appID == aid {
		return aid, nil
	}

	return 0, fmt.Errorf("invalid App reference %d", aid)
}

func (cx *EvalContext) stackIntoTxnField(sv stackValue, fs *txnFieldSpec, txn *transactions.Transaction) (err error) {
	switch fs.field {
	case Type:
		if sv.Bytes == nil {
			return fmt.Errorf("Type arg not a byte array")
		}
		txType := string(sv.Bytes)
		ver, ok := innerTxnTypes[txType]
		if ok && ver <= cx.version {
			txn.Type = protocol.TxType(txType)
		} else {
			return fmt.Errorf("%s is not a valid Type for itxn_field", txType)
		}
	case TypeEnum:
		var i uint64
		i, err = sv.uint()
		if err != nil {
			return err
		}
		// i != 0 is so that the error reports 0 instead of Unknown
		if i != 0 && i < uint64(len(TxnTypeNames)) {
			ver, ok := innerTxnTypes[TxnTypeNames[i]]
			if ok && ver <= cx.version {
				txn.Type = protocol.TxType(TxnTypeNames[i])
			} else {
				return fmt.Errorf("%s is not a valid Type for itxn_field", TxnTypeNames[i])
			}
		} else {
			return fmt.Errorf("%d is not a valid TypeEnum", i)
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
			return fmt.Errorf("%s may not exceed %d bytes", fs.field, cx.Proto.MaxTxnNoteBytes)
		}
		txn.Note = make([]byte, len(sv.Bytes))
		copy(txn.Note, sv.Bytes)
	// GenesisID, GenesisHash unsettable: surely makes no sense
	// Group unsettable: Can't make groups from AVM (yet?)
	// Lease unsettable: This seems potentially useful.

	case RekeyTo:
		txn.RekeyTo, err = sv.address()

	// KeyReg
	case VotePK:
		if len(sv.Bytes) != 32 {
			return fmt.Errorf("%s must be 32 bytes", fs.field)
		}
		copy(txn.VotePK[:], sv.Bytes)
	case SelectionPK:
		if len(sv.Bytes) != 32 {
			return fmt.Errorf("%s must be 32 bytes", fs.field)
		}
		copy(txn.SelectionPK[:], sv.Bytes)
	case StateProofPK:
		if len(sv.Bytes) != 64 {
			return fmt.Errorf("%s must be 64 bytes", fs.field)
		}
		copy(txn.StateProofPK[:], sv.Bytes)
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
			return fmt.Errorf("%s must be 32 bytes", fs.field)
		}
		copy(txn.AssetParams.MetadataHash[:], sv.Bytes)
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

	// ApplicationCall
	case ApplicationID:
		txn.ApplicationID, err = cx.availableApp(sv)
	case OnCompletion:
		var onc uint64
		onc, err = sv.uintMaxed(uint64(transactions.DeleteApplicationOC))
		txn.OnCompletion = transactions.OnCompletion(onc)
	case ApplicationArgs:
		if sv.Bytes == nil {
			return fmt.Errorf("ApplicationArg is not a byte array")
		}
		total := len(sv.Bytes)
		for _, arg := range txn.ApplicationArgs {
			total += len(arg)
		}
		if total > cx.Proto.MaxAppTotalArgLen {
			return errors.New("total application args length too long")
		}
		if len(txn.ApplicationArgs) >= cx.Proto.MaxAppArgs {
			return errors.New("too many application args")
		}
		new := make([]byte, len(sv.Bytes))
		copy(new, sv.Bytes)
		txn.ApplicationArgs = append(txn.ApplicationArgs, new)
	case Accounts:
		var new basics.Address
		new, err = cx.availableAccount(sv)
		if err != nil {
			return err
		}
		if len(txn.Accounts) >= cx.Proto.MaxAppTxnAccounts {
			return errors.New("too many foreign accounts")
		}
		txn.Accounts = append(txn.Accounts, new)
	case ApprovalProgram:
		maxPossible := cx.Proto.MaxAppProgramLen * (1 + cx.Proto.MaxExtraAppProgramPages)
		if len(sv.Bytes) > maxPossible {
			return fmt.Errorf("%s may not exceed %d bytes", fs.field, maxPossible)
		}
		txn.ApprovalProgram = make([]byte, len(sv.Bytes))
		copy(txn.ApprovalProgram, sv.Bytes)
	case ClearStateProgram:
		maxPossible := cx.Proto.MaxAppProgramLen * (1 + cx.Proto.MaxExtraAppProgramPages)
		if len(sv.Bytes) > maxPossible {
			return fmt.Errorf("%s may not exceed %d bytes", fs.field, maxPossible)
		}
		txn.ClearStateProgram = make([]byte, len(sv.Bytes))
		copy(txn.ClearStateProgram, sv.Bytes)
	case Assets:
		var new basics.AssetIndex
		new, err = cx.availableAsset(sv)
		if err != nil {
			return err
		}
		if len(txn.ForeignAssets) >= cx.Proto.MaxAppTxnForeignAssets {
			return errors.New("too many foreign assets")
		}
		txn.ForeignAssets = append(txn.ForeignAssets, new)
	case Applications:
		var new basics.AppIndex
		new, err = cx.availableApp(sv)
		if err != nil {
			return err
		}
		if len(txn.ForeignApps) >= cx.Proto.MaxAppTxnForeignApps {
			return errors.New("too many foreign apps")
		}
		txn.ForeignApps = append(txn.ForeignApps, new)
	case GlobalNumUint:
		txn.GlobalStateSchema.NumUint, err =
			sv.uintMaxed(cx.Proto.MaxGlobalSchemaEntries)
	case GlobalNumByteSlice:
		txn.GlobalStateSchema.NumByteSlice, err =
			sv.uintMaxed(cx.Proto.MaxGlobalSchemaEntries)
	case LocalNumUint:
		txn.LocalStateSchema.NumUint, err =
			sv.uintMaxed(cx.Proto.MaxLocalSchemaEntries)
	case LocalNumByteSlice:
		txn.LocalStateSchema.NumByteSlice, err =
			sv.uintMaxed(cx.Proto.MaxLocalSchemaEntries)
	case ExtraProgramPages:
		var epp uint64
		epp, err =
			sv.uintMaxed(uint64(cx.Proto.MaxExtraAppProgramPages))
		if err != nil {
			return err
		}
		txn.ExtraProgramPages = uint32(epp)
	default:
		return fmt.Errorf("invalid itxn_field %s", fs.field)
	}
	return
}

func opItxnField(cx *EvalContext) error {
	itx := len(cx.subtxns) - 1
	if itx < 0 {
		return errors.New("itxn_field without itxn_begin")
	}
	last := len(cx.stack) - 1
	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField(field)
	if !ok || fs.itxVersion == 0 || fs.itxVersion > cx.version {
		return fmt.Errorf("invalid itxn_field %s", field)
	}
	sv := cx.stack[last]
	err := cx.stackIntoTxnField(sv, &fs, &cx.subtxns[itx].Txn)
	cx.stack = cx.stack[:last] // pop
	return err
}

func opItxnSubmit(cx *EvalContext) error {
	// Should rarely trigger, since itxn_next checks these too. (but that check
	// must be imperfect, see its comment) In contrast to that check, subtxns is
	// already populated here.
	if len(cx.subtxns) > cx.remainingInners() || len(cx.subtxns) > cx.Proto.MaxTxGroupSize {
		return fmt.Errorf("too many inner transactions %d with %d left", len(cx.subtxns), cx.remainingInners())
	}

	if len(cx.subtxns) == 0 {
		return errors.New("itxn_submit without itxn_begin")
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
			return fmt.Errorf("fee too small %#v", cx.subtxns)
		}
		*cx.FeeCredit -= shortfall
	} else {
		overpay := groupPaid - groupFee
		if cx.FeeCredit == nil {
			cx.FeeCredit = new(uint64)
		}
		*cx.FeeCredit = basics.AddSaturate(*cx.FeeCredit, overpay)
	}

	// All subtxns will have zero'd GroupID since GroupID can't be set in
	// AVM. (no need to blank it out before hashing for TxID)
	var group transactions.TxGroup
	var parent transactions.Txid
	isGroup := len(cx.subtxns) > 1
	if isGroup {
		parent = cx.currentTxID()
	}
	for itx := range cx.subtxns {
		// The goal is to follow the same invariants used by the
		// transaction pool. Namely that any transaction that makes it
		// to Perform (which is equivalent to eval.applyTransaction)
		// is authorized, and WellFormed.
		err := authorizedSender(cx, cx.subtxns[itx].Txn.Sender)
		if err != nil {
			return err
		}

		// Recall that WellFormed does not care about individual
		// transaction fees because of fee pooling. Checked above.
		err = cx.subtxns[itx].Txn.WellFormed(*cx.Specials, *cx.Proto)
		if err != nil {
			return err
		}

		// Disallow reentrancy, limit inner app call depth, and do version checks
		if cx.subtxns[itx].Txn.Type == protocol.ApplicationCallTx {
			if cx.appID == cx.subtxns[itx].Txn.ApplicationID {
				return fmt.Errorf("attempt to self-call")
			}
			depth := 0
			for parent := cx.caller; parent != nil; parent = parent.caller {
				if parent.appID == cx.subtxns[itx].Txn.ApplicationID {
					return fmt.Errorf("attempt to re-enter %d", parent.appID)
				}
				depth++
			}
			if depth >= maxAppCallDepth {
				return fmt.Errorf("appl depth (%d) exceeded", depth)
			}

			// Set program by txn, approval, or clear state
			program := cx.subtxns[itx].Txn.ApprovalProgram
			if cx.subtxns[itx].Txn.ApplicationID != 0 {
				app, _, err := cx.Ledger.AppParams(cx.subtxns[itx].Txn.ApplicationID)
				if err != nil {
					return err
				}
				program = app.ApprovalProgram
				if cx.subtxns[itx].Txn.OnCompletion == transactions.ClearStateOC {
					program = app.ClearStateProgram
				}
			}

			// Can't call old versions in inner apps.
			v, _, err := transactions.ProgramVersion(program)
			if err != nil {
				return err
			}
			if v < cx.Proto.MinInnerApplVersion {
				return fmt.Errorf("inner app call with version v%d < v%d",
					v, cx.Proto.MinInnerApplVersion)
			}

			// Don't allow opt-in if the CSP is not runnable as an inner.
			// This test can only fail for v4 and v5 approval programs,
			// since v6 requires synchronized versions.
			if cx.subtxns[itx].Txn.OnCompletion == transactions.OptInOC {
				csp := cx.subtxns[itx].Txn.ClearStateProgram
				if cx.subtxns[itx].Txn.ApplicationID != 0 {
					app, _, err := cx.Ledger.AppParams(cx.subtxns[itx].Txn.ApplicationID)
					if err != nil {
						return err
					}
					csp = app.ClearStateProgram
				}
				csv, _, err := transactions.ProgramVersion(csp)
				if err != nil {
					return err
				}
				if csv < cx.Proto.MinInnerApplVersion {
					return fmt.Errorf("inner app call opt-in with CSP v%d < v%d",
						csv, cx.Proto.MinInnerApplVersion)
				}
			}

		}

		if isGroup {
			innerOffset := len(cx.txn.EvalDelta.InnerTxns)
			if cx.Proto.UnifyInnerTxIDs {
				innerOffset += itx
			}
			group.TxGroupHashes = append(group.TxGroupHashes,
				crypto.Digest(cx.subtxns[itx].Txn.InnerID(parent, innerOffset)))
		}
	}

	if isGroup {
		groupID := crypto.HashObj(group)
		for itx := range cx.subtxns {
			cx.subtxns[itx].Txn.Group = groupID
		}
	}

	// Decrement allowed inners *before* execution, else runaway recursion is
	// not noticed.
	if cx.pooledAllowedInners != nil {
		*cx.pooledAllowedInners -= len(cx.subtxns)
	}

	ep := NewInnerEvalParams(cx.subtxns, cx)
	for i := range ep.TxnGroup {
		err := cx.Ledger.Perform(i, ep)
		if err != nil {
			return err
		}
		// This is mostly a no-op, because Perform does its work "in-place", but
		// RecordAD has some further responsibilities.
		ep.RecordAD(i, ep.TxnGroup[i].ApplyData)
	}
	cx.txn.EvalDelta.InnerTxns = append(cx.txn.EvalDelta.InnerTxns, ep.TxnGroup...)
	cx.subtxns = nil
	// must clear the inner txid cache, otherwise prior inner txids will be returned for this group
	cx.innerTxidCache = nil
	return nil
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
	n, err := encoding.Decode(decoded, encoded)
	if err != nil {
		return decoded[:0], err
	}
	return decoded[:n], err
}

// base64padded returns true iff `encoded` has padding chars at the end
func base64padded(encoded []byte) bool {
	for i := len(encoded) - 1; i > 0; i-- {
		switch encoded[i] {
		case '=':
			return true
		case '\n', '\r':
			/* nothing */
		default:
			return false
		}
	}
	return false
}

func opBase64Decode(cx *EvalContext) error {
	last := len(cx.stack) - 1
	encodingField := Base64Encoding(cx.program[cx.pc+1])
	fs, ok := base64EncodingSpecByField(encodingField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid base64_decode encoding %s", encodingField)
	}

	encoding := base64.URLEncoding
	if encodingField == StdEncoding {
		encoding = base64.StdEncoding
	}
	encoded := cx.stack[last].Bytes
	if !base64padded(encoded) {
		encoding = encoding.WithPadding(base64.NoPadding)
	}
	bytes, err := base64Decode(encoded, encoding.Strict())
	if err != nil {
		return err
	}
	cx.stack[last].Bytes = bytes
	return nil
}
func hasDuplicateKeys(jsonText []byte) (bool, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(jsonText))
	parsed := make(map[string]json.RawMessage)
	t, err := dec.Token()
	if err != nil {
		return false, nil, err
	}
	t, ok := t.(json.Delim)
	if !ok || t.(json.Delim).String() != "{" {
		return false, nil, fmt.Errorf("only json object is allowed")
	}
	for dec.More() {
		var value json.RawMessage
		// get JSON key
		key, err := dec.Token()
		if err != nil {
			return false, nil, err
		}
		// end of json
		if key == '}' {
			break
		}
		// decode value
		err = dec.Decode(&value)
		if err != nil {
			return false, nil, err
		}
		// check for duplicates
		if _, ok := parsed[key.(string)]; ok {
			return true, nil, nil
		}
		parsed[key.(string)] = value
	}
	return false, parsed, nil
}

func parseJSON(jsonText []byte) (map[string]json.RawMessage, error) {
	if !json.Valid(jsonText) {
		return nil, fmt.Errorf("invalid json text")
	}
	// parse json text and check for duplicate keys
	hasDuplicates, parsed, err := hasDuplicateKeys(jsonText)
	if hasDuplicates {
		return nil, fmt.Errorf("invalid json text, duplicate keys not allowed")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid json text, %v", err)
	}
	return parsed, nil
}
func opJSONRef(cx *EvalContext) error {
	// get json key
	last := len(cx.stack) - 1
	key := string(cx.stack[last].Bytes)
	cx.stack = cx.stack[:last] // pop

	expectedType := JSONRefType(cx.program[cx.pc+1])
	fs, ok := jsonRefSpecByField(expectedType)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid json_ref type %s", expectedType)
	}

	// parse json text
	last = len(cx.stack) - 1
	parsed, err := parseJSON(cx.stack[last].Bytes)
	if err != nil {
		return fmt.Errorf("error while parsing JSON text, %v", err)
	}

	// get value from json
	var stval stackValue
	_, ok = parsed[key]
	if !ok {
		return fmt.Errorf("key %s not found in JSON text", key)
	}

	switch expectedType {
	case JSONString:
		var value string
		err := json.Unmarshal(parsed[key], &value)
		if err != nil {
			return err
		}
		stval.Bytes = []byte(value)
	case JSONUint64:
		var value uint64
		err := json.Unmarshal(parsed[key], &value)
		if err != nil {
			return err
		}
		stval.Uint = value
	case JSONObject:
		var value map[string]json.RawMessage
		err := json.Unmarshal(parsed[key], &value)
		if err != nil {
			return err
		}
		stval.Bytes = parsed[key]
	default:
		return fmt.Errorf("unsupported json_ref return type %s", expectedType)
	}
	cx.stack[last] = stval
	return nil
}
