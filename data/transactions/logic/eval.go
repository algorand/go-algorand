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
	"bytes"
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
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

// The constants below control opcode evaluation and MAY NOT be changed without
// gating them by version. Old programs need to retain their old behavior.

// maxStringSize is the limit of byte string length in an AVM value
const maxStringSize = 4096

// maxByteMathSize is the limit of byte strings supplied as input to byte math opcodes
const maxByteMathSize = 64

// maxLogSize is the limit of total log size from n log calls in a program
const maxLogSize = bounds.MaxEvalDeltaTotalLogSize

// maxLogCalls is the limit of total log calls during a program execution
const maxLogCalls = 32

// maxAppCallDepth is the limit on inner appl call depth
// To be clear, 0 would prevent inner appls, 1 would mean inner app calls cannot
// make inner appls. So the total app depth can be 1 higher than this number, if
// you count the top-level app call.
var maxAppCallDepth = 8

// maxStackDepth should not change unless controlled by an AVM version change
const maxStackDepth = 1000

// maxTxGroupSize is the same as bounds.MaxTxGroupSize, but is a constant so
// that we can declare an array of this size. A unit test confirms that they
// match.
const maxTxGroupSize = 16

// stackValue is the type for the operand stack.
// Each stackValue is either a valid []byte value or a uint64 value.
// If (.Bytes != nil) the stackValue is a []byte value, otherwise uint64 value.
type stackValue struct {
	Uint  uint64
	Bytes []byte
}

func (sv stackValue) avmType() avmType {
	if sv.Bytes != nil {
		return avmBytes
	}
	return avmUint64
}

func (sv stackValue) stackType() StackType {
	if sv.Bytes != nil {
		return NewStackType(sv.avmType(), static(uint64(len(sv.Bytes))))
	}
	return NewStackType(sv.avmType(), static(sv.Uint))
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

func (sv stackValue) asAny() any {
	if sv.Bytes != nil {
		return sv.Bytes
	}
	return sv.Uint
}

func (sv stackValue) isEmpty() bool {
	return sv.Bytes == nil && sv.Uint == 0
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
		return 0, fmt.Errorf("%#v is not a uint64", sv.Bytes)
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

// ToTealValue converts a stack value instance into a basics.TealValue instance
func (sv stackValue) ToTealValue() basics.TealValue {
	if sv.avmType() == avmBytes {
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

// computeMinAvmVersion calculates the minimum safe AVM version that may be
// used by a transaction in this group. It is important to prevent
// newly-introduced transaction fields from breaking assumptions made by older
// versions of the AVM. If one of the transactions in a group will execute a TEAL
// program whose version predates a given field, that field must not be set
// anywhere in the transaction group, or the group will be rejected.
func computeMinAvmVersion(group []transactions.SignedTxnWithAD) uint64 {
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

// LedgerForSignature represents the parts of Ledger that LogicSigs can see. It
// only exposes things that consensus has already agreed upon, so it is
// "stateless" for signature purposes.
type LedgerForSignature interface {
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	GenesisHash() crypto.Digest
}

// NoHeaderLedger is intended for debugging TEAL in isolation(no real ledger) in
// which it is reasonable to preclude the use of `block`, `txn
// LastValidTime`. Also `global GenesisHash` is just a static value.
type NoHeaderLedger struct {
}

// BlockHdr always errors
func (NoHeaderLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, fmt.Errorf("no block header access")
}

// GenesisHash returns a fixed value
func (NoHeaderLedger) GenesisHash() crypto.Digest {
	return crypto.Digest{
		0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	}
}

// LedgerForLogic represents ledger API for Stateful TEAL program
type LedgerForLogic interface {
	AccountData(addr basics.Address) (ledgercore.AccountData, error)
	Authorizer(addr basics.Address) (basics.Address, error)
	Round() basics.Round
	PrevTimestamp() int64

	// These are simplifications of the underlying Ledger methods that take a
	// round argument. They implicitly use agreement's BalanceRound (320 back).
	AgreementData(addr basics.Address) (basics.OnlineAccountData, error)
	OnlineStake() (basics.MicroAlgos, error)

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

	NewBox(appIdx basics.AppIndex, key string, value []byte, appAddr basics.Address) error
	GetBox(appIdx basics.AppIndex, key string) ([]byte, bool, error)
	SetBox(appIdx basics.AppIndex, key string, value []byte) error
	DelBox(appIdx basics.AppIndex, key string, appAddr basics.Address) (bool, error)

	Perform(gi int, ep *EvalParams) error
	Counter() uint64
}

// UnnamedResourcePolicy is an interface that defines the policy for allowing unnamed resources.
// This should only be used during simulation or debugging.
type UnnamedResourcePolicy interface {
	AvailableAccount(addr basics.Address) bool
	AvailableAsset(asset basics.AssetIndex) bool
	AvailableApp(app basics.AppIndex) bool
	AllowsHolding(addr basics.Address, asset basics.AssetIndex) bool
	AllowsLocal(addr basics.Address, app basics.AppIndex) bool
	AvailableBox(app basics.AppIndex, name string, newAppAccess bool, createSize uint64) bool
	IOSurplus(surplus int64) bool
}

// EvalConstants contains constant parameters that are used by opcodes during evaluation (including both real-execution and simulation).
type EvalConstants struct {
	// MaxLogSize is the limit of total log size from n log calls in a program
	MaxLogSize int

	// MaxLogCalls is the limit of total log calls during a program execution
	MaxLogCalls int

	// UnnamedResources, if provided, allows resources to be used without being named according to
	// this policy.
	UnnamedResources UnnamedResourcePolicy
}

// RuntimeEvalConstants gives a set of const params used in normal runtime of opcodes
func RuntimeEvalConstants() EvalConstants {
	return EvalConstants{
		MaxLogSize:  maxLogSize,
		MaxLogCalls: maxLogCalls,
	}
}

// EvalParams contains data that comes into condition evaluation.
type EvalParams struct {
	runMode RunMode

	Proto *config.ConsensusParams

	Trace *strings.Builder

	TxnGroup []transactions.SignedTxnWithAD

	pastScratch [maxTxGroupSize]*scratchSpace

	logger logging.Logger

	SigLedger LedgerForSignature
	Ledger    LedgerForLogic

	// optional tracer
	Tracer EvalTracer

	// minAvmVersion is the minimum allowed AVM version of a program to be
	// evaluated in TxnGroup.
	minAvmVersion uint64

	// Amount "overpaid" by the transactions of the group.  Often 0.  When
	// positive, it can be spent by inner transactions.  Shared across a group's
	// txns, so that it can be updated (including upward, by overpaying inner
	// transactions). nil is treated as 0 (used before fee pooling is enabled).
	FeeCredit *uint64

	Specials *transactions.SpecialAddresses

	// Total pool of app call budget in a group transaction (nil before budget pooling enabled)
	PooledApplicationBudget *int

	// Total pool of logicsig budget in a group transaction (nil before lsig pooling enabled)
	PooledLogicSigBudget *int

	// Total allowable inner txns in a group transaction (nil before inner pooling enabled)
	pooledAllowedInners *int

	// available contains resources that may be used even though they are not
	// necessarily directly in the txn's "static arrays". Apps and ASAs go in if
	// the app or asa was created earlier in the txgroup (empty until
	// createdResourcesVersion). Boxes go in when the ep is created, to share
	// availability across all txns in the group.
	available *resources

	// ioBudget is the number of bytes that the box ref'd boxes can sum to, and
	// the number of bytes that created or written boxes may sum to.
	ioBudget uint64

	// readBudgetChecked allows us to only check the read budget once
	readBudgetChecked bool

	// SurplusReadBudget is the number of bytes from the IO budget that were not
	// used for reading in boxes before evaluation began. In other words, the
	// txn group could have read in SurplusReadBudget more box bytes, but did
	// not.  It is signed because `simulate` evaluates groups even if they come
	// in with insufficient io budget, and reports the need, when invoked with
	// AllowUnnamedResources.
	SurplusReadBudget int64

	EvalConstants

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

// GetCaller returns the calling EvalContext if this is an inner transaction evaluation. Otherwise,
// this returns nil.
func (ep *EvalParams) GetCaller() *EvalContext {
	return ep.caller
}

// GetIOBudget returns the current IO budget for the group.
func (ep *EvalParams) GetIOBudget() uint64 {
	return ep.ioBudget
}

// SetIOBudget sets the IO budget for the group.
func (ep *EvalParams) SetIOBudget(ioBudget uint64) {
	ep.ioBudget = ioBudget
}

// BoxDirtyBytes returns the number of bytes that have been written to boxes
func (ep *EvalParams) BoxDirtyBytes() uint64 {
	return ep.available.dirtyBytes
}

func copyWithClearAD(txgroup []transactions.SignedTxnWithAD) []transactions.SignedTxnWithAD {
	copy := make([]transactions.SignedTxnWithAD, len(txgroup))
	for i := range txgroup {
		copy[i].SignedTxn = txgroup[i].SignedTxn
		// leave copy[i].ApplyData clear
	}
	return copy
}

// NewSigEvalParams creates an EvalParams to be used while evaluating a group's logicsigs
func NewSigEvalParams(txgroup []transactions.SignedTxn, proto *config.ConsensusParams, ls LedgerForSignature) *EvalParams {
	lsigs := 0
	for _, tx := range txgroup {
		if !tx.Lsig.Blank() {
			lsigs++
		}
	}

	var pooledLogicBudget *int
	if lsigs > 0 { // don't allocate if no lsigs
		if proto.EnableLogicSigCostPooling {
			pooledLogicBudget = new(int)
			*pooledLogicBudget = len(txgroup) * int(proto.LogicSigMaxCost)
		}
	}

	withADs := transactions.WrapSignedTxnsWithAD(txgroup)
	return &EvalParams{
		runMode:              ModeSig,
		TxnGroup:             withADs,
		Proto:                proto,
		minAvmVersion:        computeMinAvmVersion(withADs),
		SigLedger:            ls,
		PooledLogicSigBudget: pooledLogicBudget,
	}
}

// NewAppEvalParams creates an EvalParams to use while evaluating a top-level txgroup.
func NewAppEvalParams(txgroup []transactions.SignedTxnWithAD, proto *config.ConsensusParams, specials *transactions.SpecialAddresses) *EvalParams {
	apps := 0
	for _, tx := range txgroup {
		if tx.Txn.Type == protocol.ApplicationCallTx {
			apps++
		}
	}

	var pooledApplicationBudget *int
	var pooledAllowedInners *int
	var credit *uint64

	if apps > 0 { // none of these allocations needed if no apps
		credit = new(uint64)
		*credit = feeCredit(txgroup, proto.MinTxnFee)

		if proto.EnableAppCostPooling {
			pooledApplicationBudget = new(int)
			*pooledApplicationBudget = apps * proto.MaxAppProgramCost
		}

		if proto.EnableInnerTransactionPooling {
			pooledAllowedInners = new(int)
			*pooledAllowedInners = proto.MaxTxGroupSize * proto.MaxInnerTransactions
		}
	}

	ep := &EvalParams{
		runMode:                 ModeApp,
		TxnGroup:                copyWithClearAD(txgroup),
		Proto:                   proto,
		Specials:                specials,
		minAvmVersion:           computeMinAvmVersion(txgroup),
		FeeCredit:               credit,
		PooledApplicationBudget: pooledApplicationBudget,
		pooledAllowedInners:     pooledAllowedInners,
		appAddrCache:            make(map[basics.AppIndex]basics.Address),
		EvalConstants:           RuntimeEvalConstants(),
	}
	return ep
}

func (ep *EvalParams) computeAvailability() *resources {
	available := &resources{
		sharedAccounts: make(map[basics.Address]struct{}),
		sharedAsas:     make(map[basics.AssetIndex]struct{}),
		sharedApps:     make(map[basics.AppIndex]struct{}),
		sharedHoldings: make(map[ledgercore.AccountAsset]struct{}),
		sharedLocals:   make(map[ledgercore.AccountApp]struct{}),
		boxes:          make(map[basics.BoxRef]bool),
	}
	for i := range ep.TxnGroup {
		available.fill(&ep.TxnGroup[i].Txn, ep)
	}
	return available
}

// feeCredit returns the extra fee supplied in this top-level txgroup compared
// to required minfee.  It can make assumptions about overflow because the group
// is known OK according to txnGroupBatchPrep. (The group is "WellFormed")
func feeCredit(txgroup []transactions.SignedTxnWithAD, minFee uint64) uint64 {
	minFeeCount := uint64(0)
	feesPaid := uint64(0)
	for _, stxn := range txgroup {
		if stxn.Txn.Type != protocol.StateProofTx {
			minFeeCount++
		}
		feesPaid = basics.AddSaturate(feesPaid, stxn.Txn.Fee.Raw)
	}
	// Overflow is impossible, because txnGroupBatchPrep checked.
	feeNeeded := minFee * minFeeCount
	return basics.SubSaturate(feesPaid, feeNeeded)
}

// NewInnerEvalParams creates an EvalParams to be used while evaluating an inner group txgroup
func NewInnerEvalParams(txg []transactions.SignedTxnWithAD, caller *EvalContext) *EvalParams {
	minAvmVersion := max(computeMinAvmVersion(txg), caller.minAvmVersion)
	// caller.AvmVersion can't exceed the computed value currently, since earliest
	// inner callable version is higher than any minimum imposed otherwise.  But is
	// correct to inherit a stronger restriction from above, in case of future restriction.

	// Unlike NewEvalParams, do not add fee credit here. opTxSubmit has already done so.

	if caller.Proto.EnableAppCostPooling {
		for _, tx := range txg {
			if tx.Txn.Type == protocol.ApplicationCallTx {
				*caller.PooledApplicationBudget += caller.Proto.MaxAppProgramCost
			}
		}
	}

	ep := &EvalParams{
		runMode:                 ModeApp,
		Proto:                   caller.Proto,
		Trace:                   caller.Trace,
		TxnGroup:                txg,
		logger:                  caller.logger,
		SigLedger:               caller.SigLedger,
		Ledger:                  caller.Ledger,
		Tracer:                  caller.Tracer,
		minAvmVersion:           minAvmVersion,
		FeeCredit:               caller.FeeCredit,
		Specials:                caller.Specials,
		PooledApplicationBudget: caller.PooledApplicationBudget,
		pooledAllowedInners:     caller.pooledAllowedInners,
		available:               caller.available,
		ioBudget:                caller.ioBudget,
		readBudgetChecked:       true, // don't check for inners
		appAddrCache:            caller.appAddrCache,
		EvalConstants:           caller.EvalConstants,
		// read comment in EvalParams declaration about txid caches
		caller: caller,
	}
	return ep
}

type evalFunc func(cx *EvalContext) error
type checkFunc func(cx *EvalContext) error

// RunMode is a bitset of logic evaluation modes.
// There are currently two such modes: Signature and Application.
type RunMode uint64

const (
	// ModeSig is LogicSig execution
	ModeSig RunMode = 1 << iota

	// ModeApp is application/contract execution
	ModeApp

	// local constant, run in any mode
	modeAny = ModeSig | ModeApp
)

// Any checks if this mode bitset represents any evaluation mode
func (r RunMode) Any() bool {
	return r == modeAny
}

func (r RunMode) String() string {
	switch r {
	case ModeSig:
		return "Signature"
	case ModeApp:
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
	if ep.runMode == ModeSig {
		// We should not be touching a signature mode EvalParams as it shares
		// memory with its caller.  LogicSigs are supposed to be stateless!
		panic("RecordAD called in signature mode")
	}
	ep.TxnGroup[gi].ApplyData = ad
	if aid := ad.ConfigAsset; aid != 0 {
		if ep.available == nil { // here, and below, we may need to make `ep.available`
			ep.available = ep.computeAvailability()
		}
		if ep.available.createdAsas == nil {
			ep.available.createdAsas = make(map[basics.AssetIndex]struct{})
		}
		ep.available.createdAsas[aid] = struct{}{}
	}
	// we don't need to add ad.ApplicationID to createdApps, because that is
	// done at the beginning of app execution now, so that newly created apps
	// will already have their appID present.
}

type frame struct {
	retpc  int
	height int

	clear   bool // perform "shift and clear" in retsub
	args    int
	returns int
}

type scratchSpace [256]stackValue

// EvalContext is the execution context of AVM bytecode.  It contains the full
// state of the running program, and tracks some of the things that the program
// has done, like log messages and inner transactions.
type EvalContext struct {
	*EvalParams

	// determines eval mode: ModeSig or ModeApp
	runMode RunMode

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

	Stack       []stackValue
	callstack   []frame
	fromCallsub bool

	appID   basics.AppIndex
	program []byte
	pc      int
	nextpc  int
	intc    []uint64
	bytec   [][]byte
	version uint64
	Scratch scratchSpace

	subtxns []transactions.SignedTxnWithAD // place to build for itxn_submit
	cost    int                            // cost incurred so far
	logSize int                            // total log size so far

	// Set of PC values that branches we've seen so far might
	// go. So, if checkStep() skips one, that branch is trying to
	// jump into the middle of a multibyte instruction
	branchTargets []bool

	// Set of PC values that we have begun a checkStep() with. So
	// if a back jump is going to a value that isn't here, it's
	// jumping into the middle of multibyte instruction.
	instructionStarts []bool

	programHashCached crypto.Digest
}

// GroupIndex returns the group index of the transaction being evaluated
func (cx *EvalContext) GroupIndex() int {
	return cx.groupIndex
}

// RunMode returns the evaluation context's mode (signature or application)
func (cx *EvalContext) RunMode() RunMode {
	return cx.runMode
}

// ProgramVersion returns the AVM version of the current program.
func (cx *EvalContext) ProgramVersion() uint64 {
	return cx.version
}

// PC returns the program counter of the current application being evaluated
func (cx *EvalContext) PC() int { return cx.pc }

// GetOpSpec queries for the OpSpec w.r.t. current program byte.
func (cx *EvalContext) GetOpSpec() OpSpec { return opsByOpcode[cx.version][cx.program[cx.pc]] }

// GetProgram queries for the current program
func (cx *EvalContext) GetProgram() []byte { return cx.program }

// avmType describes the type of a value on the operand stack
// avmTypes are a subset of StackTypes
type avmType byte

const (
	// avmNone in an OpSpec shows that the op pops or yields nothing
	avmNone avmType = iota

	// avmAny in an OpSpec shows that the op pops or yield any type
	avmAny

	// avmUint64 in an OpSpec shows that the op pops or yields a uint64
	avmUint64

	// avmBytes in an OpSpec shows that the op pops or yields a []byte
	avmBytes
)

func (at avmType) String() string {
	switch at {
	case avmNone:
		return "none"
	case avmAny:
		return "any"
	case avmUint64:
		return "uint64"
	case avmBytes:
		return "[]byte"
	}
	return "internal error, unknown type"
}

var (
	// StackUint64 is any valid uint64
	StackUint64 = NewStackType(avmUint64, bound(0, math.MaxUint64))
	// StackBytes is any valid bytestring
	StackBytes = NewStackType(avmBytes, bound(0, maxStringSize))
	// StackAny could be Bytes or Uint64
	StackAny = StackType{
		Name:    avmAny.String(),
		AVMType: avmAny,
		Bound:   [2]uint64{0, 0},
	}
	// StackNone is used when there is no input or output to
	// an opcode
	StackNone = StackType{
		Name:    avmNone.String(),
		AVMType: avmNone,
	}

	// StackBoolean constrains the int to 1 or 0, representing True or False
	StackBoolean = NewStackType(avmUint64, bound(0, 1), "bool")
	// StackAddress represents an address
	StackAddress = NewStackType(avmBytes, static(32), "address")
	// StackBytes32 represents a bytestring that should have exactly 32 bytes
	StackBytes32 = NewStackType(avmBytes, static(32), "[32]byte")
	// StackBytes64 represents a bytestring that should have exactly 64 bytes
	StackBytes64 = NewStackType(avmBytes, static(64), "[64]byte")
	// StackBytes80 represents a bytestring that should have exactly 80 bytes
	StackBytes80 = NewStackType(avmBytes, static(80), "[80]byte")
	// StackBigInt represents a bytestring that should be treated like an int
	StackBigInt = NewStackType(avmBytes, bound(0, maxByteMathSize), "bigint")
	// StackMethodSelector represents a bytestring that should be treated like a method selector
	StackMethodSelector = NewStackType(avmBytes, static(4), "method")
	// StackStateKey represents a bytestring that can be used as a key to some storage (global/local/box)
	StackStateKey = NewStackType(avmBytes, bound(0, 64), "stateKey")
	// StackBoxName represents a bytestring that can be used as a key to a box
	StackBoxName = NewStackType(avmBytes, bound(1, 64), "boxName")

	// StackZeroUint64 is a StackUint64 with a minimum value of 0 and a maximum value of 0
	StackZeroUint64 = NewStackType(avmUint64, bound(0, 0), "0")
	// StackZeroBytes is a StackBytes with a minimum length of 0 and a maximum length of 0
	StackZeroBytes = NewStackType(avmUint64, bound(0, 0), "''")

	// AllStackTypes is a map of all the stack types we recognize
	// so that we can iterate over them in doc prep
	// and use them for opcode proto shorthand
	AllStackTypes = map[byte]StackType{
		'a': StackAny,
		'b': StackBytes,
		'i': StackUint64,
		'x': StackNone,
		'A': StackAddress,
		'I': StackBigInt,
		'T': StackBoolean,
		'M': StackMethodSelector,
		'K': StackStateKey,
		'N': StackBoxName,
	}
)

func bound(min, max uint64) [2]uint64 {
	return [2]uint64{min, max}
}

func static(size uint64) [2]uint64 {
	return bound(size, size)
}

func union(a, b [2]uint64) [2]uint64 {
	u := [2]uint64{a[0], a[1]}
	if b[0] < u[0] {
		u[0] = b[0]
	}

	if b[1] > u[1] {
		u[1] = b[1]
	}
	return u
}

// StackType describes the type of a value on the operand stack
type StackType struct {
	Name    string // alias (address, boolean, ...) or derived name [5]byte
	AVMType avmType
	Bound   [2]uint64 // represents max/min value for uint64 or max/min length for byte[]
}

// NewStackType Initializes a new StackType with fields passed
func NewStackType(at avmType, bounds [2]uint64, stname ...string) StackType {
	name := at.String()

	// It's static, set the name to show
	// the static value
	if bounds[0] == bounds[1] {
		switch at {
		case avmBytes:
			name = fmt.Sprintf("[%d]byte", bounds[0])
		case avmUint64:
			name = fmt.Sprintf("%d", bounds[0])
		}
	}

	if len(stname) > 0 {
		name = stname[0]
	}

	return StackType{Name: name, AVMType: at, Bound: bounds}
}

func (st StackType) union(b StackType) StackType {
	// TODO: Can we ever receive one or the other
	// as None? should that be a panic?
	if st.AVMType != b.AVMType {
		return StackAny
	}

	// Same type now, so we can just take the union of the bounds
	return NewStackType(st.AVMType, union(st.Bound, b.Bound))
}

func (st StackType) narrowed(bounds [2]uint64) StackType {
	return NewStackType(st.AVMType, bounds)
}

func (st StackType) widened() StackType {
	// Take only the avm type
	switch st.AVMType {
	case avmBytes:
		return StackBytes
	case avmUint64:
		return StackUint64
	case avmAny:
		return StackAny
	default:
		panic(fmt.Sprintf("What are you tyring to widen?: %+v", st))
	}
}

func (st StackType) constInt() (uint64, bool) {
	if st.AVMType != avmUint64 || st.Bound[0] != st.Bound[1] {
		return 0, false
	}
	return st.Bound[0], true
}

// overlaps checks if there is enough overlap
// between the given types that the receiver can
// possible fit in the expected type
func (st StackType) overlaps(expected StackType) bool {
	if st.AVMType == avmNone || expected.AVMType == avmNone {
		return false
	}

	if st.AVMType == avmAny || expected.AVMType == avmAny {
		return true
	}

	// By now, both are either uint or bytes
	// and must match
	if st.AVMType != expected.AVMType {
		return false
	}

	// Same type now
	// Check if our constraints will satisfy the other type
	smin, smax := st.Bound[0], st.Bound[1]
	emin, emax := expected.Bound[0], expected.Bound[1]

	return smin <= emax && smax >= emin
}

func (st StackType) String() string {
	return st.Name
}

// Typed tells whether the StackType is a specific concrete type.
func (st StackType) Typed() bool {
	switch st.AVMType {
	case avmUint64, avmBytes:
		return true
	}
	return false
}

// StackTypes is an alias for a list of StackType with syntactic sugar
type StackTypes []StackType

func parseStackTypes(spec string) StackTypes {
	if spec == "" {
		return nil
	}
	types := make(StackTypes, 0, len(spec))
	for i := 0; i < len(spec); i++ {
		letter := spec[i]
		if letter == '{' {
			if types[len(types)-1] != StackBytes {
				panic("{ after non-bytes " + spec)
			}
			end := strings.IndexByte(spec[i:], '}')
			if end == -1 {
				panic("No } after b{ " + spec)
			}
			size, err := strconv.Atoi(spec[i+1 : i+end])
			if err != nil {
				panic("b{} does not contain a number " + spec)
			}
			// replace the generic type with the constrained type
			types[len(types)-1] = NewStackType(avmBytes, static(uint64(size)), fmt.Sprintf("[%d]byte", size))
			i += end
			continue
		}
		st, ok := AllStackTypes[letter]
		if !ok {
			panic(spec)
		}
		types = append(types, st)
	}
	return types
}

func filterNoneTypes(sts StackTypes) StackTypes {
	var filteredSts = make(StackTypes, 0, len(sts))
	for i := range sts {
		if sts[i].AVMType != avmNone {
			filteredSts = append(filteredSts, sts[i])
		}
	}
	return filteredSts
}

// panicError wraps a recover() catching a panic()
type panicError struct {
	PanicValue interface{}
	StackTrace string
}

func (pe panicError) Error() string {
	return fmt.Sprintf("panic in TEAL Eval: %v\n%s", pe.PanicValue, pe.StackTrace)
}

var errLogicSigNotSupported = errors.New("LogicSig not supported")
var errTooManyArgs = errors.New("LogicSig has too many arguments")
var errLogicSigArgTooLarge = errors.New("LogicSig argument too large")

// EvalError indicates AVM evaluation failure
type EvalError struct {
	Err      error
	details  string
	logicsig bool
}

// Error satisfies builtin interface `error`
func (err EvalError) Error() string {
	var msg string
	if err.logicsig {
		msg = fmt.Sprintf("rejected by logic err=%v", err.Err)
	} else {
		msg = fmt.Sprintf("logic eval error: %v", err.Err)
	}
	if err.details == "" {
		return msg
	}
	return msg + ". Details: " + err.details
}

func (err EvalError) Unwrap() error {
	return err.Err
}

func (cx *EvalContext) evalError(err error) error {
	var pc int
	var details string
	if cx.Tracer != nil && cx.Tracer.DetailedEvalErrors() {
		var det string
		pc, det = cx.pcDetails()
		details = fmt.Sprintf("pc=%d, opcodes=%s", pc, det)
	} else {
		pc = cx.pc
		details = fmt.Sprintf("pc=%d", pc)
	}

	err = basics.Annotate(err,
		"pc", pc,
		"group-index", cx.groupIndex,
		"eval-states", cx.evalStates())
	if cx.runMode == ModeApp {
		details = fmt.Sprintf("app=%d, %s", cx.appID, details)
		err = basics.Annotate(err, "app-index", cx.appID)
	}

	return EvalError{err, details, cx.runMode == ModeSig}
}

type evalState struct {
	Scratch []any    `json:"scratch,omitempty"`
	Stack   []any    `json:"stack,omitempty"`
	Logs    [][]byte `json:"logs,omitempty"`
}

func (cx *EvalContext) evalStates() []evalState {
	states := make([]evalState, cx.groupIndex+1)
	for i := 0; i <= cx.groupIndex; i++ {
		var scratch []stackValue
		if cx.pastScratch[i] != nil {
			scratch = (*cx.pastScratch[i])[:]
		}
		lastNonZero := -1
		scratchAsAny := make([]any, len(scratch))
		for s, sv := range scratch {
			if !sv.isEmpty() {
				lastNonZero = s
			}
			scratchAsAny[s] = sv.asAny()
		}
		if lastNonZero == -1 {
			scratchAsAny = nil
		} else {
			scratchAsAny = scratchAsAny[:lastNonZero+1]
		}

		// Only the current program's stack is still available. So perhaps it
		// should be located outside of the evalState, with the PC.
		var stack []any
		if cx.groupIndex == i {
			stack = util.Map(cx.Stack, stackValue.asAny)
		}

		states[i] = evalState{
			Scratch: scratchAsAny,
			Stack:   stack,
			Logs:    util.Map(cx.TxnGroup[i].EvalDelta.Logs, func(s string) []byte { return []byte(s) }),
		}
	}
	return states
}

// EvalContract executes stateful program as the gi'th transaction in params
func EvalContract(program []byte, gi int, aid basics.AppIndex, params *EvalParams) (bool, *EvalContext, error) {
	if params.Ledger == nil {
		return false, nil, errors.New("no ledger in contract eval")
	}
	if params.SigLedger == nil {
		return false, nil, errors.New("no sig ledger in contract eval")
	}
	if aid == 0 {
		return false, nil, errors.New("0 appId in contract eval")
	}
	if params.runMode != ModeApp {
		return false, nil, fmt.Errorf("attempt to evaluate a contract with %s mode EvalParams", params.runMode)
	}
	cx := EvalContext{
		EvalParams: params,
		runMode:    ModeApp,
		groupIndex: gi,
		txn:        &params.TxnGroup[gi],
		appID:      aid,
	}
	// Save scratch for `gload`. We used to copy, but cx.scratch is quite large,
	// about 8k, and caused measurable CPU and memory demands.  Of course, these
	// should never be changed by later transactions.
	cx.pastScratch[cx.groupIndex] = &cx.Scratch

	if cx.Proto.IsolateClearState && cx.txn.Txn.OnCompletion == transactions.ClearStateOC {
		if cx.PooledApplicationBudget != nil && *cx.PooledApplicationBudget < cx.Proto.MaxAppProgramCost {
			return false, nil, fmt.Errorf("attempted ClearState execution with low OpcodeBudget %d", *cx.PooledApplicationBudget)
		}
	}

	if cx.EvalParams.available == nil {
		cx.EvalParams.available = cx.EvalParams.computeAvailability()
	}

	// If this is a creation...
	if cx.txn.Txn.ApplicationID == 0 {
		// make any "0 index" box refs available now that we have an appID.
		// This allows case 2b in TestNewAppBoxCreate of boxtxn_test.go
		for _, br := range cx.txn.Txn.Boxes {
			if br.Index == 0 {
				cx.EvalParams.available.boxes[basics.BoxRef{App: cx.appID, Name: string(br.Name)}] = false
			}
		}
		for _, rr := range cx.txn.Txn.Access {
			if len(rr.Box.Name) > 0 && rr.Box.Index == 0 { // len check ensures we have a box ref
				cx.EvalParams.available.boxes[basics.BoxRef{App: cx.appID, Name: string(rr.Box.Name)}] = false
			}
		}
		// and add the appID to `createdApps`
		if cx.EvalParams.available.createdApps == nil {
			cx.EvalParams.available.createdApps = make(map[basics.AppIndex]struct{})
		}
		cx.EvalParams.available.createdApps[cx.appID] = struct{}{}
	}

	// Check the I/O budget for reading if this is the first top-level app call
	if cx.caller == nil && !cx.readBudgetChecked {
		bumps := uint64(0) // Intentionally counts duplicates
		for _, tx := range cx.TxnGroup {
			bumps += uint64(len(tx.Txn.Boxes))
			for _, rr := range tx.Txn.Access {
				// A box or an empty ref is an io quota bump
				if !rr.Box.Empty() || rr.Empty() {
					bumps++
				}
			}
		}
		cx.ioBudget = basics.MulSaturate(bumps, cx.Proto.BytesPerBoxReference)

		used := uint64(0)
		var surplus int64
		var overflow bool
		for br := range cx.available.boxes {
			if len(br.Name) == 0 {
				// 0 length names are not allowed for actual created boxes, but
				// may have been used to add I/O budget.
				continue
			}
			box, ok, err := cx.Ledger.GetBox(br.App, br.Name)
			if err != nil {
				return false, nil, err
			}
			if !ok {
				continue
			}
			size := uint64(len(box))
			cx.available.boxes[br] = false

			used = basics.AddSaturate(used, size)
			surplus, overflow = basics.ODiff(cx.ioBudget, used)
			// we defer the check if we have cx.UnnamedResources, so we can ask for the entire surplus at the end.
			if overflow || (surplus < 0 && cx.UnnamedResources == nil) {
				err = fmt.Errorf("box read budget (%d) exceeded", cx.ioBudget)
				if !cx.Proto.EnableBareBudgetError {
					// We return an EvalError here because we used to do
					// that. It is wrong, and means that there could be a
					// ClearState call in an old block that failed on read
					// quota, but we allowed to execute anyway.  If testnet and
					// mainnet have no such transactions, we can remove
					// EnableBareBudgetError and this code.
					err = EvalError{err, "", false}
				}
				return false, nil, err
			}
		}

		// Report the surplus/deficit to the policy, and find out if we should continue
		if cx.UnnamedResources != nil && !cx.UnnamedResources.IOSurplus(surplus) {
			return false, nil, fmt.Errorf("box read budget (%d) exceeded despite policy", cx.ioBudget)
		}

		cx.readBudgetChecked = true
		cx.SurplusReadBudget = surplus // Can be negative, but only in `simulate`
	}

	if cx.Trace != nil && cx.caller != nil {
		fmt.Fprintf(cx.Trace, "--- enter %d %s %v\n", aid, cx.txn.Txn.OnCompletion, cx.txn.Txn.ApplicationArgs)
	}
	pass, err := eval(program, &cx)
	if err != nil {
		err = cx.evalError(err)
	}

	if cx.Trace != nil && cx.caller != nil {
		fmt.Fprintf(cx.Trace, "--- exit  %d accept=%t\n", aid, pass)
	}

	return pass, &cx, err
}

// EvalApp is a lighter weight interface that doesn't return the EvalContext
func EvalApp(program []byte, gi int, aid basics.AppIndex, params *EvalParams) (bool, error) {
	pass, _, err := EvalContract(program, gi, aid, params)
	return pass, err
}

// EvalSignatureFull evaluates the logicsig of the ith transaction in params.
// A program passes successfully if it finishes with one int element on the stack that is non-zero.
// It returns EvalContext suitable for obtaining additional info about the execution.
func EvalSignatureFull(gi int, params *EvalParams) (bool, *EvalContext, error) {
	if params.SigLedger == nil {
		return false, nil, errors.New("no sig ledger in signature eval")
	}
	if params.runMode != ModeSig {
		return false, nil, fmt.Errorf("attempt to evaluate a signature with %s mode EvalParams", params.runMode)
	}
	cx := EvalContext{
		EvalParams: params,
		runMode:    ModeSig,
		groupIndex: gi,
		txn:        &params.TxnGroup[gi],
	}
	// Save scratch. `gload*` opcodes are not currently allowed in ModeSig
	// (though it seems we could allow them, with access to LogicSig scratch
	// values). But error returns and potentially debug code might like to
	// return them.
	cx.pastScratch[cx.groupIndex] = &cx.Scratch
	pass, err := eval(cx.txn.Lsig.Logic, &cx)

	if err != nil {
		err = cx.evalError(err)
	}

	return pass, &cx, err
}

// EvalSignature evaluates the logicsig of the ith transaction in params.
// A program passes successfully if it finishes with one int element on the stack that is non-zero.
func EvalSignature(gi int, params *EvalParams) (bool, error) {
	pass, _, err := EvalSignatureFull(gi, params)
	return pass, err
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
			err = panicError{x, errstr}
			cx.EvalParams.log().Errorf("recovered panic in Eval: %v", err)
		}
	}()

	// 16 is chosen to avoid growth for small programs, and so that repeated
	// doublings lead to a number just a bit above 1000, the max stack height.
	cx.Stack = make([]stackValue, 0, 16)
	cx.txn.EvalDelta.GlobalDelta = basics.StateDelta{}
	cx.txn.EvalDelta.LocalDeltas = make(map[uint64]basics.StateDelta)

	// We get the error here, but defer reporting so that the Tracer can be
	// called with an basically initialized cx.
	verr := cx.begin(program)

	if cx.Tracer != nil {
		cx.Tracer.BeforeProgram(cx)

		defer func() {
			x := recover()
			tracerErr := err
			if x != nil {
				// A panic error occurred during the eval loop. Report it now.
				tracerErr = fmt.Errorf("panic in TEAL Eval: %v", x)
				cx.Tracer.AfterOpcode(cx, tracerErr)
			}

			// Ensure we update the tracer before exiting
			cx.Tracer.AfterProgram(cx, pass, tracerErr)

			if x != nil {
				// Panic again to trigger higher-level recovery and error reporting
				panic(x)
			}
		}()
	}

	if (cx.EvalParams.Proto == nil) || (cx.EvalParams.Proto.LogicSigVersion == 0) {
		return false, errLogicSigNotSupported
	}
	if cx.txn.Lsig.Args != nil {
		if len(cx.txn.Lsig.Args) > transactions.EvalMaxArgs {
			return false, errTooManyArgs
		}
		for _, arg := range cx.txn.Lsig.Args {
			if len(arg) > transactions.MaxLogicSigArgSize {
				return false, errLogicSigArgTooLarge
			}
		}
	}
	if verr != nil {
		return false, verr
	}

	for (err == nil) && (cx.pc < len(cx.program)) {
		if cx.Tracer != nil {
			cx.Tracer.BeforeOpcode(cx)
		}

		err = cx.step()

		if cx.Tracer != nil {
			cx.Tracer.AfterOpcode(cx, err)
		}
	}
	if err != nil {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "%3d %s\n", cx.pc, err)
		}

		return false, err
	}
	if len(cx.Stack) != 1 {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "end stack:\n")
			for i, sv := range cx.Stack {
				fmt.Fprintf(cx.Trace, "[%d] %s\n", i, sv)
			}
		}
		return false, fmt.Errorf("stack len is %d instead of 1", len(cx.Stack))
	}
	if cx.Stack[0].Bytes != nil {
		return false, errors.New("stack finished with bytes not int")
	}

	return cx.Stack[0].Uint != 0, nil
}

// CheckContract should be faster than EvalContract.  It can perform
// static checks and reject programs that are invalid. Prior to v4,
// these static checks include a cost estimate that must be low enough
// (controlled by params.Proto).
func CheckContract(program []byte, gi int, params *EvalParams) error {
	return check(program, gi, params, ModeApp)
}

// CheckSignature should be faster than EvalSignature.  It can perform static
// checks and reject programs that are invalid. Prior to v4, these static checks
// include a cost estimate that must be low enough (controlled by params.Proto).
func CheckSignature(gi int, params *EvalParams) error {
	return check(params.TxnGroup[gi].Lsig.Logic, gi, params, ModeSig)
}

func check(program []byte, gi int, params *EvalParams, mode RunMode) (err error) {
	defer func() {
		if x := recover(); x != nil {
			buf := make([]byte, 16*1024)
			stlen := runtime.Stack(buf, false)
			errstr := string(buf[:stlen])
			if params.Trace != nil {
				errstr += params.Trace.String()
			}
			err = panicError{x, errstr}
			params.log().Errorf("recovered panic in Check: %s", err)
		}
	}()
	if (params.Proto == nil) || (params.Proto.LogicSigVersion == 0) {
		return errLogicSigNotSupported
	}

	var cx EvalContext
	cx.EvalParams = params
	cx.runMode = mode
	cx.branchTargets = make([]bool, len(program)+1) // teal v2 allowed jumping to the end of the prog
	cx.instructionStarts = make([]bool, len(program)+1)
	cx.txn = &params.TxnGroup[gi]

	if err := cx.begin(program); err != nil {
		return err
	}

	maxCost := cx.remainingBudget()
	staticCost := 0
	for cx.pc < len(cx.program) {
		prevpc := cx.pc
		stepCost, err := cx.checkStep()
		if err != nil {
			return fmt.Errorf("pc=%3d %w", cx.pc, err)
		}
		staticCost += stepCost
		if cx.version < backBranchEnabledVersion && staticCost > maxCost {
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

func (cx *EvalContext) begin(program []byte) error {
	cx.program = program

	version, vlen, err := transactions.ProgramVersion(program)
	if err != nil {
		return err
	}
	if version > LogicVersion {
		return fmt.Errorf("program version %d greater than max supported version %d", version, LogicVersion)
	}
	if version > cx.Proto.LogicSigVersion {
		return fmt.Errorf("program version %d greater than protocol supported version %d", version, cx.Proto.LogicSigVersion)
	}
	// We disallow pre-sharedResources programs with tx.Access for the same
	// reason that we don't allow resource sharing to happen for low version
	// programs. We don't want programs to have access to unexpected
	// things. Worse, we don't want to deal with the potentially new sitation
	// that a preSharing program could have access to an account and an ASA, but
	// not the corresponding holding. We DO allow logicsigs, because they can't
	// access state anyway.
	if version < sharedResourcesVersion && cx.runMode == ModeApp && len(cx.txn.Txn.Access) > 0 {
		return fmt.Errorf("pre-sharedResources program cannot be invoked with tx.Access")
	}

	cx.version = version
	cx.pc = vlen

	if cx.version < cx.EvalParams.minAvmVersion {
		return fmt.Errorf("program version must be >= %d for this transaction group, but have version %d",
			cx.minAvmVersion, cx.version)
	}
	return nil
}

func opCompat(expected, got avmType) bool {
	if expected == avmAny {
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

func boolToSV(x bool) stackValue {
	return stackValue{Uint: boolToUint(x)}
}

// Cost return cost incurred so far
func (cx *EvalContext) Cost() int {
	return cx.cost
}

// AppID returns the ID of the currently executing app. For LogicSigs it returns 0.
func (cx *EvalContext) AppID() basics.AppIndex {
	return cx.appID
}

func (cx *EvalContext) remainingBudget() int {
	if cx.runMode == ModeSig {
		if cx.PooledLogicSigBudget != nil {
			return *cx.PooledLogicSigBudget
		}
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

	// this check also ensures versioning: v2 opcodes are not in opsByOpcode[1] array
	if spec.op == nil {
		return fmt.Errorf("%3d illegal opcode 0x%02x", cx.pc, opcode)
	}
	if (cx.runMode & spec.Modes) == 0 {
		return fmt.Errorf("%s not allowed in current mode", spec.Name)
	}

	// check args for stack underflow and types
	if len(cx.Stack) < len(spec.Arg.Types) {
		return fmt.Errorf("stack underflow in %s", spec.Name)
	}
	first := len(cx.Stack) - len(spec.Arg.Types)
	for i, argType := range spec.Arg.Types {
		if !opCompat(argType.AVMType, cx.Stack[first+i].avmType()) {
			return fmt.Errorf("%s arg %d wanted %s but got %s", spec.Name, i, argType, cx.Stack[first+i].typeName())
		}
	}

	deets := &spec.OpDetails
	if deets.Size != 0 && (cx.pc+deets.Size > len(cx.program)) {
		return fmt.Errorf("%3d %s program ends short of immediate values", cx.pc, spec.Name)
	}

	// It's something like a 5-10% overhead on our simplest instructions to make
	// the Cost() call without the FullCost.compute() short-circuit, even
	// though Cost() tries to exit fast. Use BenchmarkUintMath to test changes.
	opcost := deets.FullCost.compute(cx.Stack)
	if opcost <= 0 {
		opcost = deets.Cost(cx.program, cx.pc, cx.Stack)
		if opcost <= 0 {
			return fmt.Errorf("%3d %s returned 0 cost", cx.pc, spec.Name)
		}
	}

	if opcost > cx.remainingBudget() {
		return fmt.Errorf("pc=%3d dynamic cost budget exceeded, executing %s: local program cost was %d",
			cx.pc, spec.Name, cx.cost)
	}

	cx.cost += opcost
	// At most one of these pooled budgets will be non-nil, perhaps we could
	// collapse to one variable, but there are some complex callers trying to
	// set up big budgets for debugging runs that would have to be looked at.
	switch {
	case cx.PooledApplicationBudget != nil:
		*cx.PooledApplicationBudget -= opcost
	case cx.PooledLogicSigBudget != nil:
		*cx.PooledLogicSigBudget -= opcost
	}
	preheight := len(cx.Stack)
	err := spec.op(cx)

	if err == nil && !spec.trusted {
		postheight := len(cx.Stack)
		if postheight-preheight != len(spec.Return.Types)-len(spec.Arg.Types) && !spec.AlwaysExits() {
			return fmt.Errorf("%s changed stack height improperly %d != %d",
				spec.Name, postheight-preheight, len(spec.Return.Types)-len(spec.Arg.Types))
		}
		first = postheight - len(spec.Return.Types)
		for i, argType := range spec.Return.Types {
			stackType := cx.Stack[first+i].avmType()
			if !opCompat(argType.AVMType, stackType) {
				if spec.AlwaysExits() { // We test in the loop because it's the uncommon case.
					break
				}
				return fmt.Errorf("%s produced %s but intended %s", spec.Name, cx.Stack[first+i].typeName(), argType)
			}
			if stackType == avmBytes && len(cx.Stack[first+i].Bytes) > maxStringSize {
				return fmt.Errorf("%s produced a too big (%d) byte-array", spec.Name, len(cx.Stack[first+i].Bytes))
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
		if len(cx.Stack) == 0 {
			stackString = "<empty stack>"
		} else {
			num := max(len(spec.Return.Types), 1)
			// check for nil error here, because we might not return
			// values if we encounter an error in the opcode
			if err == nil {
				if len(cx.Stack) < num {
					return fmt.Errorf("stack underflow: expected %d, have %d", num, len(cx.Stack))
				}
				for i := 1; i <= num; i++ {
					stackString += fmt.Sprintf("(%s) ", cx.Stack[len(cx.Stack)-i])
				}
			}
		}
		fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, sourceLine, stackString)
	}

	if err != nil {
		return err
	}

	if len(cx.Stack) > maxStackDepth {
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

// blankStack is a boring stack provided to deets.Cost during checkStep. It is
// good enough to allow Cost() to not crash. It would be incorrect to provide
// this stack if there were linear cost opcodes before backBranchEnabledVersion,
// because the static cost would be wrong. But then again, a static cost model
// wouldn't work before backBranchEnabledVersion, so such an opcode is already
// unacceptable. TestLinearOpcodes ensures.
var blankStack = make([]stackValue, 5)

func (cx *EvalContext) checkStep() (int, error) {
	cx.instructionStarts[cx.pc] = true
	opcode := cx.program[cx.pc]
	spec := &opsByOpcode[cx.version][opcode]
	if spec.op == nil {
		return 0, fmt.Errorf("illegal opcode 0x%02x", opcode)
	}
	if (cx.runMode & spec.Modes) == 0 {
		return 0, fmt.Errorf("%s not allowed in current mode", spec.Name)
	}
	deets := spec.OpDetails
	if deets.Size != 0 && (cx.pc+deets.Size > len(cx.program)) {
		return 0, fmt.Errorf("%s program ends short of immediate values", spec.Name)
	}
	opcost := deets.Cost(cx.program, cx.pc, blankStack)
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
		if pc < len(cx.branchTargets) && cx.branchTargets[pc] {
			return 0, fmt.Errorf("branch target %d is not an aligned instruction", pc)
		}
	}
	return opcost, nil
}

func (cx *EvalContext) ensureStackCap(targetCap int) {
	if cap(cx.Stack) < targetCap {
		// Let's grow all at once, plus a little slack.
		newStack := make([]stackValue, len(cx.Stack), targetCap+4)
		copy(newStack, cx.Stack)
		cx.Stack = newStack
	}
}

func opErr(cx *EvalContext) error {
	return errors.New("err opcode executed")
}

func opReturn(cx *EvalContext) error {
	// Achieve the end condition:
	// Take the last element on the stack and make it the return value (only element on the stack)
	// Move the pc to the end of the program
	last := len(cx.Stack) - 1
	cx.Stack[0] = cx.Stack[last]
	cx.Stack = cx.Stack[:1]
	cx.nextpc = len(cx.program)
	return nil
}

func opAssert(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	if cx.Stack[last].Uint != 0 {
		cx.Stack = cx.Stack[:last]
		return nil
	}
	return fmt.Errorf("assert failed pc=%d", cx.pc)
}

func opSwap(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cx.Stack[last], cx.Stack[prev] = cx.Stack[prev], cx.Stack[last]
	return nil
}

func opSelect(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // condition on top
	prev := last - 1          // true is one down
	pprev := prev - 1         // false below that

	if cx.Stack[last].Uint != 0 {
		cx.Stack[pprev] = cx.Stack[prev]
	}
	cx.Stack = cx.Stack[:prev]
	return nil
}

func opPlus(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	sum, carry := bits.Add64(cx.Stack[prev].Uint, cx.Stack[last].Uint, 0)
	if carry > 0 {
		return errors.New("+ overflowed")
	}
	cx.Stack[prev].Uint = sum
	cx.Stack = cx.Stack[:last]
	return nil
}

func opAddw(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	sum, carry := bits.Add64(cx.Stack[prev].Uint, cx.Stack[last].Uint, 0)
	cx.Stack[prev].Uint = carry
	cx.Stack[last].Uint = sum
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
	loDen := len(cx.Stack) - 1
	hiDen := loDen - 1
	if cx.Stack[loDen].Uint == 0 && cx.Stack[hiDen].Uint == 0 {
		return errors.New("/ 0")
	}
	loNum := loDen - 2
	hiNum := loDen - 3
	hiQuo, loQuo, hiRem, loRem :=
		opDivModwImpl(cx.Stack[hiNum].Uint, cx.Stack[loNum].Uint, cx.Stack[hiDen].Uint, cx.Stack[loDen].Uint)
	cx.Stack[hiNum].Uint = hiQuo
	cx.Stack[loNum].Uint = loQuo
	cx.Stack[hiDen].Uint = hiRem
	cx.Stack[loDen].Uint = loRem
	return nil
}

func opMinus(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	if cx.Stack[last].Uint > cx.Stack[prev].Uint {
		return errors.New("- would result negative")
	}
	cx.Stack[prev].Uint -= cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opDiv(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	if cx.Stack[last].Uint == 0 {
		return errors.New("/ 0")
	}
	cx.Stack[prev].Uint /= cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opModulo(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	if cx.Stack[last].Uint == 0 {
		return errors.New("% 0")
	}
	cx.Stack[prev].Uint = cx.Stack[prev].Uint % cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opMul(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	high, low := bits.Mul64(cx.Stack[prev].Uint, cx.Stack[last].Uint)
	if high > 0 {
		return errors.New("* overflowed")
	}
	cx.Stack[prev].Uint = low
	cx.Stack = cx.Stack[:last]
	return nil
}

func opMulw(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	high, low := bits.Mul64(cx.Stack[prev].Uint, cx.Stack[last].Uint)
	cx.Stack[prev].Uint = high
	cx.Stack[last].Uint = low
	return nil
}

func opDivw(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	pprev := last - 2
	hi := cx.Stack[pprev].Uint
	lo := cx.Stack[prev].Uint
	y := cx.Stack[last].Uint
	// These two clauses catch what will cause panics in bits.Div64, so we get
	// nicer errors.
	if y == 0 {
		return errors.New("divw 0")
	}
	if y <= hi {
		return fmt.Errorf("divw overflow: %d <= %d", y, hi)
	}
	quo, _ := bits.Div64(hi, lo, y)
	cx.Stack = cx.Stack[:prev] // pop 2
	cx.Stack[pprev].Uint = quo
	return nil
}

func opLt(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cond := cx.Stack[prev].Uint < cx.Stack[last].Uint
	cx.Stack[prev] = boolToSV(cond)
	cx.Stack = cx.Stack[:last]
	return nil
}

// opSwap, opLt, and opNot always succeed (return nil). So error checking elided in Gt,Le,Ge

func opGt(cx *EvalContext) error {
	opSwap(cx) //nolint:errcheck // opSwap always succeeds
	return opLt(cx)
}

func opLe(cx *EvalContext) error {
	opGt(cx) //nolint:errcheck // opGt always succeeds
	return opNot(cx)
}

func opGe(cx *EvalContext) error {
	opLt(cx) //nolint:errcheck // opLt always succeeds
	return opNot(cx)
}

func opAnd(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cond := (cx.Stack[prev].Uint != 0) && (cx.Stack[last].Uint != 0)
	cx.Stack[prev] = boolToSV(cond)
	cx.Stack = cx.Stack[:last]
	return nil
}

func opOr(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cond := (cx.Stack[prev].Uint != 0) || (cx.Stack[last].Uint != 0)
	cx.Stack[prev] = boolToSV(cond)
	cx.Stack = cx.Stack[:last]
	return nil
}

func opEq(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	ta := cx.Stack[prev].avmType()
	tb := cx.Stack[last].avmType()
	if ta != tb {
		return fmt.Errorf("cannot compare (%s to %s)", cx.Stack[prev].typeName(), cx.Stack[last].typeName())
	}
	var cond bool
	if ta == avmBytes {
		cond = bytes.Equal(cx.Stack[prev].Bytes, cx.Stack[last].Bytes)
	} else {
		cond = cx.Stack[prev].Uint == cx.Stack[last].Uint
	}
	cx.Stack[prev] = boolToSV(cond)
	cx.Stack = cx.Stack[:last]
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
	last := len(cx.Stack) - 1
	cx.Stack[last] = boolToSV(cx.Stack[last].Uint == 0)
	return nil
}

func opLen(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	cx.Stack[last].Uint = uint64(len(cx.Stack[last].Bytes))
	cx.Stack[last].Bytes = nil
	return nil
}

func opItob(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, cx.Stack[last].Uint)
	// cx.stack[last].Uint is not cleared out as optimization
	// stackValue.avmType() checks Bytes field first
	cx.Stack[last].Bytes = ibytes
	return nil
}

func opBtoi(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	ibytes := cx.Stack[last].Bytes
	if len(ibytes) > 8 {
		return fmt.Errorf("btoi arg too long, got %d bytes", len(ibytes))
	}
	value := uint64(0)
	for _, b := range ibytes {
		value = value << 8
		value = value | (uint64(b) & 0x0ff)
	}
	cx.Stack[last].Uint = value
	cx.Stack[last].Bytes = nil
	return nil
}

func opBitOr(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cx.Stack[prev].Uint = cx.Stack[prev].Uint | cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opBitAnd(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cx.Stack[prev].Uint = cx.Stack[prev].Uint & cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opBitXor(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cx.Stack[prev].Uint = cx.Stack[prev].Uint ^ cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opBitNot(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	cx.Stack[last].Uint = cx.Stack[last].Uint ^ 0xffffffffffffffff
	return nil
}

func opShiftLeft(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	if cx.Stack[last].Uint > 63 {
		return fmt.Errorf("shl arg too big, (%d)", cx.Stack[last].Uint)
	}
	cx.Stack[prev].Uint = cx.Stack[prev].Uint << cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opShiftRight(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	if cx.Stack[last].Uint > 63 {
		return fmt.Errorf("shr arg too big, (%d)", cx.Stack[last].Uint)
	}
	cx.Stack[prev].Uint = cx.Stack[prev].Uint >> cx.Stack[last].Uint
	cx.Stack = cx.Stack[:last]
	return nil
}

func opSqrt(cx *EvalContext) error {
	/*
		It would not be safe to use math.Sqrt, because we would have to convert our
		u64 to an f64, but f64 cannot represent all u64s exactly.

		This algorithm comes from Jack W. Crenshaw's 1998 article in Embedded:
		http://www.embedded.com/electronics-blogs/programmer-s-toolbox/4219659/Integer-Square-Roots
	*/

	last := len(cx.Stack) - 1

	sq := cx.Stack[last].Uint
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
	cx.Stack[last].Uint = root >> 1
	return nil
}

func opBitLen(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	if cx.Stack[last].avmType() == avmUint64 {
		cx.Stack[last].Uint = uint64(bits.Len64(cx.Stack[last].Uint))
		return nil
	}
	length := len(cx.Stack[last].Bytes)
	idx := 0
	for i, b := range cx.Stack[last].Bytes {
		if b != 0 {
			idx = bits.Len8(b) + (8 * (length - i - 1))
			break
		}

	}
	cx.Stack[last].Bytes = nil
	cx.Stack[last].Uint = uint64(idx)
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
	last := len(cx.Stack) - 1
	prev := last - 1

	exp := cx.Stack[last].Uint
	base := cx.Stack[prev].Uint
	val, err := opExpImpl(base, exp)
	if err != nil {
		return err
	}
	cx.Stack[prev].Uint = val
	cx.Stack = cx.Stack[:last]
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
	last := len(cx.Stack) - 1
	prev := last - 1

	exp := cx.Stack[last].Uint
	base := cx.Stack[prev].Uint
	val, err := opExpwImpl(base, exp)
	if err != nil {
		return err
	}
	hi := new(big.Int).Rsh(val, 64).Uint64()
	lo := val.Uint64()

	cx.Stack[prev].Uint = hi
	cx.Stack[last].Uint = lo
	return nil
}

func opBytesBinOp(cx *EvalContext, result *big.Int, op func(x, y *big.Int) *big.Int) error {
	last := len(cx.Stack) - 1
	prev := last - 1

	if len(cx.Stack[last].Bytes) > maxByteMathSize || len(cx.Stack[prev].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	rhs := new(big.Int).SetBytes(cx.Stack[last].Bytes)
	lhs := new(big.Int).SetBytes(cx.Stack[prev].Bytes)
	op(lhs, rhs) // op's receiver has already been bound to result
	if result.Sign() < 0 {
		return errors.New("byte math would have negative result")
	}
	cx.Stack[prev].Bytes = result.Bytes()
	cx.Stack = cx.Stack[:last]
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
	last := len(cx.Stack) - 1

	if len(cx.Stack[last].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	val := new(big.Int).SetBytes(cx.Stack[last].Bytes)
	val.Sqrt(val)
	cx.Stack[last].Bytes = val.Bytes()
	return nil
}

func nonzero(b []byte) []byte {
	for i := range b {
		if b[i] != 0 {
			return b[i:]
		}
	}
	return nil
}

func opBytesLt(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1

	if len(cx.Stack[last].Bytes) > maxByteMathSize || len(cx.Stack[prev].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	rhs := nonzero(cx.Stack[last].Bytes)
	lhs := nonzero(cx.Stack[prev].Bytes)

	switch {
	case len(lhs) < len(rhs):
		cx.Stack[prev] = boolToSV(true)
	case len(lhs) > len(rhs):
		cx.Stack[prev] = boolToSV(false)
	default:
		cx.Stack[prev] = boolToSV(bytes.Compare(lhs, rhs) < 0)
	}

	cx.Stack = cx.Stack[:last]
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
	last := len(cx.Stack) - 1
	prev := last - 1

	if len(cx.Stack[last].Bytes) > maxByteMathSize || len(cx.Stack[prev].Bytes) > maxByteMathSize {
		return errors.New("math attempted on large byte-array")
	}

	rhs := nonzero(cx.Stack[last].Bytes)
	lhs := nonzero(cx.Stack[prev].Bytes)

	cx.Stack[prev] = boolToSV(bytes.Equal(lhs, rhs))
	cx.Stack = cx.Stack[:last]
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
	last := len(cx.Stack) - 1
	prev := last - 1

	llen := len(cx.Stack[last].Bytes)
	plen := len(cx.Stack[prev].Bytes)

	var fresh, other []byte
	if llen > plen {
		fresh, other = zpad(cx.Stack[prev].Bytes, llen), cx.Stack[last].Bytes
	} else {
		fresh, other = zpad(cx.Stack[last].Bytes, plen), cx.Stack[prev].Bytes
	}
	cx.Stack[prev].Bytes = fresh
	cx.Stack = cx.Stack[:last]
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
	last := len(cx.Stack) - 1

	fresh := make([]byte, len(cx.Stack[last].Bytes))
	for i, b := range cx.Stack[last].Bytes {
		fresh[i] = ^b
	}
	cx.Stack[last].Bytes = fresh
	return nil
}

func opBytesZero(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	length := cx.Stack[last].Uint
	if length > maxStringSize {
		return fmt.Errorf("bzero attempted to create a too large string")
	}
	cx.Stack[last].Bytes = make([]byte, length)
	return nil
}

func opIntConstBlock(cx *EvalContext) error {
	var err error
	cx.intc, cx.nextpc, err = parseIntImmArgs(cx.program, cx.pc+1)
	return err
}

func opIntConstN(cx *EvalContext, n byte) error {
	if int(n) >= len(cx.intc) {
		return fmt.Errorf("intc %d beyond %d constants", n, len(cx.intc))
	}
	cx.Stack = append(cx.Stack, stackValue{Uint: cx.intc[n]})
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
	cx.Stack = append(cx.Stack, sv)
	cx.nextpc = pos + bytesUsed
	return nil
}

func opPushInts(cx *EvalContext) error {
	intc, nextpc, err := parseIntImmArgs(cx.program, cx.pc+1)
	if err != nil {
		return err
	}
	finalLen := len(cx.Stack) + len(intc)
	cx.ensureStackCap(finalLen)
	for _, cint := range intc {
		sv := stackValue{Uint: cint}
		cx.Stack = append(cx.Stack, sv)
	}
	cx.nextpc = nextpc
	return nil
}

func opByteConstBlock(cx *EvalContext) error {
	var err error
	cx.bytec, cx.nextpc, err = parseByteImmArgs(cx.program, cx.pc+1)
	return err
}

func opByteConstN(cx *EvalContext, n uint) error {
	if n >= uint(len(cx.bytec)) {
		return fmt.Errorf("bytec %d beyond %d constants", n, len(cx.bytec))
	}
	cx.Stack = append(cx.Stack, stackValue{Bytes: cx.bytec[n]})
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
	cx.Stack = append(cx.Stack, sv)
	cx.nextpc = int(end)
	return nil
}

func opPushBytess(cx *EvalContext) error {
	cbytess, nextpc, err := parseByteImmArgs(cx.program, cx.pc+1)
	if err != nil {
		return err
	}
	finalLen := len(cx.Stack) + len(cbytess)
	cx.ensureStackCap(finalLen)
	for _, cbytes := range cbytess {
		sv := stackValue{Bytes: cbytes}
		cx.Stack = append(cx.Stack, sv)
	}
	cx.nextpc = nextpc
	return nil
}

func opArgN(cx *EvalContext, n uint64) error {
	if n >= uint64(len(cx.txn.Lsig.Args)) {
		return fmt.Errorf("cannot load arg[%d] of %d", n, len(cx.txn.Lsig.Args))
	}
	val := nilToEmpty(cx.txn.Lsig.Args[n])
	cx.Stack = append(cx.Stack, stackValue{Bytes: val})
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
	last := len(cx.Stack) - 1
	n := cx.Stack[last].Uint
	// Pop the index and push the result back on the stack.
	cx.Stack = cx.Stack[:last]
	return opArgN(cx, n)
}

func decodeBranchOffset(program []byte, pos int) int {
	// tricky casting to preserve signed value
	return int(int16(program[pos])<<8 | int16(program[pos+1]))
}

func branchTarget(cx *EvalContext) (int, error) {
	offset := decodeBranchOffset(cx.program, cx.pc+1)
	if offset < 0 && cx.version < backBranchEnabledVersion {
		return 0, fmt.Errorf("negative branch offset %x", offset)
	}
	target := cx.pc + 3 + offset
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

func switchTarget(cx *EvalContext, branchIdx uint64) (int, error) {
	if cx.pc+1 >= len(cx.program) {
		opcode := cx.program[cx.pc]
		spec := &opsByOpcode[cx.version][opcode]
		return 0, fmt.Errorf("bare %s opcode at end of program", spec.Name)
	}
	numOffsets := int(cx.program[cx.pc+1])

	end := cx.pc + 2          // end of opcode + number of offsets, beginning of offset list
	eoi := end + 2*numOffsets // end of instruction

	if eoi > len(cx.program) { // eoi will equal len(p) if switch is last instruction
		opcode := cx.program[cx.pc]
		spec := &opsByOpcode[cx.version][opcode]
		return 0, fmt.Errorf("%s opcode claims to extend beyond program", spec.Name)
	}

	offset := 0
	if branchIdx < uint64(numOffsets) {
		pos := end + int(2*branchIdx) // position of referenced offset: each offset is 2 bytes
		offset = decodeBranchOffset(cx.program, pos)
	}

	target := eoi + offset

	// branching to exactly the end of the program (target == len(cx.program)), the next pc after the last instruction,
	// is okay and ends normally
	if target > len(cx.program) || target < 0 {
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
		if ok := cx.instructionStarts[target]; !ok {
			return fmt.Errorf("back branch target %d is not an aligned instruction", target)
		}
	}
	cx.branchTargets[target] = true
	return nil
}

// checks switch or match is encoded properly (and calculates nextpc)
func checkSwitch(cx *EvalContext) error {
	if cx.pc+1 >= len(cx.program) {
		opcode := cx.program[cx.pc]
		spec := &opsByOpcode[cx.version][opcode]
		return fmt.Errorf("bare %s opcode at end of program", spec.Name)
	}
	numOffsets := int(cx.program[cx.pc+1])
	eoi := cx.pc + 2 + 2*numOffsets

	for branchIdx := 0; branchIdx < numOffsets; branchIdx++ {
		target, err := switchTarget(cx, uint64(branchIdx))
		if err != nil {
			return err
		}

		if target < eoi {
			// If a branch goes backwards, we should have already noted that an instruction began at that location.
			if ok := cx.instructionStarts[target]; !ok {
				return fmt.Errorf("back branch target %d is not an aligned instruction", target)
			}
		}
		cx.branchTargets[target] = true
	}

	// this opcode's size is dynamic so nextpc must be set here
	cx.nextpc = eoi
	return nil
}

func opBnz(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	cx.nextpc = cx.pc + 3
	isNonZero := cx.Stack[last].Uint != 0
	cx.Stack = cx.Stack[:last] // pop
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
	last := len(cx.Stack) - 1
	cx.nextpc = cx.pc + 3
	isZero := cx.Stack[last].Uint == 0
	cx.Stack = cx.Stack[:last] // pop
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

func opSwitch(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	branchIdx := cx.Stack[last].Uint

	cx.Stack = cx.Stack[:last]
	target, err := switchTarget(cx, branchIdx)
	if err != nil {
		return err
	}
	cx.nextpc = target
	return nil
}

func opMatch(cx *EvalContext) error {
	if cx.pc+1 >= len(cx.program) {
		return fmt.Errorf("bare match opcode at end of program")
	}
	n := int(cx.program[cx.pc+1])
	// stack contains the n sized match list and the single match value
	if n+1 > len(cx.Stack) {
		return fmt.Errorf("match expects %d stack args while stack only contains %d", n+1, len(cx.Stack))
	}

	last := len(cx.Stack) - 1
	matchVal := cx.Stack[last]
	cx.Stack = cx.Stack[:last]

	argBase := len(cx.Stack) - n
	matchList := cx.Stack[argBase:]
	cx.Stack = cx.Stack[:argBase]

	matchedIdx := n
	for i, stackArg := range matchList {
		if stackArg.avmType() != matchVal.avmType() {
			continue
		}

		if matchVal.avmType() == avmBytes && bytes.Equal(matchVal.Bytes, stackArg.Bytes) {
			matchedIdx = i
			break
		} else if matchVal.avmType() == avmUint64 && matchVal.Uint == stackArg.Uint {
			matchedIdx = i
			break
		}
	}

	target, err := switchTarget(cx, uint64(matchedIdx))
	if err != nil {
		return err
	}
	cx.nextpc = target
	return nil
}

const protoByte = 0x8a

func opCallSub(cx *EvalContext) error {
	cx.callstack = append(cx.callstack, frame{
		retpc:  cx.pc + 3, // retpc is pc _after_ the callsub
		height: len(cx.Stack),
	})
	err := opB(cx)

	/* We only set fromCallSub if we know we're jumping to a proto. In opProto,
	   we confirm we came directly from callsub by checking (and resetting) the
	   flag. This is really a little handshake between callsub and proto. Done
	   this way, we don't have to waste time clearing the fromCallsub flag in
	   every instruction, only in proto since we know we're going there next.
	*/

	if cx.nextpc < len(cx.program) && cx.program[cx.nextpc] == protoByte {
		cx.fromCallsub = true
	}
	return err
}

func opRetSub(cx *EvalContext) error {
	top := len(cx.callstack) - 1
	if top < 0 {
		return errors.New("retsub with empty callstack")
	}
	topFrame := cx.callstack[top]
	if topFrame.clear { // A `proto` was issued in the subroutine, so retsub cleans up.
		expect := topFrame.height + topFrame.returns
		if len(cx.Stack) < expect { // Check general error case first, only diffentiate when error is assured
			switch {
			case len(cx.Stack) < topFrame.height:
				return fmt.Errorf("retsub executed with stack below frame. Did you pop args?")
			case len(cx.Stack) == topFrame.height:
				return fmt.Errorf("retsub executed with no return values on stack. proto declared %d", topFrame.returns)
			default:
				return fmt.Errorf("retsub executed with %d return values on stack. proto declared %d",
					len(cx.Stack)-topFrame.height, topFrame.returns)
			}
		}
		argstart := topFrame.height - topFrame.args
		copy(cx.Stack[argstart:], cx.Stack[topFrame.height:expect])
		cx.Stack = cx.Stack[:argstart+topFrame.returns]
	}
	cx.callstack = cx.callstack[:top]
	cx.nextpc = topFrame.retpc
	return nil
}

func opPop(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	cx.Stack = cx.Stack[:last]
	return nil
}

func opDup(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	sv := cx.Stack[last]
	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opDup2(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	cx.Stack = append(cx.Stack, cx.Stack[prev:]...)
	return nil
}

func opDig(cx *EvalContext) error {
	depth := int(cx.program[cx.pc+1])
	idx := len(cx.Stack) - 1 - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand dig
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		return fmt.Errorf("dig %d with stack size = %d", depth, len(cx.Stack))
	}
	sv := cx.Stack[idx]
	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opCover(cx *EvalContext) error {
	depth := int(cx.program[cx.pc+1])
	topIdx := len(cx.Stack) - 1
	idx := topIdx - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand cover
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		return fmt.Errorf("cover %d with stack size = %d", depth, len(cx.Stack))
	}
	sv := cx.Stack[topIdx]
	copy(cx.Stack[idx+1:], cx.Stack[idx:])
	cx.Stack[idx] = sv
	return nil
}

func opUncover(cx *EvalContext) error {
	depth := int(cx.program[cx.pc+1])
	topIdx := len(cx.Stack) - 1
	idx := topIdx - depth
	// Need to check stack size explicitly here because checkArgs() doesn't understand uncover
	// so we can't expect our stack to be prechecked.
	if idx < 0 {
		return fmt.Errorf("uncover %d with stack size = %d", depth, len(cx.Stack))
	}

	sv := cx.Stack[idx]
	copy(cx.Stack[idx:], cx.Stack[idx+1:])
	cx.Stack[topIdx] = sv
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

	if fs.ftype.AVMType != sv.avmType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.avmType())
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

	if fs.ftype.AVMType != sv.avmType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.avmType())
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
	case AppVersion:
		sv.Uint = params.Version
	default:
		// The pseudo fields AppCreator and AppAddress are handled before this method
		return sv, fmt.Errorf("invalid app_params_get field %d", fs.field)
	}

	if fs.ftype.AVMType != sv.avmType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.avmType())
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
	return sv.ToTealValue(), err
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
		if cx.runMode == ModeSig {
			return sv, fmt.Errorf("txn[%s] not allowed in current mode", fs.field)
		}
		if cx.version < txnEffectsVersion && !inner {
			return sv, errors.New("Unable to obtain effects from top-level transactions")
		}
	}
	if inner {
		// Before we had inner apps, we did not allow these, since we had no inner groups.
		if cx.version < innerAppsEnabledVersion && (fs.field == GroupIndex || fs.field == TxID) {
			return sv, fmt.Errorf("illegal field for inner transaction %s", fs.field)
		}
	}

	txn := &stxn.SignedTxn.Txn
	switch fs.field {
	case Sender:
		sv.Bytes = txn.Sender[:]
	case Fee:
		sv.Uint = txn.Fee.Raw
	case FirstValid:
		sv.Uint = uint64(txn.FirstValid)
	case FirstValidTime:
		rnd, err := cx.availableRound(uint64(txn.FirstValid) - 1)
		if err != nil {
			return sv, err
		}
		hdr, err := cx.SigLedger.BlockHdr(rnd)
		if err != nil {
			return sv, err
		}
		if hdr.TimeStamp < 0 {
			return sv, fmt.Errorf("block(%d) timestamp %d < 0", txn.FirstValid-1, hdr.TimeStamp)
		}
		sv.Uint = uint64(hdr.TimeStamp)
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
	case RejectVersion:
		sv.Uint = uint64(txn.RejectVersion)

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
	case NumApprovalProgramPages:
		sv.Uint = uint64(basics.DivCeil(len(txn.ApprovalProgram), maxStringSize))
	case ApprovalProgramPages:
		pageCount := basics.DivCeil(len(txn.ApprovalProgram), maxStringSize)
		if arrayFieldIdx >= uint64(pageCount) {
			return sv, fmt.Errorf("invalid ApprovalProgramPages index %d", arrayFieldIdx)
		}
		first := arrayFieldIdx * maxStringSize
		last := min(first+maxStringSize, uint64(len(txn.ApprovalProgram)))
		sv.Bytes = txn.ApprovalProgram[first:last]
	case NumClearStateProgramPages:
		sv.Uint = uint64(basics.DivCeil(len(txn.ClearStateProgram), maxStringSize))
	case ClearStateProgramPages:
		pageCount := basics.DivCeil(len(txn.ClearStateProgram), maxStringSize)
		if arrayFieldIdx >= uint64(pageCount) {
			return sv, fmt.Errorf("invalid ClearStateProgramPages index %d", arrayFieldIdx)
		}
		first := arrayFieldIdx * maxStringSize
		last := min(first+maxStringSize, uint64(len(txn.ClearStateProgram)))
		sv.Bytes = txn.ClearStateProgram[first:last]
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

	if fs.ftype.AVMType != sv.avmType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.avmType())
	}
	return sv, nil
}

func (cx *EvalContext) fetchField(field TxnField, expectArray bool) (*txnFieldSpec, error) {
	fs, ok := txnFieldSpecByField(field)
	if !ok || fs.version > cx.version {
		return nil, fmt.Errorf("invalid txn field %s", field)
	}
	if expectArray != fs.array {
		if expectArray {
			return nil, fmt.Errorf("unsupported array field %s", field)
		}
		return nil, fmt.Errorf("invalid txn field %s", field)
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
			if cx.runMode == ModeSig {
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

	cx.Stack = append(cx.Stack, sv)
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

	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opTxnas(cx *EvalContext) error {
	last := len(cx.Stack) - 1

	gi := uint64(cx.groupIndex)
	field := TxnField(cx.program[cx.pc+1])
	ai := cx.Stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.Stack[last] = sv
	return nil
}

func opGtxn(cx *EvalContext) error {
	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, 0, false)
	if err != nil {
		return err
	}

	cx.Stack = append(cx.Stack, sv)
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

	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opGtxnas(cx *EvalContext) error {
	last := len(cx.Stack) - 1

	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])
	ai := cx.Stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.Stack[last] = sv
	return nil
}

func opGtxns(cx *EvalContext) error {
	last := len(cx.Stack) - 1

	gi := cx.Stack[last].Uint
	field := TxnField(cx.program[cx.pc+1])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, 0, false)
	if err != nil {
		return err
	}

	cx.Stack[last] = sv
	return nil
}

func opGtxnsa(cx *EvalContext) error {
	last := len(cx.Stack) - 1

	gi := cx.Stack[last].Uint
	field := TxnField(cx.program[cx.pc+1])
	ai := uint64(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.Stack[last] = sv
	return nil
}

func opGtxnsas(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1

	gi := cx.Stack[prev].Uint
	field := TxnField(cx.program[cx.pc+1])
	ai := cx.Stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.Stack[prev] = sv
	cx.Stack = cx.Stack[:last]
	return nil
}

func opItxn(cx *EvalContext) error {
	field := TxnField(cx.program[cx.pc+1])

	sv, err := cx.opTxnImpl(0, srcInner, field, 0, false)
	if err != nil {
		return err
	}
	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opItxna(cx *EvalContext) error {
	field := TxnField(cx.program[cx.pc+1])
	ai := uint64(cx.program[cx.pc+2])

	sv, err := cx.opTxnImpl(0, srcInner, field, ai, true)
	if err != nil {
		return err
	}

	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opItxnas(cx *EvalContext) error {
	last := len(cx.Stack) - 1

	field := TxnField(cx.program[cx.pc+1])
	ai := cx.Stack[last].Uint

	sv, err := cx.opTxnImpl(0, srcInner, field, ai, true)
	if err != nil {
		return err
	}

	cx.Stack[last] = sv
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

	cx.Stack = append(cx.Stack, sv)
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

	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opGitxnas(cx *EvalContext) error {
	last := len(cx.Stack) - 1

	gi := uint64(cx.program[cx.pc+1])
	field := TxnField(cx.program[cx.pc+2])
	ai := cx.Stack[last].Uint

	sv, err := cx.opTxnImpl(gi, srcInnerGroup, field, ai, true)
	if err != nil {
		return err
	}

	cx.Stack[last] = sv
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

	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opGaids(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	gi := cx.Stack[last].Uint

	sv, err := opGaidImpl(cx, gi, "gaids")
	if err != nil {
		return err
	}

	cx.Stack[last] = sv
	return nil
}

func (cx *EvalContext) getRound() uint64 {
	return uint64(cx.Ledger.Round())
}

func (cx *EvalContext) getLatestTimestamp() (uint64, error) {
	ts := cx.Ledger.PrevTimestamp()
	if ts < 0 {
		return 0, fmt.Errorf("latest timestamp %d < 0", ts)
	}
	return uint64(ts), nil
}

// GetApplicationAddress memoizes app.Address() across a tx group's evaluation
func (ep *EvalParams) GetApplicationAddress(app basics.AppIndex) basics.Address {
	/* Do not instantiate the cache here, that would mask a programming error.
	   The cache must be instantiated at EvalParams construction time, so that
	   proper sharing with inner EvalParams can work. */
	appAddr, ok := ep.appAddrCache[app]
	if !ok {
		appAddr = app.Address()
		ep.appAddrCache[app] = appAddr
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
		addr := cx.GetApplicationAddress(cx.appID)
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
			addr := cx.caller.GetApplicationAddress(cx.caller.appID)
			sv.Bytes = addr[:]
		} else {
			sv.Bytes = zeroAddress[:]
		}
	case AssetCreateMinBalance:
		sv.Uint = cx.Proto.MinBalance
	case AssetOptInMinBalance:
		sv.Uint = cx.Proto.MinBalance
	case GenesisHash:
		gh := cx.SigLedger.GenesisHash()
		sv.Bytes = gh[:]
	case PayoutsEnabled:
		sv.Uint = boolToUint(cx.Proto.Payouts.Enabled)
	case PayoutsGoOnlineFee:
		sv.Uint = cx.Proto.Payouts.GoOnlineFee
	case PayoutsPercent:
		sv.Uint = cx.Proto.Payouts.Percent
	case PayoutsMinBalance:
		sv.Uint = cx.Proto.Payouts.MinBalance
	case PayoutsMaxBalance:
		sv.Uint = cx.Proto.Payouts.MaxBalance
	default:
		return sv, fmt.Errorf("invalid global field %s", fs.field)
	}

	if err == nil && fs.ftype.AVMType != sv.avmType() {
		return sv, fmt.Errorf("%s expected field type is %s but got %s", fs.field, fs.ftype, sv.avmType())
	}

	return sv, err
}

func opGlobal(cx *EvalContext) error {
	globalField := GlobalField(cx.program[cx.pc+1])
	fs, ok := globalFieldSpecByField(globalField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid global field %s", globalField)
	}
	if (cx.runMode & fs.mode) == 0 {
		return fmt.Errorf("global[%s] not allowed in current mode", globalField)
	}

	sv, err := cx.globalFieldToValue(fs)
	if err != nil {
		return err
	}

	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opLoad(cx *EvalContext) error {
	n := cx.program[cx.pc+1]
	cx.Stack = append(cx.Stack, cx.Scratch[n])
	return nil
}

func opLoads(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	n := cx.Stack[last].Uint
	if n >= uint64(len(cx.Scratch)) {
		return fmt.Errorf("invalid Scratch index %d", n)
	}
	cx.Stack[last] = cx.Scratch[n]
	return nil
}

func opStore(cx *EvalContext) error {
	n := cx.program[cx.pc+1]
	last := len(cx.Stack) - 1
	cx.Scratch[n] = cx.Stack[last]
	cx.Stack = cx.Stack[:last]
	return nil
}

func opStores(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	n := cx.Stack[prev].Uint
	if n >= uint64(len(cx.Scratch)) {
		return fmt.Errorf("invalid Scratch index %d", n)
	}
	cx.Scratch[n] = cx.Stack[last]
	cx.Stack = cx.Stack[:prev]
	return nil
}

func opGloadImpl(cx *EvalContext, gi int, scratchIdx byte, opName string) (stackValue, error) {
	var none stackValue
	if gi >= len(cx.TxnGroup) {
		return none, fmt.Errorf("%s lookup TxnGroup[%d] but it only has %d", opName, gi, len(cx.TxnGroup))
	}
	if int(scratchIdx) >= len(cx.Scratch) {
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

	cx.Stack = append(cx.Stack, scratchValue)
	return nil
}

func opGloads(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	gi := cx.Stack[last].Uint
	if gi >= uint64(len(cx.TxnGroup)) {
		return fmt.Errorf("gloads lookup TxnGroup[%d] but it only has %d", gi, len(cx.TxnGroup))
	}
	scratchIdx := cx.program[cx.pc+1]
	scratchValue, err := opGloadImpl(cx, int(gi), scratchIdx, "gloads")
	if err != nil {
		return err
	}

	cx.Stack[last] = scratchValue
	return nil
}

func opGloadss(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1

	gi := cx.Stack[prev].Uint
	if gi >= uint64(len(cx.TxnGroup)) {
		return fmt.Errorf("gloadss lookup TxnGroup[%d] but it only has %d", gi, len(cx.TxnGroup))
	}
	scratchIdx := cx.Stack[last].Uint
	if scratchIdx >= 256 {
		return fmt.Errorf("gloadss scratch index >= 256 (%d)", scratchIdx)
	}
	scratchValue, err := opGloadImpl(cx, int(gi), byte(scratchIdx), "gloadss")
	if err != nil {
		return err
	}

	cx.Stack[prev] = scratchValue
	cx.Stack = cx.Stack[:last]
	return nil
}

func opConcat(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	a := cx.Stack[prev].Bytes
	b := cx.Stack[last].Bytes
	newlen := len(a) + len(b)
	newvalue := make([]byte, newlen)
	copy(newvalue, a)
	copy(newvalue[len(a):], b)
	cx.Stack[prev].Bytes = newvalue
	cx.Stack = cx.Stack[:last]
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
	last := len(cx.Stack) - 1
	start := cx.program[cx.pc+1]
	end := cx.program[cx.pc+2]
	bytes, err := substring(cx.Stack[last].Bytes, int(start), int(end))
	cx.Stack[last].Bytes = bytes
	return err
}

func opSubstring3(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // end
	prev := last - 1          // start
	pprev := prev - 1         // bytes
	start := cx.Stack[prev].Uint
	end := cx.Stack[last].Uint
	if start > math.MaxInt32 || end > math.MaxInt32 {
		return errors.New("substring range beyond length of string")
	}
	bytes, err := substring(cx.Stack[pprev].Bytes, int(start), int(end))
	cx.Stack[pprev].Bytes = bytes
	cx.Stack = cx.Stack[:prev]
	return err
}

func opGetBit(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	idx := cx.Stack[last].Uint
	target := cx.Stack[prev]

	var bit uint64
	if target.avmType() == avmUint64 {
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
	cx.Stack[prev].Uint = bit
	cx.Stack[prev].Bytes = nil
	cx.Stack = cx.Stack[:last]
	return nil
}

func opSetBit(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	pprev := prev - 1

	bit := cx.Stack[last].Uint
	idx := cx.Stack[prev].Uint
	target := cx.Stack[pprev]

	if bit > 1 {
		return errors.New("setbit value > 1")
	}

	if target.avmType() == avmUint64 {
		if idx > 63 {
			return errors.New("setbit index > 63 with Uint")
		}
		mask := uint64(1) << idx
		if bit == uint64(1) {
			cx.Stack[pprev].Uint |= mask // manipulate stack in place
		} else {
			cx.Stack[pprev].Uint &^= mask // manipulate stack in place
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
		cx.Stack[pprev].Bytes = scratch
	}
	cx.Stack = cx.Stack[:prev]
	return nil
}

func opGetByte(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1

	idx := cx.Stack[last].Uint
	target := cx.Stack[prev]

	if idx >= uint64(len(target.Bytes)) {
		return errors.New("getbyte index beyond array length")
	}
	cx.Stack[prev].Uint = uint64(target.Bytes[idx])
	cx.Stack[prev].Bytes = nil
	cx.Stack = cx.Stack[:last]
	return nil
}

func opSetByte(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	pprev := prev - 1
	if cx.Stack[last].Uint > 255 {
		return errors.New("setbyte value > 255")
	}
	if cx.Stack[prev].Uint >= uint64(len(cx.Stack[pprev].Bytes)) {
		return errors.New("setbyte index beyond array length")
	}
	// Copy to avoid modifying shared slice
	cx.Stack[pprev].Bytes = append([]byte(nil), cx.Stack[pprev].Bytes...)
	cx.Stack[pprev].Bytes[cx.Stack[prev].Uint] = byte(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:prev]
	return nil
}

func extractCarefully(x []byte, start, length uint64) ([]byte, error) {
	if start > uint64(len(x)) {
		return nil, fmt.Errorf("extraction start %d is beyond length: %d", start, len(x))
	}
	end := start + length
	if end < start {
		return nil, fmt.Errorf("extraction end exceeds uint64")
	}
	if end > uint64(len(x)) {
		return nil, fmt.Errorf("extraction end %d is beyond length: %d", end, len(x))
	}
	return x[start:end], nil
}

func opExtract(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	start := uint64(cx.program[cx.pc+1])
	length := uint64(cx.program[cx.pc+2])
	// Shortcut: if length is 0, take bytes from start index to the end
	if length == 0 {
		// If length has wrapped, it's because start > len(), so extractCarefully will report
		length = uint64(len(cx.Stack[last].Bytes) - int(start))
	}
	bytes, err := extractCarefully(cx.Stack[last].Bytes, start, length)
	cx.Stack[last].Bytes = bytes
	return err
}

func opExtract3(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // length
	prev := last - 1          // start
	pprev := prev - 1         // bytes

	start := cx.Stack[prev].Uint
	length := cx.Stack[last].Uint
	bytes, err := extractCarefully(cx.Stack[pprev].Bytes, start, length)
	cx.Stack[pprev].Bytes = bytes
	cx.Stack = cx.Stack[:prev]
	return err
}

// replaceCarefully is used to make a NEW byteslice copy of original, with
// replacement written over the bytes starting at start.
func replaceCarefully(original []byte, replacement []byte, start uint64) ([]byte, error) {
	if start > uint64(len(original)) {
		return nil, fmt.Errorf("replacement start %d beyond length: %d", start, len(original))
	}
	end := start + uint64(len(replacement))
	if end < start { // impossible because it is sum of two avm value (or box) lengths
		return nil, fmt.Errorf("replacement end exceeds uint64")
	}

	if end > uint64(len(original)) {
		return nil, fmt.Errorf("replacement end %d beyond original length: %d", end, len(original))
	}

	// Do NOT use the append trick to make a copy here.
	// append(nil, []byte{}...) would return a nil, which means "not a bytearray" to AVM.
	clone := make([]byte, len(original))
	copy(clone[:start], original)
	copy(clone[start:end], replacement)
	copy(clone[end:], original[end:])
	return clone, nil
}

func opReplace2(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // replacement
	prev := last - 1          // original

	replacement := cx.Stack[last].Bytes
	start := uint64(cx.program[cx.pc+1])
	original := cx.Stack[prev].Bytes

	bytes, err := replaceCarefully(original, replacement, start)
	if err != nil {
		return err
	}
	cx.Stack[prev].Bytes = bytes
	cx.Stack = cx.Stack[:last]
	return err
}

func opReplace3(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // replacement
	prev := last - 1          // start
	pprev := prev - 1         // original

	replacement := cx.Stack[last].Bytes
	start := cx.Stack[prev].Uint
	original := cx.Stack[pprev].Bytes

	bytes, err := replaceCarefully(original, replacement, start)
	if err != nil {
		return err
	}
	cx.Stack[pprev].Bytes = bytes
	cx.Stack = cx.Stack[:prev]
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

func opExtractNBytes(cx *EvalContext, n uint64) error {
	last := len(cx.Stack) - 1 // start
	prev := last - 1          // bytes
	start := cx.Stack[last].Uint
	bytes, err := extractCarefully(cx.Stack[prev].Bytes, start, n) // extract n bytes
	if err != nil {
		return err
	}
	cx.Stack[prev].Uint = convertBytesToInt(bytes)
	cx.Stack[prev].Bytes = nil
	cx.Stack = cx.Stack[:last]
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

// assignAccount is used to convert a stackValue into a 32-byte account value,
// enforcing any "availability" restrictions in force.
func (cx *EvalContext) assignAccount(sv stackValue) (basics.Address, error) {
	addr, err := sv.address()
	if err != nil {
		return basics.Address{}, err
	}

	if cx.availableAccount(addr) {
		return addr, nil
	}
	return basics.Address{}, fmt.Errorf("unavailable Account %s", addr)
}

// accountReference yields the address and Accounts offset designated by a
// stackValue. If the stackValue is the app account, an account of an app in
// created.apps, an account of an app in foreignApps, or an account made
// available by another txn, and it is not in the Accounts array, then
// len(Accounts) + 1 is returned as the index. This would let us catch the
// mistake if the index is used for set/del. If the txn somehow "psychically"
// predicted the address, and therefore it IS in txn.Accounts, then happy day,
// we can set/del it. Return the proper index.

// Starting in v9, apps can change local state on these accounts by adding the
// address to EvalDelta.SharedAccounts and indexing it there. But at this level,
// we still report the "failure" to find an index with `len(Accounts)+1` That
// value allows mutableAccountReference to decide whether to report an error or
// not, based on version.

func (cx *EvalContext) accountReference(account stackValue) (basics.Address, uint64, error) {
	addr, idx, err := cx.resolveAccount(account)
	if err != nil {
		return addr, 0, err
	}

	if idx >= 0 {
		return addr, uint64(idx), err
	}
	// negative idx tells us we can't return the idx into
	// txn.Accounts, but the account might still be available (because it was
	// created earlier in the group, or because of group sharing)
	ok := cx.availableAccount(addr)
	if !ok {
		return addr, 0, fmt.Errorf("unavailable Account %s", addr)
	}
	// available, but not in txn.Accounts. Return 1 higher to signal.
	return addr, uint64(len(cx.txn.Txn.Accounts) + 1), nil
}

// resolveAccount determines the Address and slot indicated by a stackValue, so
// it is either confirming that the bytes is indeed 32 bytes (and trying to find
// it in txn.Accounts or returning -1), or it is performing the lookup of the
// integer arg in txn.Accounts.
func (cx *EvalContext) resolveAccount(account stackValue) (basics.Address, int, error) {
	if account.avmType() == avmUint64 {
		addr, err := cx.txn.Txn.AddressByIndex(account.Uint, cx.txn.Txn.Sender)
		return addr, int(account.Uint), err
	}
	addr, err := account.address()
	if err != nil {
		return addr, -1, err
	}

	idx, err := cx.txn.Txn.IndexByAddress(addr, cx.txn.Txn.Sender)
	if err != nil {
		// we don't want to convey `err`, because the supplied `account` does
		// seem to be an address, but we can't give a valid index.
		return addr, -1, nil //nolint:nilerr // see above comment
	}
	return addr, int(idx), nil
}

func (cx *EvalContext) availableAccount(addr basics.Address) bool {
	_, err := cx.txn.Txn.IndexByAddress(addr, cx.txn.Txn.Sender)
	if err == nil {
		return true
	}

	// Allow an address for an app that was created in group
	if cx.version >= createdResourcesVersion {
		for appID := range cx.available.createdApps {
			if addr == cx.GetApplicationAddress(appID) {
				return true
			}
		}
	}

	// or some other txn mentioned it
	if cx.version >= sharedResourcesVersion {
		if _, ok := cx.available.sharedAccounts[addr]; ok {
			return true
		}
	}

	// Allow an address for an app that was provided in the foreign apps array.
	if cx.version >= appAddressAvailableVersion {
		for _, appID := range cx.txn.Txn.ForeignApps {
			foreignAddress := cx.GetApplicationAddress(appID)
			if addr == foreignAddress {
				return true
			}
		}
	}

	if cx.GetApplicationAddress(cx.appID) == addr {
		return true
	}

	if cx.UnnamedResources != nil && cx.UnnamedResources.AvailableAccount(addr) {
		return true
	}

	return false
}

func (cx *EvalContext) mutableAccountReference(account stackValue) (basics.Address, uint64, error) {
	addr, accountIdx, err := cx.accountReference(account)
	if err != nil {
		return basics.Address{}, 0, err
	}
	if accountIdx > uint64(len(cx.txn.Txn.Accounts)) {
		// There was no error, but accountReference has signaled that accountIdx
		// is not for mutable ops (because it can't encode it in EvalDelta)
		if cx.version < sharedResourcesVersion {
			return basics.Address{}, 0, fmt.Errorf("invalid Account reference for mutation %s", addr)
		}
		// fall through, which means that starting in v9, the accountIdx
		// returned can be > len(tx.Accounts). It will end up getting passed to
		// GetLocal, which can record that index in order to produce old-style
		// EDS. But those EDs are only made in old consenus versions - at that
		// point v9 did not exist, so no backward incompatible change occurs.
	}
	return addr, accountIdx, err
}

func opBalance(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // account (index or actual address)

	addr, _, err := cx.accountReference(cx.Stack[last])
	if err != nil {
		return err
	}

	account, err := cx.Ledger.AccountData(addr)
	if err != nil {
		return err
	}

	cx.Stack[last].Bytes = nil
	cx.Stack[last].Uint = account.MicroAlgos.Raw
	return nil
}

func opMinBalance(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // account (index or actual address)

	addr, _, err := cx.accountReference(cx.Stack[last])
	if err != nil {
		return err
	}

	account, err := cx.Ledger.AccountData(addr)
	if err != nil {
		return err
	}

	cx.Stack[last].Bytes = nil
	cx.Stack[last].Uint = account.MinBalance(cx.Proto).Raw
	return nil
}

func opAppOptedIn(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // app
	prev := last - 1          // account

	addr, app, _, err := cx.localsReference(cx.Stack[prev], cx.Stack[last].Uint)
	if err != nil {
		return err
	}

	optedIn, err := cx.Ledger.OptedIn(addr, app)
	if err != nil {
		return err
	}

	cx.Stack[prev] = boolToSV(optedIn)
	cx.Stack = cx.Stack[:last]
	return nil
}

func opAppLocalGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // state key
	prev := last - 1          // account

	key := cx.Stack[last].Bytes

	result, _, err := opAppLocalGetImpl(cx, 0, key, cx.Stack[prev])
	if err != nil {
		return err
	}

	cx.Stack[prev] = result
	cx.Stack = cx.Stack[:last]
	return nil
}

func opAppLocalGetEx(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // state key
	prev := last - 1          // app id
	pprev := prev - 1         // account

	key := cx.Stack[last].Bytes
	appID := cx.Stack[prev].Uint

	result, ok, err := opAppLocalGetImpl(cx, appID, key, cx.Stack[pprev])
	if err != nil {
		return err
	}

	cx.Stack[pprev] = result
	cx.Stack[prev] = boolToSV(ok)
	cx.Stack = cx.Stack[:last]
	return nil
}

func opAppLocalGetImpl(cx *EvalContext, appID uint64, key []byte, acct stackValue) (result stackValue, ok bool, err error) {
	addr, app, accountIdx, err := cx.localsReference(acct, appID)
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
	app, err := cx.appReference(appIndex, true)
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
	last := len(cx.Stack) - 1 // state key

	key := cx.Stack[last].Bytes

	result, _, err := opAppGetGlobalStateImpl(cx, 0, key)
	if err != nil {
		return err
	}

	cx.Stack[last] = result
	return nil
}

func opAppGlobalGetEx(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // state key
	prev := last - 1          // app

	key := cx.Stack[last].Bytes

	result, ok, err := opAppGetGlobalStateImpl(cx, cx.Stack[prev].Uint, key)
	if err != nil {
		return err
	}

	cx.Stack[prev] = result
	cx.Stack[last] = boolToSV(ok)
	return nil
}

// ensureLocalDelta is used to get accountIdx that is usable in the LocalDeltas
// of the EvalDelta. The input accountIdx is "tentative" - if it's longer than
// txn.Accounts, then we may need to add the address into SharedAccounts, and
// index into it.
func (cx *EvalContext) ensureLocalDelta(accountIdx uint64, addr basics.Address) uint64 {
	if accountIdx > uint64(len(cx.txn.Txn.Accounts)) {
		// the returned accountIdx was just a signal that the account was
		// not in txn, so we look in SharedAccounts, allocating space if needed.
		found := false
		for i, shared := range cx.txn.EvalDelta.SharedAccts {
			if shared == addr {
				found = true
				accountIdx = uint64(len(cx.txn.Txn.Accounts) + 1 + i)
			}
		}
		if !found {
			cx.txn.EvalDelta.SharedAccts = append(cx.txn.EvalDelta.SharedAccts, addr)
			accountIdx = uint64(len(cx.txn.Txn.Accounts) + len(cx.txn.EvalDelta.SharedAccts))
		}
	}
	if _, ok := cx.txn.EvalDelta.LocalDeltas[accountIdx]; !ok {
		cx.txn.EvalDelta.LocalDeltas[accountIdx] = basics.StateDelta{}
	}
	return accountIdx
}

func opAppLocalPut(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // value
	prev := last - 1          // state key
	pprev := prev - 1         // account

	sv := cx.Stack[last]
	key := string(cx.Stack[prev].Bytes)

	// Enforce key lengths. Now, this is the same as enforced by ledger, but if
	// it ever to change in proto, we would need to isolate changes to different
	// program versions. (so a v6 app could not see a bigger key, for example)
	if len(key) > cx.Proto.MaxAppKeyLen {
		return fmt.Errorf("key too long: length was %d, maximum is %d", len(key), cx.Proto.MaxAppKeyLen)
	}

	addr, accountIdx, err := cx.mutableAccountReference(cx.Stack[pprev])
	if err != nil {
		return err
	}

	// The version check is overkill, but makes very clear we don't change old
	// programs. The test here is to ensure that we didn't get access to the
	// address from another txn, but don't have access to the local state.
	if cx.version >= sharedResourcesVersion && !cx.allowsLocals(addr, cx.appID) {
		return fmt.Errorf("unavailable Local State %d+%s", cx.appID, addr)
	}

	// if writing the same value, don't record in EvalDelta, matching ledger
	// behavior with previous BuildEvalDelta mechanism
	etv, ok, err := cx.Ledger.GetLocal(addr, cx.appID, key, accountIdx)
	if err != nil {
		return err
	}

	tv := sv.ToTealValue()
	if !ok || tv != etv {
		accountIdx = cx.ensureLocalDelta(accountIdx, addr)
		cx.txn.EvalDelta.LocalDeltas[accountIdx][key] = tv.ToValueDelta()
	}

	// Enforce maximum value length (also enforced by ledger)
	if tv.Type == basics.TealBytesType {
		if len(tv.Bytes) > cx.Proto.MaxAppBytesValueLen {
			return fmt.Errorf("value too long for key 0x%x: length was %d", key, len(tv.Bytes))
		}
		if sum := len(key) + len(tv.Bytes); sum > cx.Proto.MaxAppSumKeyValueLens {
			return fmt.Errorf("key/value total too long for key 0x%x: sum was %d", key, sum)
		}
	}

	err = cx.Ledger.SetLocal(addr, cx.appID, key, tv, accountIdx)
	if err != nil {
		return err
	}

	cx.Stack = cx.Stack[:pprev]
	return nil
}

func opAppGlobalPut(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // value
	prev := last - 1          // state key

	sv := cx.Stack[last]
	key := string(cx.Stack[prev].Bytes)

	// Enforce maximum key length. Currently this is the same as enforced by
	// ledger. If it were ever to change in proto, we would need to isolate
	// changes to different program versions. (so a v6 app could not see a
	// bigger key, for example)
	if len(key) > cx.Proto.MaxAppKeyLen {
		return fmt.Errorf("key too long: length was %d, maximum is %d", len(key), cx.Proto.MaxAppKeyLen)
	}

	// if writing the same value, don't record in EvalDelta, matching ledger
	// behavior with previous BuildEvalDelta mechanism
	etv, ok, err := cx.Ledger.GetGlobal(cx.appID, key)
	if err != nil {
		return err
	}
	tv := sv.ToTealValue()
	if !ok || tv != etv {
		cx.txn.EvalDelta.GlobalDelta[key] = tv.ToValueDelta()
	}

	// Enforce maximum value length (also enforced by ledger)
	if tv.Type == basics.TealBytesType {
		if len(tv.Bytes) > cx.Proto.MaxAppBytesValueLen {
			return fmt.Errorf("value too long for key 0x%x: length was %d", key, len(tv.Bytes))
		}
		if sum := len(key) + len(tv.Bytes); sum > cx.Proto.MaxAppSumKeyValueLens {
			return fmt.Errorf("key/value total too long for key 0x%x: sum was %d", key, sum)
		}
	}

	err = cx.Ledger.SetGlobal(cx.appID, key, tv)
	if err != nil {
		return err
	}

	cx.Stack = cx.Stack[:prev]
	return nil
}

func opAppLocalDel(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // key
	prev := last - 1          // account

	key := string(cx.Stack[last].Bytes)

	addr, accountIdx, err := cx.mutableAccountReference(cx.Stack[prev])
	if err != nil {
		return err
	}

	// The version check is overkill, but makes very clear we don't change old
	// programs. The test here is to ensure that we didn't get access to the
	// address from another txn, but don't have access to the local state.
	if cx.version >= sharedResourcesVersion && !cx.allowsLocals(addr, cx.appID) {
		return fmt.Errorf("unavailable Local State %d+%s", cx.appID, addr)
	}

	// if deleting a non-existent value, don't record in EvalDelta, matching
	// ledger behavior with previous BuildEvalDelta mechanism
	if _, ok, getErr := cx.Ledger.GetLocal(addr, cx.appID, key, accountIdx); ok {
		if getErr != nil {
			return getErr
		}
		accountIdx = cx.ensureLocalDelta(accountIdx, addr)
		cx.txn.EvalDelta.LocalDeltas[accountIdx][key] = basics.ValueDelta{
			Action: basics.DeleteAction,
		}
	}

	err = cx.Ledger.DelLocal(addr, cx.appID, key, accountIdx)
	if err != nil {
		return err
	}

	cx.Stack = cx.Stack[:prev]
	return nil
}

func opAppGlobalDel(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // key

	key := string(cx.Stack[last].Bytes)

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
	cx.Stack = cx.Stack[:last]
	return nil
}

// We have a difficult naming problem here. Some opcodes allow (and used to
// require) ASAs and Apps to to be referenced by their "index" in an app call
// txn's foreign-apps or foreign-assets arrays.  That was a small integer, no
// more than 2 or so, and was often called an "index".  But it was not a
// basics.AssetIndex or basics.ApplicationIndex.

func (cx *EvalContext) appReference(ref uint64, foreign bool) (aid basics.AppIndex, err error) {
	if cx.version >= directRefEnabledVersion {
		return cx.resolveApp(ref)
	}

	// resolveApp is already similarly protected (and must be, since it is
	// called independently)
	if cx.Proto.AppForbidLowResources {
		defer func() {
			if aid <= lastForbiddenResource && err == nil {
				err = fmt.Errorf("low App lookup %d", aid)
			}
		}()
	}
	// Old rules, pre directRefEnabledVersion, when a ref has to be a slot for
	// some opcodes, and had to be an ID for others.
	if ref == 0 { // Even back when expected to be a real ID, ref = 0 was current app
		return cx.appID, nil
	}
	if foreign {
		// In old versions, a foreign reference must be an index in ForeignApps or 0
		if ref <= uint64(len(cx.txn.Txn.ForeignApps)) {
			return cx.txn.Txn.ForeignApps[ref-1], nil
		}
		return 0, fmt.Errorf("%d is not a valid foreign app slot", ref)
	}
	// Otherwise it's direct
	return basics.AppIndex(ref), nil
}

// resolveApp figures out what App an integer is referring to, considering 0 as
// current app first, then uses the integer as is if it is an availableApp, then
// tries to perform a slot lookup.
func (cx *EvalContext) resolveApp(ref uint64) (aid basics.AppIndex, err error) {
	if cx.Proto.AppForbidLowResources {
		defer func() {
			if aid <= lastForbiddenResource && err == nil {
				err = fmt.Errorf("low App lookup %d", aid)
			}
		}()
	}

	if ref == 0 || ref == uint64(cx.appID) {
		return cx.appID, nil
	}
	aid = basics.AppIndex(ref)
	if cx.availableApp(aid) {
		return aid, nil
	}

	// Allow use of indexes, but this comes last so that clear advice can be
	// given to anyone who cares about semantics in the first few rounds of
	// a new network - don't use indexes for references, use the App ID
	if ref <= uint64(len(cx.txn.Txn.ForeignApps)) {
		return cx.txn.Txn.ForeignApps[ref-1], nil
	}
	if ref > 0 && ref-1 < uint64(len(cx.txn.Txn.Access)) && cx.txn.Txn.Access[ref-1].App != 0 {
		return cx.txn.Txn.Access[ref-1].App, nil
	}

	return 0, fmt.Errorf("unavailable App %d", ref)
}

// localsReference has the main job of resolving the account (as bytes or u64)
// and the App, taking access rules into account.  It has the funny side job of
// also reporting which "slot" the address appears in, if it is in txn.Accounts
// (or is the Sender, which yields 0). But it only needs to do this funny side
// job in certain old versions that need the slot index while doing a lookup.
func (cx *EvalContext) localsReference(account stackValue, ref uint64) (basics.Address, basics.AppIndex, uint64, error) {
	if cx.version >= sharedResourcesVersion {
		addr, _, err := cx.resolveAccount(account)
		if err != nil {
			return basics.Address{}, 0, 0, err
		}
		aid, err := cx.resolveApp(ref)
		if err == nil {
			if cx.allowsLocals(addr, aid) {
				return addr, aid, 0, nil // >v9 caller doesn't care about slot
			}
		}

		// Do an extra check to give a better error, which also allows the
		// UnnamedResources code to notice that the account must be available as
		// well.

		acctOK := cx.availableAccount(addr)
		localsErr := fmt.Errorf("unavailable Local State %d+%s", aid, addr)

		switch {
		case err != nil && acctOK:
			// do nothing, err contains an App specific problem
		case err == nil && acctOK:
			// although both are available, the LOCALS are not
			err = localsErr
		case err != nil && !acctOK:
			err = fmt.Errorf("unavailable Account %s, %w, %w", addr, err, localsErr)
		case err == nil && !acctOK:
			err = fmt.Errorf("unavailable Account %s, %w", addr, localsErr)
		}

		return basics.Address{}, 0, 0, err
	}

	// Pre group resource sharing, the rule is just that account and app are
	// each available.
	addr, addrIdx, err := cx.accountReference(account)
	if err != nil {
		return basics.Address{}, 0, 0, err
	}
	app, err := cx.appReference(ref, false)
	if err != nil {
		return basics.Address{}, 0, 0, err
	}

	return addr, app, addrIdx, nil
}

func (cx *EvalContext) assetReference(ref uint64, foreign bool) (aid basics.AssetIndex, err error) {
	if cx.version >= directRefEnabledVersion {
		return cx.resolveAsset(ref)
	}

	// resolveAsset is already similarly protected (and must be, since it is
	// called independently)
	if cx.Proto.AppForbidLowResources {
		defer func() {
			if aid <= lastForbiddenResource && err == nil {
				err = fmt.Errorf("low Asset lookup %d", aid)
			}
		}()
	}
	// Old rules, pre directRefEnabledVersion, when a ref has to be a slot for
	// some opcodes, and had to be an ID for others.
	if foreign {
		// In old versions, a foreign reference must be an index in ForeignAssets
		if ref < uint64(len(cx.txn.Txn.ForeignAssets)) {
			return cx.txn.Txn.ForeignAssets[ref], nil
		}
		return 0, fmt.Errorf("%d is not a valid foreign asset slot", ref)
	}
	// Otherwise it's direct
	return basics.AssetIndex(ref), nil
}

const lastForbiddenResource = 255

// resolveAsset figures out what Asset an integer is referring to, checking if
// the integer is an availableAsset, then tries to perform a slot lookup.
func (cx *EvalContext) resolveAsset(ref uint64) (aid basics.AssetIndex, err error) {
	if cx.Proto.AppForbidLowResources {
		defer func() {
			if aid <= lastForbiddenResource && err == nil {
				err = fmt.Errorf("low Asset lookup %d", aid)
			}
		}()
	}
	aid = basics.AssetIndex(ref)
	if cx.availableAsset(aid) {
		return aid, nil
	}

	// Allow use of indexes, but this comes last so that clear advice can be
	// given to anyone who cares about semantics in the first few rounds of
	// a new network - don't use indexes for references, use the Asset ID
	if ref < uint64(len(cx.txn.Txn.ForeignAssets)) {
		return cx.txn.Txn.ForeignAssets[ref], nil
	}
	if ref > 0 && ref-1 < uint64(len(cx.txn.Txn.Access)) && cx.txn.Txn.Access[ref-1].Asset != 0 {
		return cx.txn.Txn.Access[ref-1].Asset, nil
	}
	return 0, fmt.Errorf("unavailable Asset %d", ref)
}

func (cx *EvalContext) holdingReference(account stackValue, ref uint64) (basics.Address, basics.AssetIndex, error) {
	if cx.version >= sharedResourcesVersion {
		addr, _, err := cx.resolveAccount(account)
		if err != nil {
			return basics.Address{}, 0, err
		}
		aid, err := cx.resolveAsset(ref)
		if err == nil {
			if cx.allowsHolding(addr, aid) {
				return addr, aid, nil
			}
		}

		// Do an extra check to give a better error. The asset is definitely
		// available. If the addr is too, then the trouble is they must have
		// come from different transactions, and the HOLDING is the problem.

		acctOK := cx.availableAccount(addr)
		switch {
		case err != nil && acctOK:
			// do nothing, err contains an Asset specific problem
		case err == nil && acctOK:
			// although both are available, the HOLDING is not
			err = fmt.Errorf("unavailable Holding %d+%s", aid, addr)
		case err != nil && !acctOK:
			err = fmt.Errorf("unavailable Account %s, %w", addr, err)
		case err == nil && !acctOK:
			err = fmt.Errorf("unavailable Account %s", addr)
		}
		return basics.Address{}, 0, err
	}

	// Pre group resource sharing, the rule is just that account and asset are
	// each available.
	addr, _, err := cx.accountReference(account)
	if err != nil {
		return basics.Address{}, 0, err
	}
	asset, err := cx.assetReference(ref, false)
	if err != nil {
		return basics.Address{}, 0, err
	}
	return addr, asset, nil
}

func opAssetHoldingGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // asset
	prev := last - 1          // account

	holdingField := AssetHoldingField(cx.program[cx.pc+1])
	fs, ok := assetHoldingFieldSpecByField(holdingField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid asset_holding_get field %d", holdingField)
	}

	addr, asset, err := cx.holdingReference(cx.Stack[prev], cx.Stack[last].Uint)
	if err != nil {
		return err
	}

	var exist uint64 = 0
	var value stackValue
	if holding, err := cx.Ledger.AssetHolding(addr, asset); err == nil {
		// the holding exists, read the value
		exist = 1
		value, err = cx.assetHoldingToValue(&holding, fs)
		if err != nil {
			return err
		}
	}

	cx.Stack[prev] = value
	cx.Stack[last].Uint = exist
	return nil
}

func opAssetParamsGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // asset

	paramField := AssetParamsField(cx.program[cx.pc+1])
	fs, ok := assetParamsFieldSpecByField(paramField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid asset_params_get field %d", paramField)
	}

	asset, err := cx.assetReference(cx.Stack[last].Uint, true)
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

	cx.Stack[last] = value
	cx.Stack = append(cx.Stack, stackValue{Uint: exist})
	return nil
}

func opAppParamsGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // app

	paramField := AppParamsField(cx.program[cx.pc+1])
	fs, ok := appParamsFieldSpecByField(paramField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid app_params_get field %d", paramField)
	}

	app, err := cx.appReference(cx.Stack[last].Uint, true)
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

	cx.Stack[last] = value
	cx.Stack = append(cx.Stack, stackValue{Uint: exist})
	return nil
}

func opAcctParamsGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // acct

	addr, _, err := cx.accountReference(cx.Stack[last])
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

	var value stackValue

	switch fs.field {
	case AcctBalance:
		value.Uint = account.MicroAlgos.Raw
	case AcctMinBalance:
		value.Uint = account.MinBalance(cx.Proto).Raw
	case AcctAuthAddr:
		value.Bytes = account.AuthAddr[:]

	case AcctTotalNumUint:
		value.Uint = uint64(account.TotalAppSchema.NumUint)
	case AcctTotalNumByteSlice:
		value.Uint = uint64(account.TotalAppSchema.NumByteSlice)
	case AcctTotalExtraAppPages:
		value.Uint = uint64(account.TotalExtraAppPages)

	case AcctTotalAppsCreated:
		value.Uint = account.TotalAppParams
	case AcctTotalAppsOptedIn:
		value.Uint = account.TotalAppLocalStates
	case AcctTotalAssetsCreated:
		value.Uint = account.TotalAssetParams
	case AcctTotalAssets:
		value.Uint = account.TotalAssets
	case AcctTotalBoxes:
		value.Uint = account.TotalBoxes
	case AcctTotalBoxBytes:
		value.Uint = account.TotalBoxBytes
	case AcctIncentiveEligible:
		value = boolToSV(account.IncentiveEligible)
	case AcctLastHeartbeat:
		value.Uint = uint64(account.LastHeartbeat)
	case AcctLastProposed:
		value.Uint = uint64(account.LastProposed)
	default:
		return fmt.Errorf("invalid account field %s", fs.field)
	}
	cx.Stack[last] = value
	cx.Stack = append(cx.Stack, boolToSV(account.MicroAlgos.Raw > 0))
	return nil
}

func opVoterParamsGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // acct
	addr, _, err := cx.accountReference(cx.Stack[last])
	if err != nil {
		return err
	}

	paramField := VoterParamsField(cx.program[cx.pc+1])
	fs, ok := voterParamsFieldSpecByField(paramField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid voter_params_get field %d", paramField)
	}

	account, err := cx.Ledger.AgreementData(addr)
	if err != nil {
		return err
	}

	var value stackValue

	switch fs.field {
	case VoterBalance:
		value.Uint = account.MicroAlgosWithRewards.Raw
	case VoterIncentiveEligible:
		value = boolToSV(account.IncentiveEligible)
	default:
		return fmt.Errorf("invalid voter field %s", fs.field)
	}
	cx.Stack[last] = value
	cx.Stack = append(cx.Stack, boolToSV(account.MicroAlgosWithRewards.Raw > 0))
	return nil
}

func opOnlineStake(cx *EvalContext) error {
	amount, err := cx.Ledger.OnlineStake()
	if err != nil {
		return err
	}
	cx.Stack = append(cx.Stack, stackValue{Uint: amount.Raw})
	return nil
}

func opLog(cx *EvalContext) error {
	last := len(cx.Stack) - 1

	if len(cx.txn.EvalDelta.Logs) >= cx.MaxLogCalls {
		return fmt.Errorf("too many log calls in program. up to %d is allowed", cx.MaxLogCalls)
	}
	log := cx.Stack[last]
	cx.logSize += len(log.Bytes)
	if cx.logSize > cx.MaxLogSize {
		return fmt.Errorf("program logs too large. %d bytes >  %d bytes limit", cx.logSize, cx.MaxLogSize)
	}
	cx.txn.EvalDelta.Logs = append(cx.txn.EvalDelta.Logs, string(log.Bytes))
	cx.Stack = cx.Stack[:last]
	return nil
}

func authorizedSender(cx *EvalContext, addr basics.Address) error {
	authorizer, err := cx.Ledger.Authorizer(addr)
	if err != nil {
		return err
	}
	if cx.GetApplicationAddress(cx.appID) != authorizer {
		return fmt.Errorf("app %d (addr %s) unauthorized %s", cx.appID, cx.GetApplicationAddress(cx.appID), authorizer)
	}
	return nil
}

// addInnerTxn appends a fresh SignedTxn to subtxns, populated with reasonable
// defaults.
func addInnerTxn(cx *EvalContext) error {
	addr := cx.GetApplicationAddress(cx.appID)

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

func opItxnBegin(cx *EvalContext) error {
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

// assignAsset is used to convert a stackValue to a uint64 assetIndex, reporting
// any errors due to availability rules or type checking.
func (cx *EvalContext) assignAsset(sv stackValue) (basics.AssetIndex, error) {
	uint, err := sv.uint()
	if err != nil {
		return 0, err
	}
	aid := basics.AssetIndex(uint)

	if cx.availableAsset(aid) {
		return aid, nil
	}

	return 0, fmt.Errorf("unavailable Asset %d during assignment %v", aid, cx.available)
}

// availableAsset determines whether an asset is "available". Before
// sharedResourcesVersion, an asset had to be available for asset param
// lookups, asset holding lookups, and asset id assignments to inner
// transactions. After sharedResourcesVersion, the distinction must be more fine
// grained. It must be available for asset param lookups, or use in an asset
// transaction (axfer,acfg,afrz), but not for holding lookups or assignments to
// an inner static array.
func (cx *EvalContext) availableAsset(aid basics.AssetIndex) bool {
	// Check if aid is in an access array
	if slices.ContainsFunc(cx.txn.Txn.Access, func(rr transactions.ResourceRef) bool { return rr.Asset == aid }) {
		return true
	}
	if slices.Contains(cx.txn.Txn.ForeignAssets, aid) {
		return true
	}
	// or was created in group
	if cx.version >= createdResourcesVersion {
		if _, ok := cx.available.createdAsas[aid]; ok {
			return true
		}
	}

	// or some other txn mentioned it
	if cx.version >= sharedResourcesVersion {
		if _, ok := cx.available.sharedAsas[aid]; ok {
			return true
		}
	}

	if aid > lastForbiddenResource && cx.UnnamedResources != nil && cx.UnnamedResources.AvailableAsset(aid) {
		return true
	}

	return false
}

// assignApp is used to convert a stackValue to a uint64 appIndex, reporting
// any errors due to availability rules or type checking.
func (cx *EvalContext) assignApp(sv stackValue) (basics.AppIndex, error) {
	uint, err := sv.uint()
	if err != nil {
		return 0, err
	}
	aid := basics.AppIndex(uint)

	if cx.availableApp(aid) {
		return aid, nil
	}

	return 0, fmt.Errorf("unavailable App %d", aid)
}

func (cx *EvalContext) availableApp(aid basics.AppIndex) bool {
	// Check if aid is in an access array
	if slices.ContainsFunc(cx.txn.Txn.Access, func(rr transactions.ResourceRef) bool { return rr.App == aid }) {
		return true
	}
	if slices.Contains(cx.txn.Txn.ForeignApps, aid) {
		return true
	}
	// or was created in group
	if cx.version >= createdResourcesVersion {
		if _, ok := cx.available.createdApps[aid]; ok {
			return true
		}
	}
	// Or, it can be the current app
	if cx.appID == aid {
		return true
	}

	// or some other txn mentioned it
	if cx.version >= sharedResourcesVersion {
		if _, ok := cx.available.sharedApps[aid]; ok {
			return true
		}
	}

	if aid > lastForbiddenResource && cx.UnnamedResources != nil && cx.UnnamedResources.AvailableApp(aid) {
		return true
	}

	return false
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
		txn.Sender, err = cx.assignAccount(sv)
	case Fee:
		txn.Fee.Raw, err = sv.uint()
	// FirstValid, LastValid unsettable: little motivation (maybe a app call
	// wants to inspect?)  If we set, make sure they are legal, both for current
	// round, and separation by MaxLifetime (check lifetime in submit, not here)
	case Note:
		if len(sv.Bytes) > cx.Proto.MaxTxnNoteBytes {
			return fmt.Errorf("%s may not exceed %d bytes", fs.field, cx.Proto.MaxTxnNoteBytes)
		}
		txn.Note = slices.Clone(sv.Bytes)
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
		txn.Receiver, err = cx.assignAccount(sv)
	case Amount:
		txn.Amount.Raw, err = sv.uint()
	case CloseRemainderTo:
		txn.CloseRemainderTo, err = cx.assignAccount(sv)
	// AssetTransfer
	case XferAsset:
		txn.XferAsset, err = cx.assignAsset(sv)
	case AssetAmount:
		txn.AssetAmount, err = sv.uint()
	case AssetSender:
		txn.AssetSender, err = cx.assignAccount(sv)
	case AssetReceiver:
		txn.AssetReceiver, err = cx.assignAccount(sv)
	case AssetCloseTo:
		txn.AssetCloseTo, err = cx.assignAccount(sv)
	// AssetConfig
	case ConfigAsset:
		txn.ConfigAsset, err = cx.assignAsset(sv)
	case ConfigAssetTotal:
		txn.AssetParams.Total, err = sv.uint()
	case ConfigAssetDecimals:
		var decimals uint64
		decimals, err = sv.uintMaxed(uint64(cx.Proto.MaxAssetDecimals))
		txn.AssetParams.Decimals = uint32(decimals)
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
		txn.FreezeAsset, err = cx.assignAsset(sv)
	case FreezeAssetAccount:
		txn.FreezeAccount, err = cx.assignAccount(sv)
	case FreezeAssetFrozen:
		txn.AssetFrozen, err = sv.bool()

	// ApplicationCall
	case ApplicationID:
		txn.ApplicationID, err = cx.assignApp(sv)
	case OnCompletion:
		var onc uint64
		onc, err = sv.uintMaxed(uint64(transactions.DeleteApplicationOC))
		txn.OnCompletion = transactions.OnCompletion(onc)
	case RejectVersion:
		txn.RejectVersion, err = sv.uint()
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
		txn.ApplicationArgs = append(txn.ApplicationArgs, slices.Clone(sv.Bytes))
	case Accounts:
		var new basics.Address
		new, err = cx.assignAccount(sv)
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
		txn.ApprovalProgram = slices.Clone(sv.Bytes)
	case ClearStateProgram:
		maxPossible := cx.Proto.MaxAppProgramLen * (1 + cx.Proto.MaxExtraAppProgramPages)
		if len(sv.Bytes) > maxPossible {
			return fmt.Errorf("%s may not exceed %d bytes", fs.field, maxPossible)
		}
		txn.ClearStateProgram = slices.Clone(sv.Bytes)
	case ApprovalProgramPages:
		maxPossible := cx.Proto.MaxAppProgramLen * (1 + cx.Proto.MaxExtraAppProgramPages)
		txn.ApprovalProgram = append(txn.ApprovalProgram, sv.Bytes...)
		if len(txn.ApprovalProgram) > maxPossible {
			return fmt.Errorf("%s may not exceed %d bytes", fs.field, maxPossible)
		}
	case ClearStateProgramPages:
		maxPossible := cx.Proto.MaxAppProgramLen * (1 + cx.Proto.MaxExtraAppProgramPages)
		txn.ClearStateProgram = append(txn.ClearStateProgram, sv.Bytes...)
		if len(txn.ClearStateProgram) > maxPossible {
			return fmt.Errorf("%s may not exceed %d bytes", fs.field, maxPossible)
		}
	case Assets:
		var new basics.AssetIndex
		new, err = cx.assignAsset(sv)
		if err != nil {
			return err
		}
		if len(txn.ForeignAssets) >= cx.Proto.MaxAppTxnForeignAssets {
			return errors.New("too many foreign assets")
		}
		txn.ForeignAssets = append(txn.ForeignAssets, new)
	case Applications:
		var new basics.AppIndex
		new, err = cx.assignApp(sv)
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
	last := len(cx.Stack) - 1
	field := TxnField(cx.program[cx.pc+1])
	fs, ok := txnFieldSpecByField(field)
	if !ok || fs.itxVersion == 0 || fs.itxVersion > cx.version {
		return fmt.Errorf("invalid itxn_field %s", field)
	}
	sv := cx.Stack[last]
	err := cx.stackIntoTxnField(sv, &fs, &cx.subtxns[itx].Txn)
	cx.Stack = cx.Stack[:last] // pop
	return err
}

func opItxnSubmit(cx *EvalContext) (err error) {
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
		// The goal is to follow the same invariants used by the transaction
		// pool. Namely that any transaction that makes it to Perform (which is
		// equivalent to eval.applyTransaction) is WellFormed. Authorization
		// must be checked later, to take state changes from earlier in the
		// group into account.

		// Recall that WellFormed does not care about individual
		// transaction fees because of fee pooling. Checked above.
		txnErr := cx.subtxns[itx].Txn.WellFormed(*cx.Specials, *cx.Proto)
		if txnErr != nil {
			return txnErr
		}

		var calledVersion uint64

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
				app, _, paramsErr := cx.Ledger.AppParams(cx.subtxns[itx].Txn.ApplicationID)
				if paramsErr != nil {
					return paramsErr
				}
				program = app.ApprovalProgram
				if cx.subtxns[itx].Txn.OnCompletion == transactions.ClearStateOC {
					program = app.ClearStateProgram
				}
			}

			// Can't call old versions in inner apps.
			calledVersion, _, err = transactions.ProgramVersion(program)
			if err != nil {
				return err
			}
			if calledVersion < cx.Proto.MinInnerApplVersion {
				return fmt.Errorf("inner app call with version v%d < v%d",
					calledVersion, cx.Proto.MinInnerApplVersion)
			}

			// Don't allow opt-in if the CSP is not runnable as an inner.
			// This test can only fail for v4 and v5 approval programs,
			// since v6 requires synchronized versions.
			if cx.subtxns[itx].Txn.OnCompletion == transactions.OptInOC {
				csp := cx.subtxns[itx].Txn.ClearStateProgram
				if cx.subtxns[itx].Txn.ApplicationID != 0 {
					app, _, paramsErr := cx.Ledger.AppParams(cx.subtxns[itx].Txn.ApplicationID)
					if paramsErr != nil {
						return paramsErr
					}
					csp = app.ClearStateProgram
				}
				csv, _, verErr := transactions.ProgramVersion(csp)
				if verErr != nil {
					return verErr
				}
				if csv < cx.Proto.MinInnerApplVersion {
					return fmt.Errorf("inner app call opt-in with CSP v%d < v%d",
						csv, cx.Proto.MinInnerApplVersion)
				}
			}
		}

		// Starting in v9, it's possible for apps to create transactions that
		// should not be allowed to run, because they require access to
		// resources that the caller does not have.  This can only happen for
		// Holdings and Local States. The caller might have access to the
		// account and the asa or app, but not the holding or locals, because
		// the caller gained access to the two top resources by group sharing
		// from two different transactions.
		err = cx.allows(&cx.subtxns[itx].Txn, calledVersion)
		if err != nil {
			return err
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

	if ep.Tracer != nil {
		ep.Tracer.BeforeTxnGroup(ep)
		// Ensure we update the tracer before exiting
		defer func() {
			ep.Tracer.AfterTxnGroup(ep, nil, err)
		}()
	}

	for i := range ep.TxnGroup {
		if ep.Tracer != nil {
			ep.Tracer.BeforeTxn(ep, i)
		}

		err := authorizedSender(cx, ep.TxnGroup[i].Txn.Sender)
		if err != nil {
			return err
		}
		err = cx.Ledger.Perform(i, ep)

		if ep.Tracer != nil {
			ep.Tracer.AfterTxn(ep, i, ep.TxnGroup[i].ApplyData, err)
		}

		if err != nil {
			return basics.Wrap(err, fmt.Sprintf("inner tx %d failed: %s", i, err.Error()), "inner")
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

// availableRound checks to see if the requested round, `r`, is allowed to be
// accessed. If it is, it's returned as a basics.Round. It is named by analogy
// to the availableAsset and  availableApp helpers.
func (cx *EvalContext) availableRound(r uint64) (basics.Round, error) {
	firstAvail := cx.txn.Txn.LastValid - basics.Round(cx.Proto.MaxTxnLife) - 1
	if firstAvail > cx.txn.Txn.LastValid || firstAvail == 0 { // early in chain's life
		firstAvail = 1
	}
	lastAvail := cx.txn.Txn.FirstValid - 1
	if lastAvail > cx.txn.Txn.FirstValid { // txn had a 0 in FirstValid
		lastAvail = 0 // So nothing will be available
	}
	round := basics.Round(r)
	if firstAvail > round || round > lastAvail {
		return 0, fmt.Errorf("round %d is not available. It's outside [%d-%d]", r, firstAvail, lastAvail)
	}
	return round, nil
}

func opBlock(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // round
	round, err := cx.availableRound(cx.Stack[last].Uint)
	if err != nil {
		return err
	}
	f := BlockField(cx.program[cx.pc+1])
	fs, ok := blockFieldSpecByField(f)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid block field %s", f)
	}

	hdr, err := cx.SigLedger.BlockHdr(round)
	if err != nil {
		return err
	}

	switch fs.field {
	case BlkSeed:
		cx.Stack[last].Bytes = hdr.Seed[:]
	case BlkTimestamp:
		if hdr.TimeStamp < 0 {
			return fmt.Errorf("block(%d) timestamp %d < 0", round, hdr.TimeStamp)
		}
		cx.Stack[last] = stackValue{Uint: uint64(hdr.TimeStamp)}

	case BlkBranch:
		cx.Stack[last].Bytes = hdr.Branch[:]
	case BlkFeeSink:
		cx.Stack[last].Bytes = hdr.FeeSink[:]
	case BlkProtocol:
		cx.Stack[last].Bytes = []byte(hdr.CurrentProtocol)
	case BlkTxnCounter:
		cx.Stack[last] = stackValue{Uint: hdr.TxnCounter}

	case BlkProposer:
		cx.Stack[last].Bytes = hdr.Proposer[:]
	case BlkFeesCollected:
		cx.Stack[last] = stackValue{Uint: hdr.FeesCollected.Raw}
	case BlkBonus:
		cx.Stack[last] = stackValue{Uint: hdr.Bonus.Raw}
	case BlkProposerPayout:
		cx.Stack[last] = stackValue{Uint: hdr.ProposerPayout.Raw}

	case BlkBranch512:
		cx.Stack[last].Bytes = hdr.Branch512[:]
	case BlkSha512_256TxnCommitment:
		cx.Stack[last].Bytes = hdr.NativeSha512_256Commitment[:]
	case BlkSha256TxnCommitment:
		cx.Stack[last].Bytes = hdr.Sha256Commitment[:]
	case BlkSha512TxnCommitment:
		cx.Stack[last].Bytes = hdr.Sha512Commitment[:]

	default:
		return fmt.Errorf("invalid block field %s", fs.field)
	}
	return nil
}

// pcDetails return PC and disassembled instructions at PC up to 2 opcodes back
func (cx *EvalContext) pcDetails() (pc int, dis string) {
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
	return cx.pc, strings.ReplaceAll(strings.TrimSuffix(dis, "\n"), "\n", "; ")
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
	last := len(cx.Stack) - 1
	encodingField := Base64Encoding(cx.program[cx.pc+1])
	fs, ok := base64EncodingSpecByField(encodingField)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid base64_decode encoding %s", encodingField)
	}

	encoding := base64.URLEncoding
	if encodingField == StdEncoding {
		encoding = base64.StdEncoding
	}
	encoded := cx.Stack[last].Bytes
	if !base64padded(encoded) {
		encoding = encoding.WithPadding(base64.NoPadding)
	}
	bytes, err := base64Decode(encoded, encoding.Strict())
	if err != nil {
		return err
	}
	cx.Stack[last].Bytes = bytes
	return nil
}

func isPrimitiveJSON(jsonText []byte) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(jsonText))
	t, err := dec.Token()
	if err != nil {
		return false, err
	}
	t, ok := t.(json.Delim)
	if !ok || t.(json.Delim).String() != "{" {
		return true, nil
	}
	return false, nil
}

func parseJSON(jsonText []byte) (map[string]json.RawMessage, error) {
	// parse JSON with Algorand's standard JSON library
	var parsed map[interface{}]json.RawMessage
	err := protocol.DecodeJSON(jsonText, &parsed)

	if err != nil {
		// if the error was caused by duplicate keys
		if strings.Contains(err.Error(), "cannot decode into a non-pointer value") {
			return nil, fmt.Errorf("invalid json text, duplicate keys not allowed")
		}

		// if the error was caused by non-json object
		if strings.Contains(err.Error(), "read map - expect char '{' but got char") {
			return nil, fmt.Errorf("invalid json text, only json object is allowed")
		}

		return nil, fmt.Errorf("invalid json text")
	}

	// check whether any keys are not strings
	stringMap := make(map[string]json.RawMessage)
	for k, v := range parsed {
		key, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("invalid json text")
		}
		stringMap[key] = v
	}

	return stringMap, nil
}

func opJSONRef(cx *EvalContext) error {
	// get json key
	last := len(cx.Stack) - 1
	key := string(cx.Stack[last].Bytes)
	cx.Stack = cx.Stack[:last] // pop

	expectedType := JSONRefType(cx.program[cx.pc+1])
	fs, ok := jsonRefSpecByField(expectedType)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid json_ref type %s", expectedType)
	}

	// parse json text
	last = len(cx.Stack) - 1
	parsed, err := parseJSON(cx.Stack[last].Bytes)
	if err != nil {
		return fmt.Errorf("error while parsing JSON text, %v", err)
	}

	// get value from json
	var stval stackValue
	_, ok = parsed[key]
	if !ok {
		// if the key is not found, first check whether the JSON text is the null value
		// by checking whether it is a primitive JSON value. Any other primitive
		// (or array) would have thrown an error previously during `parseJSON`.
		isPrimitive, err := isPrimitiveJSON(cx.Stack[last].Bytes)
		if err == nil && isPrimitive {
			err = fmt.Errorf("invalid json text, only json object is allowed")
		}
		if err != nil {
			return fmt.Errorf("error while parsing JSON text, %v", err)
		}

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
	cx.Stack[last] = stval
	return nil
}
