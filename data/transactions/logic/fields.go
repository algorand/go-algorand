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
	"fmt"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

//go:generate stringer -type=TxnField,GlobalField,AssetParamsField,AppParamsField,AcctParamsField,AssetHoldingField,OnCompletionConstType,EcdsaCurve,EcGroup,MimcConfig,Base64Encoding,JSONRefType,VoterParamsField,VrfStandard,BlockField -output=fields_string.go

// FieldSpec unifies the various specs for assembly, disassembly, and doc generation.
type FieldSpec interface {
	Field() byte
	Type() StackType
	OpVersion() uint64
	Note() string
	Version() uint64
}

// fieldSpecMap is something that yields a FieldSpec, given a name for the field
type fieldSpecMap interface {
	get(name string) (FieldSpec, bool)
}

// FieldGroup binds all the info for a field (names, int value, spec access) so
// they can be attached to opcodes and used by doc generation
type FieldGroup struct {
	Name  string
	Doc   string
	Names []string
	specs fieldSpecMap
}

// SpecByName returns a FieldsSpec for a name, respecting the "sparseness" of
// the Names array to hide some names
func (fg *FieldGroup) SpecByName(name string) (FieldSpec, bool) {
	if fs, ok := fg.specs.get(name); ok {
		if fg.Names[fs.Field()] != "" {
			return fs, true
		}
	}
	return nil, false
}

// TxnField is an enum type for `txn` and `gtxn`
type TxnField int

const (
	// Sender Transaction.Sender
	Sender TxnField = iota
	// Fee Transaction.Fee
	Fee
	// FirstValid Transaction.FirstValid
	FirstValid
	// FirstValidTime timestamp of block(FirstValid-1)
	FirstValidTime
	// LastValid Transaction.LastValid
	LastValid
	// Note Transaction.Note
	Note
	// Lease Transaction.Lease
	Lease
	// Receiver Transaction.Receiver
	Receiver
	// Amount Transaction.Amount
	Amount
	// CloseRemainderTo Transaction.CloseRemainderTo
	CloseRemainderTo
	// VotePK Transaction.VotePK
	VotePK
	// SelectionPK Transaction.SelectionPK
	SelectionPK
	// VoteFirst Transaction.VoteFirst
	VoteFirst
	// VoteLast Transaction.VoteLast
	VoteLast
	// VoteKeyDilution Transaction.VoteKeyDilution
	VoteKeyDilution
	// Type Transaction.Type
	Type
	// TypeEnum int(Transaction.Type)
	TypeEnum
	// XferAsset Transaction.XferAsset
	XferAsset
	// AssetAmount Transaction.AssetAmount
	AssetAmount
	// AssetSender Transaction.AssetSender
	AssetSender
	// AssetReceiver Transaction.AssetReceiver
	AssetReceiver
	// AssetCloseTo Transaction.AssetCloseTo
	AssetCloseTo
	// GroupIndex i for txngroup[i] == Txn
	GroupIndex
	// TxID Transaction.ID()
	TxID
	// ApplicationID basics.AppIndex
	ApplicationID
	// OnCompletion OnCompletion
	OnCompletion
	// ApplicationArgs  [][]byte
	ApplicationArgs
	// NumAppArgs len(ApplicationArgs)
	NumAppArgs
	// Accounts []basics.Address
	Accounts
	// NumAccounts len(Accounts)
	NumAccounts
	// ApprovalProgram []byte
	ApprovalProgram
	// ClearStateProgram []byte
	ClearStateProgram
	// RekeyTo basics.Address
	RekeyTo
	// ConfigAsset basics.AssetIndex
	ConfigAsset
	// ConfigAssetTotal AssetParams.Total
	ConfigAssetTotal
	// ConfigAssetDecimals AssetParams.Decimals
	ConfigAssetDecimals
	// ConfigAssetDefaultFrozen AssetParams.AssetDefaultFrozen
	ConfigAssetDefaultFrozen
	// ConfigAssetUnitName AssetParams.UnitName
	ConfigAssetUnitName
	// ConfigAssetName AssetParams.AssetName
	ConfigAssetName
	// ConfigAssetURL AssetParams.URL
	ConfigAssetURL
	// ConfigAssetMetadataHash AssetParams.MetadataHash
	ConfigAssetMetadataHash
	// ConfigAssetManager AssetParams.Manager
	ConfigAssetManager
	// ConfigAssetReserve AssetParams.Reserve
	ConfigAssetReserve
	// ConfigAssetFreeze AssetParams.Freeze
	ConfigAssetFreeze
	// ConfigAssetClawback AssetParams.Clawback
	ConfigAssetClawback
	//FreezeAsset  basics.AssetIndex
	FreezeAsset
	// FreezeAssetAccount basics.Address
	FreezeAssetAccount
	// FreezeAssetFrozen bool
	FreezeAssetFrozen
	// Assets []basics.AssetIndex
	Assets
	// NumAssets len(ForeignAssets)
	NumAssets
	// Applications []basics.AppIndex
	Applications
	// NumApplications len(ForeignApps)
	NumApplications

	// GlobalNumUint uint64
	GlobalNumUint
	// GlobalNumByteSlice uint64
	GlobalNumByteSlice
	// LocalNumUint uint64
	LocalNumUint
	// LocalNumByteSlice uint64
	LocalNumByteSlice

	// ExtraProgramPages AppParams.ExtraProgramPages
	ExtraProgramPages

	// Nonparticipation Transaction.Nonparticipation
	Nonparticipation

	// Logs Transaction.ApplyData.EvalDelta.Logs
	Logs

	// NumLogs len(Logs)
	NumLogs

	// CreatedAssetID Transaction.ApplyData.EvalDelta.ConfigAsset
	CreatedAssetID

	// CreatedApplicationID Transaction.ApplyData.EvalDelta.ApplicationID
	CreatedApplicationID

	// LastLog Logs[len(Logs)-1]
	LastLog

	// StateProofPK Transaction.StateProofPK
	StateProofPK

	// ApprovalProgramPages [][]byte
	ApprovalProgramPages

	// NumApprovalProgramPages = len(ApprovalProgramPages) // 4096
	NumApprovalProgramPages

	// ClearStateProgramPages [][]byte
	ClearStateProgramPages

	// NumClearStateProgramPages = len(ClearStateProgramPages) // 4096
	NumClearStateProgramPages

	// RejectVersion uint64
	RejectVersion

	invalidTxnField // compile-time constant for number of fields
)

func txnFieldSpecByField(f TxnField) (txnFieldSpec, bool) {
	if int(f) >= len(txnFieldSpecs) {
		return txnFieldSpec{}, false
	}
	return txnFieldSpecs[f], true
}

// TxnFieldNames are arguments to the 'txn' family of opcodes.
var TxnFieldNames [invalidTxnField]string

var txnFieldSpecByName = make(tfNameSpecMap, len(TxnFieldNames))

// simple interface used by doc generator for fields versioning
type tfNameSpecMap map[string]txnFieldSpec

func (s tfNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

type txnFieldSpec struct {
	field      TxnField
	ftype      StackType
	array      bool   // Is this an array field?
	version    uint64 // When this field become available to txn/gtxn. 0=always
	itxVersion uint64 // When this field become available to itxn_field. 0=never
	effects    bool   // Is this a field on the "effects"? That is, something in ApplyData
	doc        string
}

func (fs txnFieldSpec) Field() byte {
	return byte(fs.field)
}
func (fs txnFieldSpec) Type() StackType {
	return fs.ftype
}
func (fs txnFieldSpec) OpVersion() uint64 {
	return 0
}
func (fs txnFieldSpec) Version() uint64 {
	return fs.version
}
func (fs txnFieldSpec) Note() string {
	note := fs.doc
	if fs.effects {
		note = addExtra(note, "Application mode only")
	}
	return note
}

var txnFieldSpecs = [...]txnFieldSpec{
	{Sender, StackAddress, false, 0, 5, false, "32 byte address"},
	{Fee, StackUint64, false, 0, 5, false, "microalgos"},
	{FirstValid, StackUint64, false, 0, 0, false, "round number"},
	{FirstValidTime, StackUint64, false, randomnessVersion, 0, false, "UNIX timestamp of block before txn.FirstValid. Fails if negative"},
	{LastValid, StackUint64, false, 0, 0, false, "round number"},
	{Note, StackBytes, false, 0, 6, false, "Any data up to 1024 bytes"},
	{Lease, StackBytes32, false, 0, 0, false, "32 byte lease value"},
	{Receiver, StackAddress, false, 0, 5, false, "32 byte address"},
	{Amount, StackUint64, false, 0, 5, false, "microalgos"},
	{CloseRemainderTo, StackAddress, false, 0, 5, false, "32 byte address"},
	{VotePK, StackBytes32, false, 0, 6, false, "32 byte address"},
	{SelectionPK, StackBytes32, false, 0, 6, false, "32 byte address"},
	{VoteFirst, StackUint64, false, 0, 6, false, "The first round that the participation key is valid."},
	{VoteLast, StackUint64, false, 0, 6, false, "The last round that the participation key is valid."},
	{VoteKeyDilution, StackUint64, false, 0, 6, false, "Dilution for the 2-level participation key"},
	{Type, StackBytes, false, 0, 5, false, "Transaction type as bytes"},
	{TypeEnum, StackUint64, false, 0, 5, false, "Transaction type as integer"},
	{XferAsset, StackUint64, false, 0, 5, false, "Asset ID"},
	{AssetAmount, StackUint64, false, 0, 5, false, "value in Asset's units"},
	{AssetSender, StackAddress, false, 0, 5, false,
		"32 byte address. Source of assets if Sender is the Asset's Clawback address."},
	{AssetReceiver, StackAddress, false, 0, 5, false, "32 byte address"},
	{AssetCloseTo, StackAddress, false, 0, 5, false, "32 byte address"},
	{GroupIndex, StackUint64, false, 0, 0, false,
		"Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1"},
	{TxID, StackBytes32, false, 0, 0, false, "The computed ID for this transaction. 32 bytes."},
	{ApplicationID, StackUint64, false, 2, 6, false, "ApplicationID from ApplicationCall transaction"},
	{OnCompletion, StackUint64, false, 2, 6, false, "ApplicationCall transaction on completion action"},
	{ApplicationArgs, StackBytes, true, 2, 6, false,
		"Arguments passed to the application in the ApplicationCall transaction"},
	{NumAppArgs, StackUint64, false, 2, 0, false, "Number of ApplicationArgs"},
	{Accounts, StackAddress, true, 2, 6, false, "Accounts listed in the ApplicationCall transaction"},
	{NumAccounts, StackUint64, false, 2, 0, false, "Number of Accounts"},
	{ApprovalProgram, StackBytes, false, 2, 6, false, "Approval program"},
	{ClearStateProgram, StackBytes, false, 2, 6, false, "Clear state program"},
	{RekeyTo, StackAddress, false, 2, 6, false, "32 byte Sender's new AuthAddr"},
	{ConfigAsset, StackUint64, false, 2, 5, false, "Asset ID in asset config transaction"},
	{ConfigAssetTotal, StackUint64, false, 2, 5, false, "Total number of units of this asset created"},
	{ConfigAssetDecimals, StackUint64, false, 2, 5, false,
		"Number of digits to display after the decimal place when displaying the asset"},
	{ConfigAssetDefaultFrozen, StackBoolean, false, 2, 5, false,
		"Whether the asset's slots are frozen by default or not, 0 or 1"},
	{ConfigAssetUnitName, StackBytes, false, 2, 5, false, "Unit name of the asset"},
	{ConfigAssetName, StackBytes, false, 2, 5, false, "The asset name"},
	{ConfigAssetURL, StackBytes, false, 2, 5, false, "URL"},
	{ConfigAssetMetadataHash, StackBytes32, false, 2, 5, false,
		"32 byte commitment to unspecified asset metadata"},
	{ConfigAssetManager, StackAddress, false, 2, 5, false, "32 byte address"},
	{ConfigAssetReserve, StackAddress, false, 2, 5, false, "32 byte address"},
	{ConfigAssetFreeze, StackAddress, false, 2, 5, false, "32 byte address"},
	{ConfigAssetClawback, StackAddress, false, 2, 5, false, "32 byte address"},
	{FreezeAsset, StackUint64, false, 2, 5, false, "Asset ID being frozen or un-frozen"},
	{FreezeAssetAccount, StackAddress, false, 2, 5, false,
		"32 byte address of the account whose asset slot is being frozen or un-frozen"},
	{FreezeAssetFrozen, StackBoolean, false, 2, 5, false, "The new frozen value, 0 or 1"},
	{Assets, StackUint64, true, 3, 6, false, "Foreign Assets listed in the ApplicationCall transaction"},
	{NumAssets, StackUint64, false, 3, 0, false, "Number of Assets"},
	{Applications, StackUint64, true, 3, 6, false, "Foreign Apps listed in the ApplicationCall transaction"},
	{NumApplications, StackUint64, false, 3, 0, false, "Number of Applications"},
	{GlobalNumUint, StackUint64, false, 3, 6, false, "Number of global state integers in ApplicationCall"},
	{GlobalNumByteSlice, StackUint64, false, 3, 6, false, "Number of global state byteslices in ApplicationCall"},
	{LocalNumUint, StackUint64, false, 3, 6, false, "Number of local state integers in ApplicationCall"},
	{LocalNumByteSlice, StackUint64, false, 3, 6, false, "Number of local state byteslices in ApplicationCall"},
	{ExtraProgramPages, StackUint64, false, 4, 6, false,
		"Number of additional pages for each of the application's approval and clear state programs. An ExtraProgramPages of 1 means 2048 more total bytes, or 1024 for each program."},
	{Nonparticipation, StackBoolean, false, 5, 6, false, "Marks an account nonparticipating for rewards"},

	// "Effects" Last two things are always going to: 0, true
	{Logs, StackBytes, true, 5, 0, true, "Log messages emitted by an application call (only with `itxn` in v5)"},
	{NumLogs, StackUint64, false, 5, 0, true, "Number of Logs (only with `itxn` in v5)"},
	{CreatedAssetID, StackUint64, false, 5, 0, true,
		"Asset ID allocated by the creation of an ASA (only with `itxn` in v5)"},
	{CreatedApplicationID, StackUint64, false, 5, 0, true,
		"ApplicationID allocated by the creation of an application (only with `itxn` in v5)"},
	{LastLog, StackBytes, false, 6, 0, true, "The last message emitted. Empty bytes if none were emitted"},

	// Not an effect. Just added after the effects fields.
	{StateProofPK, StackBytes64, false, 6, 6, false, "State proof public key"},

	// Pseudo-fields to aid access to large programs (bigger than TEAL values)
	// reading in a txn seems not *super* useful, but setting in `itxn` is critical to inner app factories
	{ApprovalProgramPages, StackBytes, true, 7, 7, false, "Approval Program as an array of pages"},
	{NumApprovalProgramPages, StackUint64, false, 7, 0, false, "Number of Approval Program pages"},
	{ClearStateProgramPages, StackBytes, true, 7, 7, false, "ClearState Program as an array of pages"},
	{NumClearStateProgramPages, StackUint64, false, 7, 0, false, "Number of ClearState Program pages"},

	{RejectVersion, StackUint64, false, 12, 12, false, "Application version for which the txn must reject"},
}

// TxnFields contains info on the arguments to the txn* family of opcodes
var TxnFields = FieldGroup{
	"txn", "",
	TxnFieldNames[:],
	txnFieldSpecByName,
}

// TxnScalarFields narrows TxnFields to only have the names of scalar fetching opcodes
var TxnScalarFields = FieldGroup{
	"txn", "Fields (see [transaction reference](https://developer.algorand.org/docs/reference/transactions/))",
	txnScalarFieldNames(),
	txnFieldSpecByName,
}

// txnScalarFieldNames are txn field names that return scalars. Return value is
// a "sparse" slice, the names appear at their usual index, array slots are set
// to "".  They are laid out this way so that it is possible to get the name
// from the index value.
func txnScalarFieldNames() []string {
	names := make([]string, len(txnFieldSpecs))
	for i, fs := range txnFieldSpecs {
		if fs.array {
			names[i] = ""
		} else {
			names[i] = fs.field.String()
		}
	}
	return names
}

// TxnArrayFields narows TxnFields to only have the names of array fetching opcodes
var TxnArrayFields = FieldGroup{
	"txna", "Fields (see [transaction reference](https://developer.algorand.org/docs/reference/transactions/))",
	txnaFieldNames(),
	txnFieldSpecByName,
}

// txnaFieldNames are txn field names that return arrays. Return value is a
// "sparse" slice, the names appear at their usual index, non-array slots are
// set to "".  They are laid out this way so that it is possible to get the name
// from the index value.
func txnaFieldNames() []string {
	names := make([]string, len(txnFieldSpecs))
	for i, fs := range txnFieldSpecs {
		if fs.array {
			names[i] = fs.field.String()
		} else {
			names[i] = ""
		}
	}
	return names
}

// ItxnSettableFields collects info for itxn_field opcode
var ItxnSettableFields = FieldGroup{
	"itxn_field", "",
	itxnSettableFieldNames(),
	txnFieldSpecByName,
}

// itxnSettableFieldNames are txn field names that can be set by
// itxn_field. Return value is a "sparse" slice, the names appear at their usual
// index, unsettable slots are set to "".  They are laid out this way so that it is
// possible to get the name from the index value.
func itxnSettableFieldNames() []string {
	names := make([]string, len(txnFieldSpecs))
	for i, fs := range txnFieldSpecs {
		if fs.itxVersion == 0 {
			names[i] = ""
		} else {
			names[i] = fs.field.String()
		}
	}
	return names
}

var innerTxnTypes = map[string]uint64{
	string(protocol.PaymentTx):         5,
	string(protocol.KeyRegistrationTx): 6,
	string(protocol.AssetTransferTx):   5,
	string(protocol.AssetConfigTx):     5,
	string(protocol.AssetFreezeTx):     5,
	string(protocol.ApplicationCallTx): 6,
}

// TxnTypeNames is the values of Txn.Type in enum order
var TxnTypeNames = [...]string{
	string(protocol.UnknownTx),
	string(protocol.PaymentTx),
	string(protocol.KeyRegistrationTx),
	string(protocol.AssetConfigTx),
	string(protocol.AssetTransferTx),
	string(protocol.AssetFreezeTx),
	string(protocol.ApplicationCallTx),
}

// map txn type names (long and short) to index/enum value
var txnTypeMap = make(map[string]uint64)

// OnCompletionConstType is the same as transactions.OnCompletion
type OnCompletionConstType transactions.OnCompletion

const (
	// NoOp = transactions.NoOpOC
	NoOp = OnCompletionConstType(transactions.NoOpOC)
	// OptIn = transactions.OptInOC
	OptIn = OnCompletionConstType(transactions.OptInOC)
	// CloseOut = transactions.CloseOutOC
	CloseOut = OnCompletionConstType(transactions.CloseOutOC)
	// ClearState = transactions.ClearStateOC
	ClearState = OnCompletionConstType(transactions.ClearStateOC)
	// UpdateApplication = transactions.UpdateApplicationOC
	UpdateApplication = OnCompletionConstType(transactions.UpdateApplicationOC)
	// DeleteApplication = transactions.DeleteApplicationOC
	DeleteApplication = OnCompletionConstType(transactions.DeleteApplicationOC)
	// end of constants
	invalidOnCompletionConst = DeleteApplication + 1
)

// OnCompletionNames is the string names of Txn.OnCompletion, array index is the const value
var OnCompletionNames [invalidOnCompletionConst]string

// onCompletionMap maps symbolic name to uint64 for assembleInt
var onCompletionMap map[string]uint64

// GlobalField is an enum for `global` opcode
type GlobalField uint64

const (
	// MinTxnFee ConsensusParams.MinTxnFee
	MinTxnFee GlobalField = iota
	// MinBalance ConsensusParams.MinBalance
	MinBalance
	// MaxTxnLife ConsensusParams.MaxTxnLife
	MaxTxnLife
	// ZeroAddress [32]byte{0...}
	ZeroAddress
	// GroupSize len(txn group)
	GroupSize

	// v2

	// LogicSigVersion ConsensusParams.LogicSigVersion
	LogicSigVersion
	// Round basics.Round
	Round
	// LatestTimestamp uint64
	LatestTimestamp
	// CurrentApplicationID uint64
	CurrentApplicationID

	// v3

	// CreatorAddress [32]byte
	CreatorAddress

	// v5

	// CurrentApplicationAddress [32]byte
	CurrentApplicationAddress
	// GroupID [32]byte
	GroupID

	// v6

	// OpcodeBudget The remaining budget available for execution
	OpcodeBudget

	// CallerApplicationID The ID of the caller app, else 0
	CallerApplicationID

	// CallerApplicationAddress The Address of the caller app, else ZeroAddress
	CallerApplicationAddress

	// AssetCreateMinBalance is the additional minimum balance required to
	// create an asset (which also opts an account into that asset)
	AssetCreateMinBalance

	// AssetOptInMinBalance is the additional minimum balance required to opt in to an asset
	AssetOptInMinBalance

	// GenesisHash is the genesis hash for the network
	GenesisHash

	// PayoutsEnabled is whether block proposal payouts are enabled
	PayoutsEnabled

	// PayoutsGoOnlineFee is the fee required in a keyreg transaction to make an account incentive eligible
	PayoutsGoOnlineFee

	// PayoutsPercent is the percentage of transaction fees in a block that can be paid to the block proposer.
	PayoutsPercent

	// PayoutsMinBalance is the minimum algo balance an account must have to receive block payouts (in the agreement round).
	PayoutsMinBalance

	// PayoutsMaxBalance is the maximum algo balance an account can have to receive block payouts (in the agreement round).
	PayoutsMaxBalance

	invalidGlobalField // compile-time constant for number of fields
)

// GlobalFieldNames are arguments to the 'global' opcode
var GlobalFieldNames [invalidGlobalField]string

type globalFieldSpec struct {
	field   GlobalField
	ftype   StackType
	mode    RunMode
	version uint64
	doc     string
}

func (fs globalFieldSpec) Field() byte {
	return byte(fs.field)
}
func (fs globalFieldSpec) Type() StackType {
	return fs.ftype
}
func (fs globalFieldSpec) OpVersion() uint64 {
	return 0
}
func (fs globalFieldSpec) Version() uint64 {
	return fs.version
}
func (fs globalFieldSpec) Note() string {
	note := fs.doc
	if fs.mode == ModeApp {
		note = addExtra(note, "Application mode only.")
	}
	// There are no Signature mode only globals
	return note
}

var globalFieldSpecs = [...]globalFieldSpec{
	// version 0 is the same as v1 (initial release)
	{MinTxnFee, StackUint64, modeAny, 0, "microalgos"},
	{MinBalance, StackUint64, modeAny, 0, "microalgos"},
	{MaxTxnLife, StackUint64, modeAny, 0, "rounds"},
	{ZeroAddress, StackAddress, modeAny, 0, "32 byte address of all zero bytes"},
	{GroupSize, StackUint64, modeAny, 0,
		"Number of transactions in this atomic transaction group. At least 1"},
	{LogicSigVersion, StackUint64, modeAny, 2, "Maximum supported version"},
	{Round, StackUint64, ModeApp, 2, "Current round number"},
	{LatestTimestamp, StackUint64, ModeApp, 2,
		"Last confirmed block UNIX timestamp. Fails if negative"},
	{CurrentApplicationID, StackUint64, ModeApp, 2, "ID of current application executing"},
	{CreatorAddress, StackAddress, ModeApp, 3,
		"Address of the creator of the current application"},
	{CurrentApplicationAddress, StackAddress, ModeApp, 5,
		"Address that the current application controls"},
	{GroupID, StackBytes32, modeAny, 5,
		"ID of the transaction group. 32 zero bytes if the transaction is not part of a group."},
	{OpcodeBudget, StackUint64, modeAny, 6,
		"The remaining cost that can be spent by opcodes in this program."},
	{CallerApplicationID, StackUint64, ModeApp, 6,
		"The application ID of the application that called this application. 0 if this application is at the top-level."},
	{CallerApplicationAddress, StackAddress, ModeApp, 6,
		"The application address of the application that called this application. ZeroAddress if this application is at the top-level."},
	{AssetCreateMinBalance, StackUint64, modeAny, 10,
		"The additional minimum balance required to create (and opt-in to) an asset."},
	{AssetOptInMinBalance, StackUint64, modeAny, 10,
		"The additional minimum balance required to opt-in to an asset."},
	{GenesisHash, StackBytes32, modeAny, 10, "The Genesis Hash for the network."},

	{PayoutsEnabled, StackBoolean, modeAny, incentiveVersion,
		"Whether block proposal payouts are enabled."},
	{PayoutsGoOnlineFee, StackUint64, modeAny, incentiveVersion,
		"The fee required in a keyreg transaction to make an account incentive eligible."},
	{PayoutsPercent, StackUint64, modeAny, incentiveVersion,
		"The percentage of transaction fees in a block that can be paid to the block proposer."},
	{PayoutsMinBalance, StackUint64, modeAny, incentiveVersion,
		"The minimum balance an account must have in the agreement round to receive block payouts in the proposal round."},
	{PayoutsMaxBalance, StackUint64, modeAny, incentiveVersion,
		"The maximum balance an account can have in the agreement round to receive block payouts in the proposal round."},
}

func globalFieldSpecByField(f GlobalField) (globalFieldSpec, bool) {
	if int(f) >= len(globalFieldSpecs) {
		return globalFieldSpec{}, false
	}
	return globalFieldSpecs[f], true
}

var globalFieldSpecByName = make(gfNameSpecMap, len(GlobalFieldNames))

type gfNameSpecMap map[string]globalFieldSpec

func (s gfNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// GlobalFields has info on the global opcode's immediate
var GlobalFields = FieldGroup{
	"global", "Fields",
	GlobalFieldNames[:],
	globalFieldSpecByName,
}

// EcdsaCurve is an enum for `ecdsa_` opcodes
type EcdsaCurve int

const (
	// Secp256k1 curve for bitcoin/ethereum
	Secp256k1 EcdsaCurve = iota
	// Secp256r1 curve
	Secp256r1
	invalidEcdsaCurve // compile-time constant for number of fields
)

var ecdsaCurveNames [invalidEcdsaCurve]string

type ecdsaCurveSpec struct {
	field   EcdsaCurve
	version uint64
	doc     string
}

func (fs ecdsaCurveSpec) Field() byte {
	return byte(fs.field)
}
func (fs ecdsaCurveSpec) Type() StackType {
	return StackNone // Will not show, since all are untyped
}
func (fs ecdsaCurveSpec) OpVersion() uint64 {
	return 5
}
func (fs ecdsaCurveSpec) Version() uint64 {
	return fs.version
}
func (fs ecdsaCurveSpec) Note() string {
	return fs.doc
}

var ecdsaCurveSpecs = [...]ecdsaCurveSpec{
	{Secp256k1, 5, "secp256k1 curve, used in Bitcoin"},
	{Secp256r1, fidoVersion, "secp256r1 curve, NIST standard"},
}

func ecdsaCurveSpecByField(c EcdsaCurve) (ecdsaCurveSpec, bool) {
	if int(c) >= len(ecdsaCurveSpecs) {
		return ecdsaCurveSpec{}, false
	}
	return ecdsaCurveSpecs[c], true
}

var ecdsaCurveSpecByName = make(ecdsaCurveNameSpecMap, len(ecdsaCurveNames))

type ecdsaCurveNameSpecMap map[string]ecdsaCurveSpec

func (s ecdsaCurveNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// EcdsaCurves collects details about the constants used to describe EcdsaCurves
var EcdsaCurves = FieldGroup{
	"ECDSA", "Curves",
	ecdsaCurveNames[:],
	ecdsaCurveSpecByName,
}

// EcGroup is an enum for `ec_` opcodes
type EcGroup int

const (
	// BN254g1 is the G1 group of BN254
	BN254g1 EcGroup = iota
	// BN254g2 is the G2 group of BN254
	BN254g2
	// BLS12_381g1 specifies the G1 group of BLS 12-381
	BLS12_381g1
	// BLS12_381g2 specifies the G2 group of BLS 12-381
	BLS12_381g2
	invalidEcGroup // compile-time constant for number of fields
)

var ecGroupNames [invalidEcGroup]string

type ecGroupSpec struct {
	field EcGroup
	doc   string
}

func (fs ecGroupSpec) Field() byte {
	return byte(fs.field)
}
func (fs ecGroupSpec) Type() StackType {
	return StackNone // Will not show, since all are untyped
}
func (fs ecGroupSpec) OpVersion() uint64 {
	return pairingVersion
}
func (fs ecGroupSpec) Version() uint64 {
	return pairingVersion
}
func (fs ecGroupSpec) Note() string {
	return fs.doc
}

var ecGroupSpecs = [...]ecGroupSpec{
	{BN254g1, "G1 of the BN254 curve. Points encoded as 32 byte X following by 32 byte Y"},
	{BN254g2, "G2 of the BN254 curve. Points encoded as 64 byte X following by 64 byte Y"},
	{BLS12_381g1, "G1 of the BLS 12-381 curve. Points encoded as 48 byte X following by 48 byte Y"},
	{BLS12_381g2, "G2 of the BLS 12-381 curve. Points encoded as 96 byte X following by 96 byte Y"},
}

func ecGroupSpecByField(c EcGroup) (ecGroupSpec, bool) {
	if int(c) >= len(ecGroupSpecs) {
		return ecGroupSpec{}, false
	}
	return ecGroupSpecs[c], true
}

var ecGroupSpecByName = make(ecGroupNameSpecMap, len(ecGroupNames))

type ecGroupNameSpecMap map[string]ecGroupSpec

func (s ecGroupNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// EcGroups collects details about the constants used to describe EcGroups
var EcGroups = FieldGroup{
	"EC", "Groups",
	ecGroupNames[:],
	ecGroupSpecByName,
}

// MimcConfig is an enum for the `mimc` opcode
type MimcConfig int

const (
	// BN254Mp110 is the default MiMC configuration for the BN254 curve with Miyaguchi-Preneel mode, 110 rounds, exponent 5, seed "seed"
	BN254Mp110 MimcConfig = iota
	// BLS12_381Mp111 is the default MiMC configuration for the BLS12-381 curve with Miyaguchi-Preneel mode, 111 rounds, exponent 5, seed "seed"
	BLS12_381Mp111
	invalidMimcConfig // compile-time constant for number of fields
)

var mimcConfigNames [invalidMimcConfig]string

type mimcConfigSpec struct {
	field MimcConfig
	doc   string
}

func (fs mimcConfigSpec) Field() byte {
	return byte(fs.field)
}
func (fs mimcConfigSpec) Type() StackType {
	return StackNone // Will not show, since all are untyped
}
func (fs mimcConfigSpec) OpVersion() uint64 {
	return mimcVersion
}
func (fs mimcConfigSpec) Version() uint64 {
	return mimcVersion
}
func (fs mimcConfigSpec) Note() string {
	return fs.doc
}

var mimcConfigSpecs = [...]mimcConfigSpec{
	{BN254Mp110, "MiMC configuration for the BN254 curve with Miyaguchi-Preneel mode, 110 rounds, exponent 5, seed \"seed\""},
	{BLS12_381Mp111, "MiMC configuration for the BLS12-381 curve with Miyaguchi-Preneel mode, 111 rounds, exponent 5, seed \"seed\""},
}

func mimcConfigSpecByField(c MimcConfig) (mimcConfigSpec, bool) {
	if int(c) >= len(mimcConfigSpecs) {
		return mimcConfigSpec{}, false
	}
	return mimcConfigSpecs[c], true
}

var mimcConfigSpecByName = make(mimcConfigNameSpecMap, len(mimcConfigNames))

type mimcConfigNameSpecMap map[string]mimcConfigSpec

func (s mimcConfigNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// MimcConfigs collects details about the constants used to describe MimcConfigs
var MimcConfigs = FieldGroup{
	"Mimc Configurations", "Parameters",
	mimcConfigNames[:],
	mimcConfigSpecByName,
}

// Base64Encoding is an enum for the `base64decode` opcode
type Base64Encoding int

const (
	// URLEncoding represents the base64url encoding defined in https://www.rfc-editor.org/rfc/rfc4648.html
	URLEncoding Base64Encoding = iota
	// StdEncoding represents the standard encoding of the RFC
	StdEncoding
	invalidBase64Encoding // compile-time constant for number of fields
)

var base64EncodingNames [invalidBase64Encoding]string

type base64EncodingSpec struct {
	field   Base64Encoding
	version uint64
}

var base64EncodingSpecs = [...]base64EncodingSpec{
	{URLEncoding, 6},
	{StdEncoding, 6},
}

func base64EncodingSpecByField(e Base64Encoding) (base64EncodingSpec, bool) {
	if int(e) >= len(base64EncodingSpecs) {
		return base64EncodingSpec{}, false
	}
	return base64EncodingSpecs[e], true
}

var base64EncodingSpecByName = make(base64EncodingSpecMap, len(base64EncodingNames))

type base64EncodingSpecMap map[string]base64EncodingSpec

func (fs base64EncodingSpec) Field() byte {
	return byte(fs.field)
}
func (fs base64EncodingSpec) Type() StackType {
	return StackAny // Will not show in docs, since all are untyped
}
func (fs base64EncodingSpec) OpVersion() uint64 {
	return 6
}
func (fs base64EncodingSpec) Version() uint64 {
	return fs.version
}
func (fs base64EncodingSpec) Note() string {
	note := "" // no doc list?
	return note
}

func (s base64EncodingSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// Base64Encodings describes the base64_encode immediate
var Base64Encodings = FieldGroup{
	"base64", "Encodings",
	base64EncodingNames[:],
	base64EncodingSpecByName,
}

// JSONRefType is an enum for the `json_ref` opcode
type JSONRefType int

const (
	// JSONString represents string json value
	JSONString JSONRefType = iota
	// JSONUint64 represents uint64 json value
	JSONUint64
	// JSONObject represents json object
	JSONObject
	invalidJSONRefType // compile-time constant for number of fields
)

var jsonRefTypeNames [invalidJSONRefType]string

type jsonRefSpec struct {
	field   JSONRefType
	ftype   StackType
	version uint64
}

var jsonRefSpecs = [...]jsonRefSpec{
	{JSONString, StackBytes, fidoVersion},
	{JSONUint64, StackUint64, fidoVersion},
	{JSONObject, StackBytes, fidoVersion},
}

func jsonRefSpecByField(r JSONRefType) (jsonRefSpec, bool) {
	if int(r) >= len(jsonRefSpecs) {
		return jsonRefSpec{}, false
	}
	return jsonRefSpecs[r], true
}

var jsonRefSpecByName = make(jsonRefSpecMap, len(jsonRefTypeNames))

type jsonRefSpecMap map[string]jsonRefSpec

func (fs jsonRefSpec) Field() byte {
	return byte(fs.field)
}
func (fs jsonRefSpec) Type() StackType {
	return fs.ftype
}
func (fs jsonRefSpec) OpVersion() uint64 {
	return fidoVersion
}
func (fs jsonRefSpec) Version() uint64 {
	return fs.version
}
func (fs jsonRefSpec) Note() string {
	note := "" // no doc list?
	return note
}

func (s jsonRefSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// JSONRefTypes describes the json_ref immediate
var JSONRefTypes = FieldGroup{
	"json_ref", "Types",
	jsonRefTypeNames[:],
	jsonRefSpecByName,
}

// VrfStandard is an enum for the `vrf_verify` opcode
type VrfStandard int

const (
	// VrfAlgorand is the built-in VRF of the Algorand chain
	VrfAlgorand        VrfStandard = iota
	invalidVrfStandard             // compile-time constant for number of fields
)

var vrfStandardNames [invalidVrfStandard]string

type vrfStandardSpec struct {
	field   VrfStandard
	version uint64
}

var vrfStandardSpecs = [...]vrfStandardSpec{
	{VrfAlgorand, randomnessVersion},
}

func vrfStandardSpecByField(r VrfStandard) (vrfStandardSpec, bool) {
	if int(r) >= len(vrfStandardSpecs) {
		return vrfStandardSpec{}, false
	}
	return vrfStandardSpecs[r], true
}

var vrfStandardSpecByName = make(vrfStandardSpecMap, len(vrfStandardNames))

type vrfStandardSpecMap map[string]vrfStandardSpec

func (s vrfStandardSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

func (fs vrfStandardSpec) Field() byte {
	return byte(fs.field)
}

func (fs vrfStandardSpec) Type() StackType {
	return StackNone // Will not show, since all are the same
}

func (fs vrfStandardSpec) OpVersion() uint64 {
	return randomnessVersion
}

func (fs vrfStandardSpec) Version() uint64 {
	return fs.version
}

func (fs vrfStandardSpec) Note() string {
	note := "" // no doc list?
	return note
}

func (s vrfStandardSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

// VrfStandards describes the json_ref immediate
var VrfStandards = FieldGroup{
	"vrf_verify", "Standards",
	vrfStandardNames[:],
	vrfStandardSpecByName,
}

// BlockField is an enum for the `block` opcode
type BlockField int

const (
	// BlkSeed is the Block's vrf seed
	BlkSeed BlockField = iota
	// BlkTimestamp is the Block's timestamp, seconds from epoch
	BlkTimestamp
	// BlkProposer is the Block's proposer, or ZeroAddress, pre Payouts.Enabled
	BlkProposer
	// BlkFeesCollected is the sum of fees for the block, or 0, pre Payouts.Enabled
	BlkFeesCollected
	// BlkBonus is the extra amount to be paid for the given block (from FeeSink)
	BlkBonus
	// BlkBranch is the hash of the previous block
	BlkBranch
	// BlkFeeSink is the fee sink for the given round
	BlkFeeSink
	// BlkProtocol is the ConsensusVersion of the block.
	BlkProtocol
	// BlkTxnCounter is the number of the next transaction after the block
	BlkTxnCounter
	// BlkProposerPayout is the actual amount moved from feesink to proposer
	BlkProposerPayout

	// BlkBranch512 is the wider, sha-512 hash of the previous block
	BlkBranch512

	// BlkSha512_256TxnCommitment is "Algorand Native" txn merkle root
	BlkSha512_256TxnCommitment

	// BlkSha256TxnCommitment is the sha256 txn merkle root
	BlkSha256TxnCommitment

	// BlkSha512TxnCommitment is the sha512 txn merkle root
	BlkSha512TxnCommitment

	invalidBlockField // compile-time constant for number of fields
)

var blockFieldNames [invalidBlockField]string

type blockFieldSpec struct {
	field   BlockField
	ftype   StackType
	version uint64
}

var blockFieldSpecs = [...]blockFieldSpec{
	{BlkSeed, StackBytes32, randomnessVersion},
	{BlkTimestamp, StackUint64, randomnessVersion},
	{BlkProposer, StackAddress, incentiveVersion},
	{BlkFeesCollected, StackUint64, incentiveVersion},
	{BlkBonus, StackUint64, incentiveVersion},
	{BlkBranch, StackBytes32, incentiveVersion},
	{BlkFeeSink, StackAddress, incentiveVersion},
	{BlkProtocol, StackBytes, incentiveVersion},
	{BlkTxnCounter, StackUint64, incentiveVersion},
	{BlkProposerPayout, StackUint64, incentiveVersion},
	{BlkBranch512, StackBytes64, 13},
	{BlkSha512_256TxnCommitment, StackBytes32, 13},
	{BlkSha256TxnCommitment, StackBytes32, 13},
	{BlkSha512TxnCommitment, StackBytes64, 13},
}

func blockFieldSpecByField(r BlockField) (blockFieldSpec, bool) {
	if int(r) >= len(blockFieldSpecs) {
		return blockFieldSpec{}, false
	}
	return blockFieldSpecs[r], true
}

var blockFieldSpecByName = make(blockFieldSpecMap, len(blockFieldNames))

type blockFieldSpecMap map[string]blockFieldSpec

func (s blockFieldSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

func (fs blockFieldSpec) Field() byte {
	return byte(fs.field)
}

func (fs blockFieldSpec) Type() StackType {
	return fs.ftype
}

func (fs blockFieldSpec) OpVersion() uint64 {
	return randomnessVersion
}

func (fs blockFieldSpec) Version() uint64 {
	return fs.version
}

func (fs blockFieldSpec) Note() string {
	return ""
}

func (s blockFieldSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

// BlockFields describes the json_ref immediate
var BlockFields = FieldGroup{
	"block", "Fields",
	blockFieldNames[:],
	blockFieldSpecByName,
}

// AssetHoldingField is an enum for `asset_holding_get` opcode
type AssetHoldingField int

const (
	// AssetBalance AssetHolding.Amount
	AssetBalance AssetHoldingField = iota
	// AssetFrozen AssetHolding.Frozen
	AssetFrozen
	invalidAssetHoldingField // compile-time constant for number of fields
)

var assetHoldingFieldNames [invalidAssetHoldingField]string

type assetHoldingFieldSpec struct {
	field   AssetHoldingField
	ftype   StackType
	version uint64
	doc     string
}

func (fs assetHoldingFieldSpec) Field() byte {
	return byte(fs.field)
}
func (fs assetHoldingFieldSpec) Type() StackType {
	return fs.ftype
}
func (fs assetHoldingFieldSpec) OpVersion() uint64 {
	return 2
}
func (fs assetHoldingFieldSpec) Version() uint64 {
	return fs.version
}
func (fs assetHoldingFieldSpec) Note() string {
	return fs.doc
}

var assetHoldingFieldSpecs = [...]assetHoldingFieldSpec{
	{AssetBalance, StackUint64, 2, "Amount of the asset unit held by this account"},
	{AssetFrozen, StackBoolean, 2, "Is the asset frozen or not"},
}

func assetHoldingFieldSpecByField(f AssetHoldingField) (assetHoldingFieldSpec, bool) {
	if int(f) >= len(assetHoldingFieldSpecs) {
		return assetHoldingFieldSpec{}, false
	}
	return assetHoldingFieldSpecs[f], true
}

var assetHoldingFieldSpecByName = make(ahfNameSpecMap, len(assetHoldingFieldNames))

type ahfNameSpecMap map[string]assetHoldingFieldSpec

func (s ahfNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// AssetHoldingFields describes asset_holding_get's immediates
var AssetHoldingFields = FieldGroup{
	"asset_holding", "Fields",
	assetHoldingFieldNames[:],
	assetHoldingFieldSpecByName,
}

// AssetParamsField is an enum for `asset_params_get` opcode
type AssetParamsField int

const (
	// AssetTotal AssetParams.Total
	AssetTotal AssetParamsField = iota
	// AssetDecimals AssetParams.Decimals
	AssetDecimals
	// AssetDefaultFrozen AssetParams.AssetDefaultFrozen
	AssetDefaultFrozen
	// AssetUnitName AssetParams.UnitName
	AssetUnitName
	// AssetName AssetParams.AssetName
	AssetName
	// AssetURL AssetParams.URL
	AssetURL
	// AssetMetadataHash AssetParams.MetadataHash
	AssetMetadataHash
	// AssetManager AssetParams.Manager
	AssetManager
	// AssetReserve AssetParams.Reserve
	AssetReserve
	// AssetFreeze AssetParams.Freeze
	AssetFreeze
	// AssetClawback AssetParams.Clawback
	AssetClawback

	// AssetCreator is not *in* the Params, but it is uniquely determined.
	AssetCreator

	invalidAssetParamsField // compile-time constant for number of fields
)

var assetParamsFieldNames [invalidAssetParamsField]string

type assetParamsFieldSpec struct {
	field   AssetParamsField
	ftype   StackType
	version uint64
	doc     string
}

func (fs assetParamsFieldSpec) Field() byte {
	return byte(fs.field)
}
func (fs assetParamsFieldSpec) Type() StackType {
	return fs.ftype
}
func (fs assetParamsFieldSpec) OpVersion() uint64 {
	return 2
}
func (fs assetParamsFieldSpec) Version() uint64 {
	return fs.version
}
func (fs assetParamsFieldSpec) Note() string {
	return fs.doc
}

var assetParamsFieldSpecs = [...]assetParamsFieldSpec{
	{AssetTotal, StackUint64, 2, "Total number of units of this asset"},
	{AssetDecimals, StackUint64, 2, "See AssetParams.Decimals"},
	{AssetDefaultFrozen, StackBoolean, 2, "Frozen by default or not"},
	{AssetUnitName, StackBytes, 2, "Asset unit name"},
	{AssetName, StackBytes, 2, "Asset name"},
	{AssetURL, StackBytes, 2, "URL with additional info about the asset"},
	{AssetMetadataHash, StackBytes32, 2, "Arbitrary commitment"},
	{AssetManager, StackAddress, 2, "Manager address"},
	{AssetReserve, StackAddress, 2, "Reserve address"},
	{AssetFreeze, StackAddress, 2, "Freeze address"},
	{AssetClawback, StackAddress, 2, "Clawback address"},
	{AssetCreator, StackAddress, 5, "Creator address"},
}

func assetParamsFieldSpecByField(f AssetParamsField) (assetParamsFieldSpec, bool) {
	if int(f) >= len(assetParamsFieldSpecs) {
		return assetParamsFieldSpec{}, false
	}
	return assetParamsFieldSpecs[f], true
}

var assetParamsFieldSpecByName = make(apfNameSpecMap, len(assetParamsFieldNames))

type apfNameSpecMap map[string]assetParamsFieldSpec

func (s apfNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// AssetParamsFields describes asset_params_get's immediates
var AssetParamsFields = FieldGroup{
	"asset_params", "Fields",
	assetParamsFieldNames[:],
	assetParamsFieldSpecByName,
}

// AppParamsField is an enum for `app_params_get` opcode
type AppParamsField int

const (
	// AppApprovalProgram AppParams.ApprovalProgram
	AppApprovalProgram AppParamsField = iota
	// AppClearStateProgram AppParams.ClearStateProgram
	AppClearStateProgram
	// AppGlobalNumUint AppParams.StateSchemas.GlobalStateSchema.NumUint
	AppGlobalNumUint
	// AppGlobalNumByteSlice AppParams.StateSchemas.GlobalStateSchema.NumByteSlice
	AppGlobalNumByteSlice
	// AppLocalNumUint AppParams.StateSchemas.LocalStateSchema.NumUint
	AppLocalNumUint
	// AppLocalNumByteSlice AppParams.StateSchemas.LocalStateSchema.NumByteSlice
	AppLocalNumByteSlice
	// AppExtraProgramPages AppParams.ExtraProgramPages
	AppExtraProgramPages

	// AppCreator is not *in* the Params, but it is uniquely determined.
	AppCreator

	// AppAddress is also not *in* the Params, but can be derived
	AppAddress

	// AppVersion begins at 0 and increasing each time either program changes
	AppVersion

	invalidAppParamsField // compile-time constant for number of fields
)

var appParamsFieldNames [invalidAppParamsField]string

type appParamsFieldSpec struct {
	field   AppParamsField
	ftype   StackType
	version uint64
	doc     string
}

func (fs appParamsFieldSpec) Field() byte {
	return byte(fs.field)
}
func (fs appParamsFieldSpec) Type() StackType {
	return fs.ftype
}
func (fs appParamsFieldSpec) OpVersion() uint64 {
	return 5
}
func (fs appParamsFieldSpec) Version() uint64 {
	return fs.version
}
func (fs appParamsFieldSpec) Note() string {
	return fs.doc
}

var appParamsFieldSpecs = [...]appParamsFieldSpec{
	{AppApprovalProgram, StackBytes, 5, "Bytecode of Approval Program"},
	{AppClearStateProgram, StackBytes, 5, "Bytecode of Clear State Program"},
	{AppGlobalNumUint, StackUint64, 5, "Number of uint64 values allowed in Global State"},
	{AppGlobalNumByteSlice, StackUint64, 5, "Number of byte array values allowed in Global State"},
	{AppLocalNumUint, StackUint64, 5, "Number of uint64 values allowed in Local State"},
	{AppLocalNumByteSlice, StackUint64, 5, "Number of byte array values allowed in Local State"},
	{AppExtraProgramPages, StackUint64, 5, "Number of Extra Program Pages of code space"},
	{AppCreator, StackAddress, 5, "Creator address"},
	{AppAddress, StackAddress, 5, "Address for which this application has authority"},
	{AppVersion, StackUint64, 12, "Version of the app, incremented each time the approval or clear program changes"},
}

func appParamsFieldSpecByField(f AppParamsField) (appParamsFieldSpec, bool) {
	if int(f) >= len(appParamsFieldSpecs) {
		return appParamsFieldSpec{}, false
	}
	return appParamsFieldSpecs[f], true
}

var appParamsFieldSpecByName = make(appNameSpecMap, len(appParamsFieldNames))

// simple interface used by doc generator for fields versioning
type appNameSpecMap map[string]appParamsFieldSpec

func (s appNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// AppParamsFields describes app_params_get's immediates
var AppParamsFields = FieldGroup{
	"app_params", "Fields",
	appParamsFieldNames[:],
	appParamsFieldSpecByName,
}

// AcctParamsField is an enum for `acct_params_get` opcode
type AcctParamsField int

const (
	// AcctBalance is the balance, with pending rewards
	AcctBalance AcctParamsField = iota
	// AcctMinBalance is algos needed for this accounts apps and assets
	AcctMinBalance
	// AcctAuthAddr is the rekeyed address if any, else ZeroAddress
	AcctAuthAddr

	// AcctTotalNumUint is the count of all uints from created global apps or opted in locals
	AcctTotalNumUint
	// AcctTotalNumByteSlice is the count of all byte slices from created global apps or opted in locals
	AcctTotalNumByteSlice

	// AcctTotalExtraAppPages is the extra code pages across all apps
	AcctTotalExtraAppPages

	// AcctTotalAppsCreated is the number of apps created by this account
	AcctTotalAppsCreated
	// AcctTotalAppsOptedIn is the number of apps opted in by this account
	AcctTotalAppsOptedIn
	// AcctTotalAssetsCreated is the number of ASAs created by this account
	AcctTotalAssetsCreated
	// AcctTotalAssets is the number of ASAs opted in by this account (always includes AcctTotalAssetsCreated)
	AcctTotalAssets
	// AcctTotalBoxes is the number of boxes created by the app this account is associated with
	AcctTotalBoxes
	// AcctTotalBoxBytes is the number of bytes in all boxes of this app account
	AcctTotalBoxBytes

	// AcctIncentiveEligible is whether this account opted into block payouts by
	// paying extra in `keyreg`. Does not reflect eligibility based on balance.
	AcctIncentiveEligible
	// AcctLastProposed is the last time this account proposed. Does not include _this_ round.
	AcctLastProposed
	// AcctLastHeartbeat is the last heartbeat from this account.
	AcctLastHeartbeat

	// AcctTotalAppSchema - consider how to expose

	invalidAcctParamsField // compile-time constant for number of fields
)

var acctParamsFieldNames [invalidAcctParamsField]string

type acctParamsFieldSpec struct {
	field   AcctParamsField
	ftype   StackType
	version uint64
	doc     string
}

func (fs acctParamsFieldSpec) Field() byte {
	return byte(fs.field)
}
func (fs acctParamsFieldSpec) Type() StackType {
	return fs.ftype
}
func (fs acctParamsFieldSpec) OpVersion() uint64 {
	return 6
}
func (fs acctParamsFieldSpec) Version() uint64 {
	return fs.version
}
func (fs acctParamsFieldSpec) Note() string {
	return fs.doc
}

var acctParamsFieldSpecs = [...]acctParamsFieldSpec{
	{AcctBalance, StackUint64, 6, "Account balance in microalgos"},
	{AcctMinBalance, StackUint64, 6, "Minimum required balance for account, in microalgos"},
	{AcctAuthAddr, StackAddress, 6, "Address the account is rekeyed to."},

	{AcctTotalNumUint, StackUint64, 8, "The total number of uint64 values allocated by this account in Global and Local States."},
	{AcctTotalNumByteSlice, StackUint64, 8, "The total number of byte array values allocated by this account in Global and Local States."},
	{AcctTotalExtraAppPages, StackUint64, 8, "The number of extra app code pages used by this account."},
	{AcctTotalAppsCreated, StackUint64, 8, "The number of existing apps created by this account."},
	{AcctTotalAppsOptedIn, StackUint64, 8, "The number of apps this account is opted into."},
	{AcctTotalAssetsCreated, StackUint64, 8, "The number of existing ASAs created by this account."},
	{AcctTotalAssets, StackUint64, 8, "The numbers of ASAs held by this account (including ASAs this account created)."},
	{AcctTotalBoxes, StackUint64, boxVersion, "The number of existing boxes created by this account's app."},
	{AcctTotalBoxBytes, StackUint64, boxVersion, "The total number of bytes used by this account's app's box keys and values."},

	{AcctIncentiveEligible, StackBoolean, incentiveVersion, "Has this account opted into block payouts"},
	{AcctLastProposed, StackUint64, incentiveVersion, "The round number of the last block this account proposed."},
	{AcctLastHeartbeat, StackUint64, incentiveVersion, "The round number of the last block this account sent a heartbeat."},
}

func acctParamsFieldSpecByField(f AcctParamsField) (acctParamsFieldSpec, bool) {
	if int(f) >= len(acctParamsFieldSpecs) {
		return acctParamsFieldSpec{}, false
	}
	return acctParamsFieldSpecs[f], true
}

var acctParamsFieldSpecByName = make(acctNameSpecMap, len(acctParamsFieldNames))

type acctNameSpecMap map[string]acctParamsFieldSpec

func (s acctNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// AcctParamsFields describes acct_params_get's immediates
var AcctParamsFields = FieldGroup{
	"acct_params", "Fields",
	acctParamsFieldNames[:],
	acctParamsFieldSpecByName,
}

// VoterParamsField is an enum for `voter_params_get` opcode
type VoterParamsField int

const (
	// VoterBalance is the balance, with pending rewards, from the balance
	// round.  It is 0 if the account was offline then.
	VoterBalance VoterParamsField = iota

	// expose voter keys?

	// VoterIncentiveEligible is whether this account opted into block payouts
	// by paying extra in `keyreg`. Does not reflect eligibility based on
	// balance. The value is returned for the balance round and is _false_ if
	// the account was offline then.
	VoterIncentiveEligible

	invalidVoterParamsField // compile-time constant for number of fields
)

var voterParamsFieldNames [invalidVoterParamsField]string

type voterParamsFieldSpec struct {
	field   VoterParamsField
	ftype   StackType
	version uint64
	doc     string
}

func (fs voterParamsFieldSpec) Field() byte {
	return byte(fs.field)
}
func (fs voterParamsFieldSpec) Type() StackType {
	return fs.ftype
}
func (fs voterParamsFieldSpec) OpVersion() uint64 {
	return incentiveVersion
}
func (fs voterParamsFieldSpec) Version() uint64 {
	return fs.version
}
func (fs voterParamsFieldSpec) Note() string {
	return fs.doc
}

var voterParamsFieldSpecs = [...]voterParamsFieldSpec{
	{VoterBalance, StackUint64, incentiveVersion, "Online stake in microalgos"},
	{VoterIncentiveEligible, StackBoolean, incentiveVersion, "Had this account opted into block payouts"},
}

func voterParamsFieldSpecByField(f VoterParamsField) (voterParamsFieldSpec, bool) {
	if int(f) >= len(voterParamsFieldSpecs) {
		return voterParamsFieldSpec{}, false
	}
	return voterParamsFieldSpecs[f], true
}

var voterParamsFieldSpecByName = make(voterNameSpecMap, len(voterParamsFieldNames))

type voterNameSpecMap map[string]voterParamsFieldSpec

func (s voterNameSpecMap) get(name string) (FieldSpec, bool) {
	fs, ok := s[name]
	return fs, ok
}

// VoterParamsFields describes voter_params_get's immediates
var VoterParamsFields = FieldGroup{
	"voter_params", "Fields",
	voterParamsFieldNames[:],
	voterParamsFieldSpecByName,
}

func init() {
	equal := func(x int, y int) {
		if x != y {
			panic(fmt.Sprintf("%d != %d", x, y))
		}
	}

	equal(len(txnFieldSpecs), len(TxnFieldNames))
	for i, s := range txnFieldSpecs {
		equal(int(s.field), i)
		TxnFieldNames[s.field] = s.field.String()
		txnFieldSpecByName[s.field.String()] = s
	}

	equal(len(globalFieldSpecs), len(GlobalFieldNames))
	for i, s := range globalFieldSpecs {
		equal(int(s.field), i)
		GlobalFieldNames[s.field] = s.field.String()
		globalFieldSpecByName[s.field.String()] = s
	}

	equal(len(ecdsaCurveSpecs), len(ecdsaCurveNames))
	for i, s := range ecdsaCurveSpecs {
		equal(int(s.field), i)
		ecdsaCurveNames[s.field] = s.field.String()
		ecdsaCurveSpecByName[s.field.String()] = s
	}

	equal(len(ecGroupSpecs), len(ecGroupNames))
	for i, s := range ecGroupSpecs {
		equal(int(s.field), i)
		ecGroupNames[s.field] = s.field.String()
		ecGroupSpecByName[s.field.String()] = s
	}

	equal(len(mimcConfigSpecs), len(mimcConfigNames))
	for i, s := range mimcConfigSpecs {
		equal(int(s.field), i)
		mimcConfigNames[s.field] = s.field.String()
		mimcConfigSpecByName[s.field.String()] = s
	}

	equal(len(base64EncodingSpecs), len(base64EncodingNames))
	for i, s := range base64EncodingSpecs {
		equal(int(s.field), i)
		base64EncodingNames[i] = s.field.String()
		base64EncodingSpecByName[s.field.String()] = s
	}

	equal(len(jsonRefSpecs), len(jsonRefTypeNames))
	for i, s := range jsonRefSpecs {
		equal(int(s.field), i)
		jsonRefTypeNames[i] = s.field.String()
		jsonRefSpecByName[s.field.String()] = s
	}

	equal(len(vrfStandardSpecs), len(vrfStandardNames))
	for i, s := range vrfStandardSpecs {
		equal(int(s.field), i)
		vrfStandardNames[i] = s.field.String()
		vrfStandardSpecByName[s.field.String()] = s
	}

	equal(len(blockFieldSpecs), len(blockFieldNames))
	for i, s := range blockFieldSpecs {
		equal(int(s.field), i)
		blockFieldNames[i] = s.field.String()
		blockFieldSpecByName[s.field.String()] = s
	}

	equal(len(assetHoldingFieldSpecs), len(assetHoldingFieldNames))
	for i, s := range assetHoldingFieldSpecs {
		equal(int(s.field), i)
		assetHoldingFieldNames[i] = s.field.String()
		assetHoldingFieldSpecByName[s.field.String()] = s
	}

	equal(len(assetParamsFieldSpecs), len(assetParamsFieldNames))
	for i, s := range assetParamsFieldSpecs {
		equal(int(s.field), i)
		assetParamsFieldNames[i] = s.field.String()
		assetParamsFieldSpecByName[s.field.String()] = s
	}

	equal(len(appParamsFieldSpecs), len(appParamsFieldNames))
	for i, s := range appParamsFieldSpecs {
		equal(int(s.field), i)
		appParamsFieldNames[i] = s.field.String()
		appParamsFieldSpecByName[s.field.String()] = s
	}

	equal(len(acctParamsFieldSpecs), len(acctParamsFieldNames))
	for i, s := range acctParamsFieldSpecs {
		equal(int(s.field), i)
		acctParamsFieldNames[i] = s.field.String()
		acctParamsFieldSpecByName[s.field.String()] = s
	}

	equal(len(voterParamsFieldSpecs), len(voterParamsFieldNames))
	for i, s := range voterParamsFieldSpecs {
		equal(int(s.field), i)
		voterParamsFieldNames[i] = s.field.String()
		voterParamsFieldSpecByName[s.field.String()] = s
	}

	txnTypeMap = make(map[string]uint64)
	for i, tt := range TxnTypeNames {
		txnTypeMap[tt] = uint64(i)
	}
	for k, v := range TypeNameDescriptions {
		txnTypeMap[v] = txnTypeMap[k]
	}

	onCompletionMap = make(map[string]uint64, len(OnCompletionNames))
	for oc := NoOp; oc < invalidOnCompletionConst; oc++ {
		symbol := oc.String()
		OnCompletionNames[oc] = symbol
		onCompletionMap[symbol] = uint64(oc)
	}

}
