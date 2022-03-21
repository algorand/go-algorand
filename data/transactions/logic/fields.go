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
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

//go:generate stringer -type=TxnField,GlobalField,AssetParamsField,AppParamsField,AcctParamsField,AssetHoldingField,OnCompletionConstType,EcdsaCurve,Base64Encoding,JSONRefType -output=fields_string.go

// TxnField is an enum type for `txn` and `gtxn`
type TxnField int

const (
	// Sender Transaction.Sender
	Sender TxnField = iota
	// Fee Transaction.Fee
	Fee
	// FirstValid Transaction.FirstValid
	FirstValid
	// FirstValidTime panic
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

	invalidTxnField // fence for some setup that loops from Sender..invalidTxnField
)

// FieldSpec unifies the various specs for presentation
type FieldSpec interface {
	Type() StackType
	OpVersion() uint64
	Note() string
	Version() uint64
}

// TxnFieldNames are arguments to the 'txn' and 'txnById' opcodes
var TxnFieldNames []string

var txnFieldSpecByField map[TxnField]txnFieldSpec

// TxnFieldSpecByName gives access to the field specs by field name
var TxnFieldSpecByName tfNameSpecMap

// simple interface used by doc generator for fields versioning
type tfNameSpecMap map[string]txnFieldSpec

func (s tfNameSpecMap) SpecByName(name string) FieldSpec {
	fs := s[name]
	return &fs
}

type txnFieldSpec struct {
	field      TxnField
	ftype      StackType
	array      bool   // Is this an array field?
	version    uint64 // When this field become available to txn/gtxn. 0=always
	itxVersion uint64 // When this field become available to itxn_field. 0=never
	effects    bool   // Is this a field on the "effects"? That is, something in ApplyData
}

func (fs *txnFieldSpec) Type() StackType {
	return fs.ftype
}

func (fs *txnFieldSpec) OpVersion() uint64 {
	return 0
}

func (fs *txnFieldSpec) Version() uint64 {
	return fs.version
}

func (fs *txnFieldSpec) Note() string {
	note := txnFieldDocs[fs.field.String()]
	if fs.effects {
		note = addExtra(note, "Application mode only")
	}
	return note
}

var txnFieldSpecs = []txnFieldSpec{
	{Sender, StackBytes, false, 0, 5, false},
	{Fee, StackUint64, false, 0, 5, false},
	{FirstValid, StackUint64, false, 0, 0, false},
	{FirstValidTime, StackUint64, false, 0, 0, false},
	{LastValid, StackUint64, false, 0, 0, false},
	{Note, StackBytes, false, 0, 6, false},
	{Lease, StackBytes, false, 0, 0, false},
	{Receiver, StackBytes, false, 0, 5, false},
	{Amount, StackUint64, false, 0, 5, false},
	{CloseRemainderTo, StackBytes, false, 0, 5, false},
	{VotePK, StackBytes, false, 0, 6, false},
	{SelectionPK, StackBytes, false, 0, 6, false},
	{VoteFirst, StackUint64, false, 0, 6, false},
	{VoteLast, StackUint64, false, 0, 6, false},
	{VoteKeyDilution, StackUint64, false, 0, 6, false},
	{Type, StackBytes, false, 0, 5, false},
	{TypeEnum, StackUint64, false, 0, 5, false},
	{XferAsset, StackUint64, false, 0, 5, false},
	{AssetAmount, StackUint64, false, 0, 5, false},
	{AssetSender, StackBytes, false, 0, 5, false},
	{AssetReceiver, StackBytes, false, 0, 5, false},
	{AssetCloseTo, StackBytes, false, 0, 5, false},
	{GroupIndex, StackUint64, false, 0, 0, false},
	{TxID, StackBytes, false, 0, 0, false},
	{ApplicationID, StackUint64, false, 2, 6, false},
	{OnCompletion, StackUint64, false, 2, 6, false},
	{ApplicationArgs, StackBytes, true, 2, 6, false},
	{NumAppArgs, StackUint64, false, 2, 0, false},
	{Accounts, StackBytes, true, 2, 6, false},
	{NumAccounts, StackUint64, false, 2, 0, false},
	{ApprovalProgram, StackBytes, false, 2, 6, false},
	{ClearStateProgram, StackBytes, false, 2, 6, false},
	{RekeyTo, StackBytes, false, 2, 6, false},
	{ConfigAsset, StackUint64, false, 2, 5, false},
	{ConfigAssetTotal, StackUint64, false, 2, 5, false},
	{ConfigAssetDecimals, StackUint64, false, 2, 5, false},
	{ConfigAssetDefaultFrozen, StackUint64, false, 2, 5, false},
	{ConfigAssetUnitName, StackBytes, false, 2, 5, false},
	{ConfigAssetName, StackBytes, false, 2, 5, false},
	{ConfigAssetURL, StackBytes, false, 2, 5, false},
	{ConfigAssetMetadataHash, StackBytes, false, 2, 5, false},
	{ConfigAssetManager, StackBytes, false, 2, 5, false},
	{ConfigAssetReserve, StackBytes, false, 2, 5, false},
	{ConfigAssetFreeze, StackBytes, false, 2, 5, false},
	{ConfigAssetClawback, StackBytes, false, 2, 5, false},
	{FreezeAsset, StackUint64, false, 2, 5, false},
	{FreezeAssetAccount, StackBytes, false, 2, 5, false},
	{FreezeAssetFrozen, StackUint64, false, 2, 5, false},
	{Assets, StackUint64, true, 3, 6, false},
	{NumAssets, StackUint64, false, 3, 0, false},
	{Applications, StackUint64, true, 3, 6, false},
	{NumApplications, StackUint64, false, 3, 0, false},
	{GlobalNumUint, StackUint64, false, 3, 6, false},
	{GlobalNumByteSlice, StackUint64, false, 3, 6, false},
	{LocalNumUint, StackUint64, false, 3, 6, false},
	{LocalNumByteSlice, StackUint64, false, 3, 6, false},
	{ExtraProgramPages, StackUint64, false, 4, 6, false},
	{Nonparticipation, StackUint64, false, 5, 6, false},

	// "Effects" Last two things are always going to: 0, true
	{Logs, StackBytes, true, 5, 0, true},
	{NumLogs, StackUint64, false, 5, 0, true},
	{CreatedAssetID, StackUint64, false, 5, 0, true},
	{CreatedApplicationID, StackUint64, false, 5, 0, true},
	{LastLog, StackBytes, false, 6, 0, true},
	{StateProofPK, StackBytes, false, 6, 6, false},
}

// TxnaFieldNames are arguments to the 'txna' opcode
// It need not be fast, as it's only used for doc generation.
func TxnaFieldNames() []string {
	var names []string
	for _, fs := range txnFieldSpecs {
		if fs.array {
			names = append(names, fs.field.String())
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
var TxnTypeNames = []string{
	string(protocol.UnknownTx),
	string(protocol.PaymentTx),
	string(protocol.KeyRegistrationTx),
	string(protocol.AssetConfigTx),
	string(protocol.AssetTransferTx),
	string(protocol.AssetFreezeTx),
	string(protocol.ApplicationCallTx),
}

// map TxnTypeName to its enum index, for `txn TypeEnum`
var txnTypeIndexes map[string]uint64

// map symbolic name to uint64 for assembleInt
var txnTypeConstToUint64 map[string]uint64

// OnCompletionConstType is the same as transactions.OnCompletion
type OnCompletionConstType transactions.OnCompletion

const (
	// NoOp = transactions.NoOpOC
	NoOp OnCompletionConstType = OnCompletionConstType(transactions.NoOpOC)
	// OptIn = transactions.OptInOC
	OptIn OnCompletionConstType = OnCompletionConstType(transactions.OptInOC)
	// CloseOut = transactions.CloseOutOC
	CloseOut OnCompletionConstType = OnCompletionConstType(transactions.CloseOutOC)
	// ClearState = transactions.ClearStateOC
	ClearState OnCompletionConstType = OnCompletionConstType(transactions.ClearStateOC)
	// UpdateApplication = transactions.UpdateApplicationOC
	UpdateApplication OnCompletionConstType = OnCompletionConstType(transactions.UpdateApplicationOC)
	// DeleteApplication = transactions.DeleteApplicationOC
	DeleteApplication OnCompletionConstType = OnCompletionConstType(transactions.DeleteApplicationOC)
	// end of constants
	invalidOnCompletionConst OnCompletionConstType = DeleteApplication + 1
)

// OnCompletionNames is the string names of Txn.OnCompletion, array index is the const value
var OnCompletionNames []string

// onCompletionConstToUint64 map symbolic name to uint64 for assembleInt
var onCompletionConstToUint64 map[string]uint64

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

	invalidGlobalField
)

// GlobalFieldNames are arguments to the 'global' opcode
var GlobalFieldNames []string

type globalFieldSpec struct {
	field   GlobalField
	ftype   StackType
	mode    runMode
	version uint64
}

func (fs *globalFieldSpec) Type() StackType {
	return fs.ftype
}

func (fs *globalFieldSpec) OpVersion() uint64 {
	return 0
}

func (fs *globalFieldSpec) Version() uint64 {
	return fs.version
}
func (fs *globalFieldSpec) Note() string {
	note := globalFieldDocs[fs.field.String()]
	if fs.mode == runModeApplication {
		note = addExtra(note, "Application mode only.")
	}
	// There are no Signature mode only globals
	return note
}

var globalFieldSpecs = []globalFieldSpec{
	{MinTxnFee, StackUint64, modeAny, 0}, // version 0 is the same as TEAL v1 (initial TEAL release)
	{MinBalance, StackUint64, modeAny, 0},
	{MaxTxnLife, StackUint64, modeAny, 0},
	{ZeroAddress, StackBytes, modeAny, 0},
	{GroupSize, StackUint64, modeAny, 0},
	{LogicSigVersion, StackUint64, modeAny, 2},
	{Round, StackUint64, runModeApplication, 2},
	{LatestTimestamp, StackUint64, runModeApplication, 2},
	{CurrentApplicationID, StackUint64, runModeApplication, 2},
	{CreatorAddress, StackBytes, runModeApplication, 3},
	{CurrentApplicationAddress, StackBytes, runModeApplication, 5},
	{GroupID, StackBytes, modeAny, 5},
	{OpcodeBudget, StackUint64, modeAny, 6},
	{CallerApplicationID, StackUint64, runModeApplication, 6},
	{CallerApplicationAddress, StackBytes, runModeApplication, 6},
}

var globalFieldSpecByField map[GlobalField]globalFieldSpec

// GlobalFieldSpecByName gives access to the field specs by field name
var GlobalFieldSpecByName gfNameSpecMap

type gfNameSpecMap map[string]globalFieldSpec

func (s gfNameSpecMap) SpecByName(name string) FieldSpec {
	fs := s[name]
	return &fs
}

// EcdsaCurve is an enum for `ecdsa_` opcodes
type EcdsaCurve int

const (
	// Secp256k1 curve for bitcoin/ethereum
	Secp256k1 EcdsaCurve = iota
	// Secp256r1 curve
	Secp256r1
	invalidEcdsaCurve
)

// EcdsaCurveNames are arguments to the 'ecdsa_' opcode
var EcdsaCurveNames []string

type ecdsaCurveSpec struct {
	field   EcdsaCurve
	version uint64
}

func (fs *ecdsaCurveSpec) Type() StackType {
	return StackNone // Will not show, since all are the same
}

func (fs *ecdsaCurveSpec) OpVersion() uint64 {
	return 5
}

func (fs *ecdsaCurveSpec) Version() uint64 {
	return fs.version
}

func (fs *ecdsaCurveSpec) Note() string {
	note := EcdsaCurveDocs[fs.field.String()]
	return note
}

var ecdsaCurveSpecs = []ecdsaCurveSpec{
	{Secp256k1, 5},
	{Secp256r1, fidoVersion},
}

var ecdsaCurveSpecByField map[EcdsaCurve]ecdsaCurveSpec

// EcdsaCurveSpecByName gives access to the field specs by field name
var EcdsaCurveSpecByName ecDsaCurveNameSpecMap

// simple interface used by doc generator for fields versioning
type ecDsaCurveNameSpecMap map[string]ecdsaCurveSpec

func (s ecDsaCurveNameSpecMap) SpecByName(name string) FieldSpec {
	fs := s[name]
	return &fs
}

// Base64Encoding is an enum for the `base64decode` opcode
type Base64Encoding int

const (
	// URLEncoding represents the base64url encoding defined in https://www.rfc-editor.org/rfc/rfc4648.html
	URLEncoding Base64Encoding = iota
	// StdEncoding represents the standard encoding of the RFC
	StdEncoding
	invalidBase64Alphabet
)

// After running `go generate` these strings will be available:
var base64EncodingNames [2]string = [...]string{URLEncoding.String(), StdEncoding.String()}

type base64EncodingSpec struct {
	field   Base64Encoding
	ftype   StackType
	version uint64
}

var base64EncodingSpecs = []base64EncodingSpec{
	{URLEncoding, StackBytes, 6},
	{StdEncoding, StackBytes, 6},
}

var base64EncodingSpecByField map[Base64Encoding]base64EncodingSpec
var base64EncodingSpecByName base64EncodingSpecMap

type base64EncodingSpecMap map[string]base64EncodingSpec

func (fs *base64EncodingSpec) Type() StackType {
	return fs.ftype
}

func (fs *base64EncodingSpec) OpVersion() uint64 {
	return 6
}

func (fs *base64EncodingSpec) Version() uint64 {
	return fs.version
}

func (fs *base64EncodingSpec) Note() string {
	note := "" // no doc list?
	return note
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
	invalidJSONRefType
)

// After running `go generate` these strings will be available:
var jsonRefTypeNames [3]string = [...]string{JSONString.String(), JSONUint64.String(), JSONObject.String()}

type jsonRefSpec struct {
	field   JSONRefType
	ftype   StackType
	version uint64
}

var jsonRefSpecs = []jsonRefSpec{
	{JSONString, StackBytes, fidoVersion},
	{JSONUint64, StackUint64, fidoVersion},
	{JSONObject, StackBytes, fidoVersion},
}

var jsonRefSpecByField map[JSONRefType]jsonRefSpec
var jsonRefSpecByName jsonRefSpecMap

type jsonRefSpecMap map[string]jsonRefSpec

// AssetHoldingField is an enum for `asset_holding_get` opcode
type AssetHoldingField int

const (
	// AssetBalance AssetHolding.Amount
	AssetBalance AssetHoldingField = iota
	// AssetFrozen AssetHolding.Frozen
	AssetFrozen
	invalidAssetHoldingField
)

// AssetHoldingFieldNames are arguments to the 'asset_holding_get' opcode
var AssetHoldingFieldNames []string

type assetHoldingFieldSpec struct {
	field   AssetHoldingField
	ftype   StackType
	version uint64
}

func (fs *assetHoldingFieldSpec) Type() StackType {
	return fs.ftype
}

func (fs *assetHoldingFieldSpec) OpVersion() uint64 {
	return 2
}

func (fs *assetHoldingFieldSpec) Version() uint64 {
	return fs.version
}

func (fs *assetHoldingFieldSpec) Note() string {
	note := assetHoldingFieldDocs[fs.field.String()]
	return note
}

var assetHoldingFieldSpecs = []assetHoldingFieldSpec{
	{AssetBalance, StackUint64, 2},
	{AssetFrozen, StackUint64, 2},
}

var assetHoldingFieldSpecByField map[AssetHoldingField]assetHoldingFieldSpec

// AssetHoldingFieldSpecByName gives access to the field specs by field name
var AssetHoldingFieldSpecByName ahfNameSpecMap

type ahfNameSpecMap map[string]assetHoldingFieldSpec

func (s ahfNameSpecMap) SpecByName(name string) FieldSpec {
	fs := s[name]
	return &fs
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

	invalidAssetParamsField
)

// AssetParamsFieldNames are arguments to the 'asset_params_get' opcode
var AssetParamsFieldNames []string

type assetParamsFieldSpec struct {
	field   AssetParamsField
	ftype   StackType
	version uint64
}

func (fs *assetParamsFieldSpec) Type() StackType {
	return fs.ftype
}

func (fs *assetParamsFieldSpec) OpVersion() uint64 {
	return 2
}

func (fs *assetParamsFieldSpec) Version() uint64 {
	return fs.version
}

func (fs *assetParamsFieldSpec) Note() string {
	note := assetParamsFieldDocs[fs.field.String()]
	return note
}

var assetParamsFieldSpecs = []assetParamsFieldSpec{
	{AssetTotal, StackUint64, 2},
	{AssetDecimals, StackUint64, 2},
	{AssetDefaultFrozen, StackUint64, 2},
	{AssetUnitName, StackBytes, 2},
	{AssetName, StackBytes, 2},
	{AssetURL, StackBytes, 2},
	{AssetMetadataHash, StackBytes, 2},
	{AssetManager, StackBytes, 2},
	{AssetReserve, StackBytes, 2},
	{AssetFreeze, StackBytes, 2},
	{AssetClawback, StackBytes, 2},
	{AssetCreator, StackBytes, 5},
}

var assetParamsFieldSpecByField map[AssetParamsField]assetParamsFieldSpec

// AssetParamsFieldSpecByName gives access to the field specs by field name
var AssetParamsFieldSpecByName apfNameSpecMap

type apfNameSpecMap map[string]assetParamsFieldSpec

func (s apfNameSpecMap) SpecByName(name string) FieldSpec {
	fs := s[name]
	return &fs
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

	invalidAppParamsField
)

// AppParamsFieldNames are arguments to the 'app_params_get' opcode
var AppParamsFieldNames []string

type appParamsFieldSpec struct {
	field   AppParamsField
	ftype   StackType
	version uint64
}

func (fs *appParamsFieldSpec) Type() StackType {
	return fs.ftype
}

func (fs *appParamsFieldSpec) OpVersion() uint64 {
	return 5
}

func (fs *appParamsFieldSpec) Version() uint64 {
	return fs.version
}

func (fs *appParamsFieldSpec) Note() string {
	note := appParamsFieldDocs[fs.field.String()]
	return note
}

var appParamsFieldSpecs = []appParamsFieldSpec{
	{AppApprovalProgram, StackBytes, 5},
	{AppClearStateProgram, StackBytes, 5},
	{AppGlobalNumUint, StackUint64, 5},
	{AppGlobalNumByteSlice, StackUint64, 5},
	{AppLocalNumUint, StackUint64, 5},
	{AppLocalNumByteSlice, StackUint64, 5},
	{AppExtraProgramPages, StackUint64, 5},
	{AppCreator, StackBytes, 5},
	{AppAddress, StackBytes, 5},
}

var appParamsFieldSpecByField map[AppParamsField]appParamsFieldSpec

// AppParamsFieldSpecByName gives access to the field specs by field name
var AppParamsFieldSpecByName appNameSpecMap

// simple interface used by doc generator for fields versioning
type appNameSpecMap map[string]appParamsFieldSpec

func (s appNameSpecMap) SpecByName(name string) FieldSpec {
	fs := s[name]
	return &fs
}

// AcctParamsField is an enum for `acct_params_get` opcode
type AcctParamsField int

const (
	// AcctBalance is the blance, with pending rewards
	AcctBalance AcctParamsField = iota
	// AcctMinBalance is algos needed for this accounts apps and assets
	AcctMinBalance
	//AcctAuthAddr is the rekeyed address if any, else ZeroAddress
	AcctAuthAddr

	invalidAcctParamsField
)

// AcctParamsFieldNames are arguments to the 'acct_params_get' opcode
var AcctParamsFieldNames []string

type acctParamsFieldSpec struct {
	field   AcctParamsField
	ftype   StackType
	version uint64
}

func (fs *acctParamsFieldSpec) Type() StackType {
	return fs.ftype
}

func (fs *acctParamsFieldSpec) OpVersion() uint64 {
	return 6
}

func (fs *acctParamsFieldSpec) Version() uint64 {
	return fs.version
}

func (fs *acctParamsFieldSpec) Note() string {
	note := acctParamsFieldDocs[fs.field.String()]
	return note
}

var acctParamsFieldSpecs = []acctParamsFieldSpec{
	{AcctBalance, StackUint64, 6},
	{AcctMinBalance, StackUint64, 6},
	{AcctAuthAddr, StackBytes, 6},
}

var acctParamsFieldSpecByField map[AcctParamsField]acctParamsFieldSpec

// AcctParamsFieldSpecByName gives access to the field specs by field name
var AcctParamsFieldSpecByName acctNameSpecMap

// simple interface used by doc generator for fields versioning
type acctNameSpecMap map[string]acctParamsFieldSpec

func (s acctNameSpecMap) SpecByName(name string) FieldSpec {
	fs := s[name]
	return &fs
}

func init() {
	TxnFieldNames = make([]string, int(invalidTxnField))
	for fi := Sender; fi < invalidTxnField; fi++ {
		TxnFieldNames[fi] = fi.String()
	}
	txnFieldSpecByField = make(map[TxnField]txnFieldSpec, len(TxnFieldNames))
	for i, s := range txnFieldSpecs {
		if int(s.field) != i {
			panic("txnFieldSpecs disjoint with TxnField enum")
		}
		txnFieldSpecByField[s.field] = s
	}
	TxnFieldSpecByName = make(map[string]txnFieldSpec, len(TxnFieldNames))
	for i, tfn := range TxnFieldNames {
		TxnFieldSpecByName[tfn] = txnFieldSpecByField[TxnField(i)]
	}

	GlobalFieldNames = make([]string, int(invalidGlobalField))
	for i := MinTxnFee; i < invalidGlobalField; i++ {
		GlobalFieldNames[i] = i.String()
	}
	globalFieldSpecByField = make(map[GlobalField]globalFieldSpec, len(GlobalFieldNames))
	for i, s := range globalFieldSpecs {
		if int(s.field) != i {
			panic("globalFieldSpecs disjoint with GlobalField enum")
		}
		globalFieldSpecByField[s.field] = s
	}
	GlobalFieldSpecByName = make(gfNameSpecMap, len(GlobalFieldNames))
	for i, gfn := range GlobalFieldNames {
		GlobalFieldSpecByName[gfn] = globalFieldSpecByField[GlobalField(i)]
	}

	EcdsaCurveNames = make([]string, int(invalidEcdsaCurve))
	for i := Secp256k1; i < invalidEcdsaCurve; i++ {
		EcdsaCurveNames[i] = i.String()
	}
	ecdsaCurveSpecByField = make(map[EcdsaCurve]ecdsaCurveSpec, len(EcdsaCurveNames))
	for _, s := range ecdsaCurveSpecs {
		ecdsaCurveSpecByField[s.field] = s
	}

	EcdsaCurveSpecByName = make(ecDsaCurveNameSpecMap, len(EcdsaCurveNames))
	for i, ahfn := range EcdsaCurveNames {
		EcdsaCurveSpecByName[ahfn] = ecdsaCurveSpecByField[EcdsaCurve(i)]
	}

	base64EncodingSpecByField = make(map[Base64Encoding]base64EncodingSpec, len(base64EncodingNames))
	for _, s := range base64EncodingSpecs {
		base64EncodingSpecByField[s.field] = s
	}

	base64EncodingSpecByName = make(base64EncodingSpecMap, len(base64EncodingNames))
	for i, encoding := range base64EncodingNames {
		base64EncodingSpecByName[encoding] = base64EncodingSpecByField[Base64Encoding(i)]
	}

	base64EncodingSpecByField = make(map[Base64Encoding]base64EncodingSpec, len(base64EncodingNames))
	for _, s := range base64EncodingSpecs {
		base64EncodingSpecByField[s.field] = s
	}

	base64EncodingSpecByName = make(base64EncodingSpecMap, len(base64EncodingNames))
	for i, encoding := range base64EncodingNames {
		base64EncodingSpecByName[encoding] = base64EncodingSpecByField[Base64Encoding(i)]
	}

	jsonRefSpecByField = make(map[JSONRefType]jsonRefSpec, len(jsonRefTypeNames))
	for _, s := range jsonRefSpecs {
		jsonRefSpecByField[s.field] = s
	}

	jsonRefSpecByName = make(jsonRefSpecMap, len(jsonRefTypeNames))
	for i, typename := range jsonRefTypeNames {
		jsonRefSpecByName[typename] = jsonRefSpecByField[JSONRefType(i)]
	}

	AssetHoldingFieldNames = make([]string, int(invalidAssetHoldingField))
	for i := AssetBalance; i < invalidAssetHoldingField; i++ {
		AssetHoldingFieldNames[i] = i.String()
	}
	assetHoldingFieldSpecByField = make(map[AssetHoldingField]assetHoldingFieldSpec, len(AssetHoldingFieldNames))
	for _, s := range assetHoldingFieldSpecs {
		assetHoldingFieldSpecByField[s.field] = s
	}
	AssetHoldingFieldSpecByName = make(ahfNameSpecMap, len(AssetHoldingFieldNames))
	for i, ahfn := range AssetHoldingFieldNames {
		AssetHoldingFieldSpecByName[ahfn] = assetHoldingFieldSpecByField[AssetHoldingField(i)]
	}

	AssetParamsFieldNames = make([]string, int(invalidAssetParamsField))
	for i := AssetTotal; i < invalidAssetParamsField; i++ {
		AssetParamsFieldNames[i] = i.String()
	}
	assetParamsFieldSpecByField = make(map[AssetParamsField]assetParamsFieldSpec, len(AssetParamsFieldNames))
	for _, s := range assetParamsFieldSpecs {
		assetParamsFieldSpecByField[s.field] = s
	}
	AssetParamsFieldSpecByName = make(apfNameSpecMap, len(AssetParamsFieldNames))
	for i, apfn := range AssetParamsFieldNames {
		AssetParamsFieldSpecByName[apfn] = assetParamsFieldSpecByField[AssetParamsField(i)]
	}

	AppParamsFieldNames = make([]string, int(invalidAppParamsField))
	for i := AppApprovalProgram; i < invalidAppParamsField; i++ {
		AppParamsFieldNames[i] = i.String()
	}
	appParamsFieldSpecByField = make(map[AppParamsField]appParamsFieldSpec, len(AppParamsFieldNames))
	for _, s := range appParamsFieldSpecs {
		appParamsFieldSpecByField[s.field] = s
	}
	AppParamsFieldSpecByName = make(appNameSpecMap, len(AppParamsFieldNames))
	for i, apfn := range AppParamsFieldNames {
		AppParamsFieldSpecByName[apfn] = appParamsFieldSpecByField[AppParamsField(i)]
	}

	AcctParamsFieldNames = make([]string, int(invalidAcctParamsField))
	for i := AcctBalance; i < invalidAcctParamsField; i++ {
		AcctParamsFieldNames[i] = i.String()
	}
	acctParamsFieldSpecByField = make(map[AcctParamsField]acctParamsFieldSpec, len(AcctParamsFieldNames))
	for _, s := range acctParamsFieldSpecs {
		acctParamsFieldSpecByField[s.field] = s
	}
	AcctParamsFieldSpecByName = make(acctNameSpecMap, len(AcctParamsFieldNames))
	for i, apfn := range AcctParamsFieldNames {
		AcctParamsFieldSpecByName[apfn] = acctParamsFieldSpecByField[AcctParamsField(i)]
	}

	txnTypeIndexes = make(map[string]uint64, len(TxnTypeNames))
	for i, tt := range TxnTypeNames {
		txnTypeIndexes[tt] = uint64(i)
	}

	txnTypeConstToUint64 = make(map[string]uint64, len(TxnTypeNames))
	for tt, v := range txnTypeIndexes {
		symbol := TypeNameDescriptions[tt]
		txnTypeConstToUint64[symbol] = v
	}

	OnCompletionNames = make([]string, int(invalidOnCompletionConst))
	onCompletionConstToUint64 = make(map[string]uint64, len(OnCompletionNames))
	for oc := NoOp; oc < invalidOnCompletionConst; oc++ {
		symbol := oc.String()
		OnCompletionNames[oc] = symbol
		onCompletionConstToUint64[symbol] = uint64(oc)
	}
}
