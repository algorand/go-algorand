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

	invalidTxnField // compile-time constant for number of fields
)

// FieldSpec unifies the various specs for presentation
type FieldSpec interface {
	Field() byte
	Type() StackType
	OpVersion() uint64
	Note() string
	Version() uint64
}

// FieldSpecMap is something that yields a FieldSpec, given a name for the field
type FieldSpecMap interface {
	SpecByName(name string) FieldSpec
}

// FieldGroup binds all the info for a field (names, int value, spec access) so
// they can be attached to opcodes and used by doc generation
type FieldGroup struct {
	Name  string
	Names []string
	Specs FieldSpecMap
}

// TxnFieldNames are arguments to the 'txn' family of opcodes.
var TxnFieldNames [invalidTxnField]string

func txnFieldSpecByField(f TxnField) (txnFieldSpec, bool) {
	if int(f) >= len(txnFieldSpecs) {
		return txnFieldSpec{}, false
	}
	return txnFieldSpecs[f], true
}

// TxnFieldSpecByName gives access to the field specs by field name
var TxnFieldSpecByName tfNameSpecMap = make(map[string]txnFieldSpec, len(TxnFieldNames))

// simple interface used by doc generator for fields versioning
type tfNameSpecMap map[string]txnFieldSpec

func (s tfNameSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
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
	{Sender, StackBytes, false, 0, 5, false, "32 byte address"},
	{Fee, StackUint64, false, 0, 5, false, "microalgos"},
	{FirstValid, StackUint64, false, 0, 0, false, "round number"},
	{FirstValidTime, StackUint64, false, 0, 0, false, "Causes program to fail; reserved for future use"},
	{LastValid, StackUint64, false, 0, 0, false, "round number"},
	{Note, StackBytes, false, 0, 6, false, "Any data up to 1024 bytes"},
	{Lease, StackBytes, false, 0, 0, false, "32 byte lease value"},
	{Receiver, StackBytes, false, 0, 5, false, "32 byte address"},
	{Amount, StackUint64, false, 0, 5, false, "microalgos"},
	{CloseRemainderTo, StackBytes, false, 0, 5, false, "32 byte address"},
	{VotePK, StackBytes, false, 0, 6, false, "32 byte address"},
	{SelectionPK, StackBytes, false, 0, 6, false, "32 byte address"},
	{VoteFirst, StackUint64, false, 0, 6, false, "The first round that the participation key is valid."},
	{VoteLast, StackUint64, false, 0, 6, false, "The last round that the participation key is valid."},
	{VoteKeyDilution, StackUint64, false, 0, 6, false, "Dilution for the 2-level participation key"},
	{Type, StackBytes, false, 0, 5, false, "Transaction type as bytes"},
	{TypeEnum, StackUint64, false, 0, 5, false, "See table below"},
	{XferAsset, StackUint64, false, 0, 5, false, "Asset ID"},
	{AssetAmount, StackUint64, false, 0, 5, false, "value in Asset's units"},
	{AssetSender, StackBytes, false, 0, 5, false,
		"32 byte address. Moves asset from AssetSender if Sender is the Clawback address of the asset."},
	{AssetReceiver, StackBytes, false, 0, 5, false, "32 byte address"},
	{AssetCloseTo, StackBytes, false, 0, 5, false, "32 byte address"},
	{GroupIndex, StackUint64, false, 0, 0, false,
		"Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1"},
	{TxID, StackBytes, false, 0, 0, false, "The computed ID for this transaction. 32 bytes."},
	{ApplicationID, StackUint64, false, 2, 6, false, "ApplicationID from ApplicationCall transaction"},
	{OnCompletion, StackUint64, false, 2, 6, false, "ApplicationCall transaction on completion action"},
	{ApplicationArgs, StackBytes, true, 2, 6, false,
		"Arguments passed to the application in the ApplicationCall transaction"},
	{NumAppArgs, StackUint64, false, 2, 0, false, "Number of ApplicationArgs"},
	{Accounts, StackBytes, true, 2, 6, false, "Accounts listed in the ApplicationCall transaction"},
	{NumAccounts, StackUint64, false, 2, 0, false, "Number of Accounts"},
	{ApprovalProgram, StackBytes, false, 2, 6, false, "Approval program"},
	{ClearStateProgram, StackBytes, false, 2, 6, false, "Clear state program"},
	{RekeyTo, StackBytes, false, 2, 6, false, "32 byte Sender's new AuthAddr"},
	{ConfigAsset, StackUint64, false, 2, 5, false, "Asset ID in asset config transaction"},
	{ConfigAssetTotal, StackUint64, false, 2, 5, false, "Total number of units of this asset created"},
	{ConfigAssetDecimals, StackUint64, false, 2, 5, false,
		"Number of digits to display after the decimal place when displaying the asset"},
	{ConfigAssetDefaultFrozen, StackUint64, false, 2, 5, false,
		"Whether the asset's slots are frozen by default or not, 0 or 1"},
	{ConfigAssetUnitName, StackBytes, false, 2, 5, false, "Unit name of the asset"},
	{ConfigAssetName, StackBytes, false, 2, 5, false, "The asset name"},
	{ConfigAssetURL, StackBytes, false, 2, 5, false, "URL"},
	{ConfigAssetMetadataHash, StackBytes, false, 2, 5, false,
		"32 byte commitment to unspecified asset metadata"},
	{ConfigAssetManager, StackBytes, false, 2, 5, false, "32 byte address"},
	{ConfigAssetReserve, StackBytes, false, 2, 5, false, "32 byte address"},
	{ConfigAssetFreeze, StackBytes, false, 2, 5, false, "32 byte address"},
	{ConfigAssetClawback, StackBytes, false, 2, 5, false, "32 byte address"},
	{FreezeAsset, StackUint64, false, 2, 5, false, "Asset ID being frozen or un-frozen"},
	{FreezeAssetAccount, StackBytes, false, 2, 5, false,
		"32 byte address of the account whose asset slot is being frozen or un-frozen"},
	{FreezeAssetFrozen, StackUint64, false, 2, 5, false, "The new frozen value, 0 or 1"},
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
	{Nonparticipation, StackUint64, false, 5, 6, false, "Marks an account nonparticipating for rewards"},

	// "Effects" Last two things are always going to: 0, true
	{Logs, StackBytes, true, 5, 0, true, "Log messages emitted by an application call (only with `itxn` in v5)"},
	{NumLogs, StackUint64, false, 5, 0, true, "Number of Logs (only with `itxn` in v5)"},
	{CreatedAssetID, StackUint64, false, 5, 0, true,
		"Asset ID allocated by the creation of an ASA (only with `itxn` in v5)"},
	{CreatedApplicationID, StackUint64, false, 5, 0, true,
		"ApplicationID allocated by the creation of an application (only with `itxn` in v5)"},
	{LastLog, StackBytes, false, 6, 0, true, "The last message emitted. Empty bytes if none were emitted"},

	// Not an effect. Just added after the effects fields.
	{StateProofPK, StackBytes, false, 6, 6, false, "64 byte state proof public key commitment"},
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

var txnFields = FieldGroup{
	"txn",
	TxnFieldNames[:],
	TxnFieldSpecByName,
}

/*
var txnaFields = FieldGroup{
	"txna",
	TxnaFieldNames(),
	TxnFieldSpecByName,
}
*/

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
var txnTypeMap map[string]uint64 = make(map[string]uint64)

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

	invalidGlobalField // compile-time constant for number of fields
)

// GlobalFieldNames are arguments to the 'global' opcode
var GlobalFieldNames [invalidGlobalField]string

type globalFieldSpec struct {
	field   GlobalField
	ftype   StackType
	mode    runMode
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
	if fs.mode == runModeApplication {
		note = addExtra(note, "Application mode only.")
	}
	// There are no Signature mode only globals
	return note
}

var globalFieldSpecs = [...]globalFieldSpec{
	// version 0 is the same as TEAL v1 (initial TEAL release)
	{MinTxnFee, StackUint64, modeAny, 0, "microalgos"},
	{MinBalance, StackUint64, modeAny, 0, "microalgos"},
	{MaxTxnLife, StackUint64, modeAny, 0, "rounds"},
	{ZeroAddress, StackBytes, modeAny, 0, "32 byte address of all zero bytes"},
	{GroupSize, StackUint64, modeAny, 0,
		"Number of transactions in this atomic transaction group. At least 1"},
	{LogicSigVersion, StackUint64, modeAny, 2, "Maximum supported version"},
	{Round, StackUint64, runModeApplication, 2, "Current round number"},
	{LatestTimestamp, StackUint64, runModeApplication, 2,
		"Last confirmed block UNIX timestamp. Fails if negative"},
	{CurrentApplicationID, StackUint64, runModeApplication, 2, "ID of current application executing"},
	{CreatorAddress, StackBytes, runModeApplication, 3,
		"Address of the creator of the current application"},
	{CurrentApplicationAddress, StackBytes, runModeApplication, 5,
		"Address that the current application controls"},
	{GroupID, StackBytes, modeAny, 5,
		"ID of the transaction group. 32 zero bytes if the transaction is not part of a group."},
	{OpcodeBudget, StackUint64, modeAny, 6,
		"The remaining cost that can be spent by opcodes in this program."},
	{CallerApplicationID, StackUint64, runModeApplication, 6,
		"The application ID of the application that called this application. 0 if this application is at the top-level."},
	{CallerApplicationAddress, StackBytes, runModeApplication, 6,
		"The application address of the application that called this application. ZeroAddress if this application is at the top-level."},
}

func globalFieldSpecByField(f GlobalField) (globalFieldSpec, bool) {
	if int(f) >= len(globalFieldSpecs) {
		return globalFieldSpec{}, false
	}
	return globalFieldSpecs[f], true
}

// GlobalFieldSpecByName gives access to the field specs by field name
var GlobalFieldSpecByName gfNameSpecMap = make(gfNameSpecMap, len(GlobalFieldNames))

type gfNameSpecMap map[string]globalFieldSpec

func (s gfNameSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var globalFields = FieldGroup{
	"global",
	GlobalFieldNames[:],
	GlobalFieldSpecByName,
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

// EcdsaCurveNames are arguments to the 'ecdsa_' opcode
var EcdsaCurveNames [invalidEcdsaCurve]string

type ecdsaCurveSpec struct {
	field   EcdsaCurve
	version uint64
	doc     string
}

func (fs ecdsaCurveSpec) Field() byte {
	return byte(fs.field)
}

func (fs ecdsaCurveSpec) Type() StackType {
	return StackNone // Will not show, since all are the same
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

// EcdsaCurveSpecByName gives access to the field specs by field name
var EcdsaCurveSpecByName ecDsaCurveNameSpecMap = make(ecDsaCurveNameSpecMap, len(EcdsaCurveNames))

type ecDsaCurveNameSpecMap map[string]ecdsaCurveSpec

func (s ecDsaCurveNameSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var ecdsaCurves = FieldGroup{
	"ecdsa",
	EcdsaCurveNames[:],
	EcdsaCurveSpecByName,
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
	ftype   StackType
	version uint64
}

var base64EncodingSpecs = [...]base64EncodingSpec{
	{URLEncoding, StackBytes, 6},
	{StdEncoding, StackBytes, 6},
}

func base64EncodingSpecByField(e Base64Encoding) (base64EncodingSpec, bool) {
	if int(e) >= len(base64EncodingSpecs) {
		return base64EncodingSpec{}, false
	}
	return base64EncodingSpecs[e], true
}

var base64EncodingSpecByName base64EncodingSpecMap = make(base64EncodingSpecMap, len(base64EncodingNames))

type base64EncodingSpecMap map[string]base64EncodingSpec

func (fs base64EncodingSpec) Field() byte {
	return byte(fs.field)
}

func (fs base64EncodingSpec) Type() StackType {
	return fs.ftype
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

func (s base64EncodingSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var base64Encodings = FieldGroup{
	"base64",
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

// After running `go generate` these strings will be available:
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

var jsonRefSpecByName jsonRefSpecMap = make(jsonRefSpecMap, len(jsonRefTypeNames))

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

func (s jsonRefSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var jsonRefTypes = FieldGroup{
	"json_ref",
	jsonRefTypeNames[:],
	jsonRefSpecByName,
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

// AssetHoldingFieldNames are arguments to the 'asset_holding_get' opcode
var AssetHoldingFieldNames [invalidAssetHoldingField]string

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
	{AssetFrozen, StackUint64, 2, "Is the asset frozen or not"},
}

func assetHoldingFieldSpecByField(f AssetHoldingField) (assetHoldingFieldSpec, bool) {
	if int(f) >= len(assetHoldingFieldSpecs) {
		return assetHoldingFieldSpec{}, false
	}
	return assetHoldingFieldSpecs[f], true
}

// AssetHoldingFieldSpecByName gives access to the field specs by field name
var AssetHoldingFieldSpecByName ahfNameSpecMap = make(ahfNameSpecMap, len(AssetHoldingFieldNames))

type ahfNameSpecMap map[string]assetHoldingFieldSpec

func (s ahfNameSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var assetHoldingFields = FieldGroup{
	"asset_holding",
	AssetHoldingFieldNames[:],
	AssetHoldingFieldSpecByName,
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

// AssetParamsFieldNames are arguments to the 'asset_params_get' opcode
var AssetParamsFieldNames [invalidAssetParamsField]string

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
	{AssetDefaultFrozen, StackUint64, 2, "Frozen by default or not"},
	{AssetUnitName, StackBytes, 2, "Asset unit name"},
	{AssetName, StackBytes, 2, "Asset name"},
	{AssetURL, StackBytes, 2, "URL with additional info about the asset"},
	{AssetMetadataHash, StackBytes, 2, "Arbitrary commitment"},
	{AssetManager, StackBytes, 2, "Manager address"},
	{AssetReserve, StackBytes, 2, "Reserve address"},
	{AssetFreeze, StackBytes, 2, "Freeze address"},
	{AssetClawback, StackBytes, 2, "Clawback address"},
	{AssetCreator, StackBytes, 5, "Creator address"},
}

func assetParamsFieldSpecByField(f AssetParamsField) (assetParamsFieldSpec, bool) {
	if int(f) >= len(assetParamsFieldSpecs) {
		return assetParamsFieldSpec{}, false
	}
	return assetParamsFieldSpecs[f], true
}

// AssetParamsFieldSpecByName gives access to the field specs by field name
var AssetParamsFieldSpecByName apfNameSpecMap = make(apfNameSpecMap, len(AssetParamsFieldNames))

type apfNameSpecMap map[string]assetParamsFieldSpec

func (s apfNameSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var assetParamsFields = FieldGroup{
	"asset_params",
	AssetParamsFieldNames[:],
	AssetParamsFieldSpecByName,
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

	invalidAppParamsField // compile-time constant for number of fields
)

// AppParamsFieldNames are arguments to the 'app_params_get' opcode
var AppParamsFieldNames [invalidAppParamsField]string

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
	{AppCreator, StackBytes, 5, "Creator address"},
	{AppAddress, StackBytes, 5, "Address for which this application has authority"},
}

func appParamsFieldSpecByField(f AppParamsField) (appParamsFieldSpec, bool) {
	if int(f) >= len(appParamsFieldSpecs) {
		return appParamsFieldSpec{}, false
	}
	return appParamsFieldSpecs[f], true
}

// AppParamsFieldSpecByName gives access to the field specs by field name
var AppParamsFieldSpecByName appNameSpecMap = make(appNameSpecMap, len(AppParamsFieldNames))

// simple interface used by doc generator for fields versioning
type appNameSpecMap map[string]appParamsFieldSpec

func (s appNameSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var appParamsFields = FieldGroup{
	"app_params",
	AppParamsFieldNames[:],
	AppParamsFieldSpecByName,
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

	invalidAcctParamsField // compile-time constant for number of fields
)

// AcctParamsFieldNames are arguments to the 'acct_params_get' opcode
var AcctParamsFieldNames [invalidAcctParamsField]string

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
	{AcctMinBalance, StackUint64, 6, "Minimum required blance for account, in microalgos"},
	{AcctAuthAddr, StackBytes, 6, "Address the account is rekeyed to."},
}

func acctParamsFieldSpecByField(f AcctParamsField) (acctParamsFieldSpec, bool) {
	if int(f) >= len(acctParamsFieldSpecs) {
		return acctParamsFieldSpec{}, false
	}
	return acctParamsFieldSpecs[f], true
}

// AcctParamsFieldSpecByName gives access to the field specs by field name
var AcctParamsFieldSpecByName acctNameSpecMap = make(acctNameSpecMap, len(AcctParamsFieldNames))

// simple interface used by doc generator for fields versioning
type acctNameSpecMap map[string]acctParamsFieldSpec

func (s acctNameSpecMap) SpecByName(name string) FieldSpec {
	return s[name]
}

var acctParamsFields = FieldGroup{
	"acct_params",
	AcctParamsFieldNames[:],
	AcctParamsFieldSpecByName,
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
		TxnFieldSpecByName[s.field.String()] = s
	}

	equal(len(globalFieldSpecs), len(GlobalFieldNames))
	for i, s := range globalFieldSpecs {
		equal(int(s.field), i)
		GlobalFieldNames[s.field] = s.field.String()
		GlobalFieldSpecByName[s.field.String()] = s
	}

	equal(len(ecdsaCurveSpecs), len(EcdsaCurveNames))
	for i, s := range ecdsaCurveSpecs {
		equal(int(s.field), i)
		EcdsaCurveNames[s.field] = s.field.String()
		EcdsaCurveSpecByName[s.field.String()] = s
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

	equal(len(assetHoldingFieldSpecs), len(AssetHoldingFieldNames))
	for i, s := range assetHoldingFieldSpecs {
		equal(int(s.field), i)
		AssetHoldingFieldNames[i] = s.field.String()
		AssetHoldingFieldSpecByName[s.field.String()] = s
	}

	equal(len(assetParamsFieldSpecs), len(AssetParamsFieldNames))
	for i, s := range assetParamsFieldSpecs {
		equal(int(s.field), i)
		AssetParamsFieldNames[i] = s.field.String()
		AssetParamsFieldSpecByName[s.field.String()] = s
	}

	equal(len(appParamsFieldSpecs), len(AppParamsFieldNames))
	for i, s := range appParamsFieldSpecs {
		equal(int(s.field), i)
		AppParamsFieldNames[i] = s.field.String()
		AppParamsFieldSpecByName[s.field.String()] = s
	}

	equal(len(acctParamsFieldSpecs), len(AcctParamsFieldNames))
	for i, s := range acctParamsFieldSpecs {
		equal(int(s.field), i)
		AcctParamsFieldNames[i] = s.field.String()
		AcctParamsFieldSpecByName[s.field.String()] = s
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
