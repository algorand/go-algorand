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
	"fmt"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

//go:generate stringer -type=TxnField,GlobalField,AssetParamsField,AppParamsField,AssetHoldingField,OnCompletionConstType,EcdsaCurve,Base64Alphabet -output=fields_string.go

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

	invalidTxnField // fence for some setup that loops from Sender..invalidTxnField
)

// TxnFieldNames are arguments to the 'txn' and 'txnById' opcodes
var TxnFieldNames []string

// TxnFieldTypes is StackBytes or StackUint64 parallel to TxnFieldNames
var TxnFieldTypes []StackType

var txnFieldSpecByField map[TxnField]txnFieldSpec
var txnFieldSpecByName tfNameSpecMap

// simple interface used by doc generator for fields versioning
type tfNameSpecMap map[string]txnFieldSpec

func (s tfNameSpecMap) getExtraFor(name string) (extra string) {
	if s[name].version > 1 {
		extra = fmt.Sprintf("LogicSigVersion >= %d.", s[name].version)
	}
	return
}

type txnFieldSpec struct {
	field      TxnField
	ftype      StackType
	array      bool   // Is this an array field?
	version    uint64 // When this field become available to txn/gtxn. 0=always
	itxVersion uint64 // When this field become available to itxn_field. 0=never
	effects    bool   // Is this a field on the "effects"? That is, something in ApplyData
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

	{Logs, StackBytes, true, 5, 5, true},
	{NumLogs, StackUint64, false, 5, 5, true},
	{CreatedAssetID, StackUint64, false, 5, 5, true},
	{CreatedApplicationID, StackUint64, false, 5, 5, true},
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

// TxnaFieldTypes is StackBytes or StackUint64 parallel to TxnaFieldNames
func TxnaFieldTypes() []StackType {
	var types []StackType
	for _, fs := range txnFieldSpecs {
		if fs.array {
			types = append(types, fs.ftype)
		}
	}
	return types
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

// GlobalFieldTypes is StackUint64 StackBytes in parallel with GlobalFieldNames
var GlobalFieldTypes []StackType

type globalFieldSpec struct {
	field   GlobalField
	ftype   StackType
	mode    runMode
	version uint64
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
	{OpcodeBudget, StackUint64, runModeApplication, 6},
	{CallerApplicationID, StackUint64, runModeApplication, 6},
	{CallerApplicationAddress, StackBytes, runModeApplication, 6},
}

// GlobalFieldSpecByField maps GlobalField to spec
var globalFieldSpecByField map[GlobalField]globalFieldSpec
var globalFieldSpecByName gfNameSpecMap

// simple interface used by doc generator for fields versioning
type gfNameSpecMap map[string]globalFieldSpec

func (s gfNameSpecMap) getExtraFor(name string) (extra string) {
	if s[name].version > 1 {
		extra = fmt.Sprintf("LogicSigVersion >= %d.", s[name].version)
	}
	return
}

// EcdsaCurve is an enum for `ecdsa_` opcodes
type EcdsaCurve int

const (
	// Secp256k1 curve for bitcoin/ethereum
	Secp256k1 EcdsaCurve = iota
	invalidEcdsaCurve
)

// EcdsaCurveNames are arguments to the 'ecdsa_' opcode
var EcdsaCurveNames []string

type ecdsaCurveSpec struct {
	field   EcdsaCurve
	version uint64
}

var ecdsaCurveSpecs = []ecdsaCurveSpec{
	{Secp256k1, 5},
}

var ecdsaCurveSpecByField map[EcdsaCurve]ecdsaCurveSpec
var ecdsaCurveSpecByName ecDsaCurveNameSpecMap

// simple interface used by doc generator for fields versioning
type ecDsaCurveNameSpecMap map[string]ecdsaCurveSpec

func (s ecDsaCurveNameSpecMap) getExtraFor(name string) (extra string) {
	// Uses 5 here because ecdsa fields were introduced in 5
	if s[name].version > 5 {
		extra = fmt.Sprintf("LogicSigVersion >= %d.", s[name].version)
	}
	return
}

// Base64Alphabet is an enum for the `base64decode` opcode
type Base64Alphabet int

const (
	// URLAlph represents the base64url alphabet defined in https://www.rfc-editor.org/rfc/rfc4648.html
	URLAlph Base64Alphabet = iota
	// StdAlph represents the standard alphabet of the RFC
	StdAlph
	invalidBase64Alphabet
)

// After running `go generate` these strings will be available:
var base64AlphabetNames [2]string = [...]string{URLAlph.String(), StdAlph.String()}

type base64AlphabetSpec struct {
	field   Base64Alphabet
	ftype   StackType
	version uint64
}

var base64AlphbetSpecs = []base64AlphabetSpec{
	{URLAlph, StackBytes, 6},
	{StdAlph, StackBytes, 6},
}

var base64AlphabetSpecByField map[Base64Alphabet]base64AlphabetSpec
var base64AlphabetSpecByName base64AlphabetSpecMap

type base64AlphabetSpecMap map[string]base64AlphabetSpec

func (s base64AlphabetSpecMap) getExtraFor(name string) (extra string) {
	// Uses 6 here because base64_decode fields were introduced in 6
	if s[name].version > 6 {
		extra = fmt.Sprintf("LogicSigVersion >= %d.", s[name].version)
	}
	return
}

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

// AssetHoldingFieldTypes is StackUint64 StackBytes in parallel with AssetHoldingFieldNames
var AssetHoldingFieldTypes []StackType

type assetHoldingFieldSpec struct {
	field   AssetHoldingField
	ftype   StackType
	version uint64
}

var assetHoldingFieldSpecs = []assetHoldingFieldSpec{
	{AssetBalance, StackUint64, 2},
	{AssetFrozen, StackUint64, 2},
}

var assetHoldingFieldSpecByField map[AssetHoldingField]assetHoldingFieldSpec
var assetHoldingFieldSpecByName ahfNameSpecMap

// simple interface used by doc generator for fields versioning
type ahfNameSpecMap map[string]assetHoldingFieldSpec

func (s ahfNameSpecMap) getExtraFor(name string) (extra string) {
	// Uses 2 here because asset fields were introduced in 2
	if s[name].version > 2 {
		extra = fmt.Sprintf("LogicSigVersion >= %d.", s[name].version)
	}
	return
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

// AssetParamsFieldTypes is StackUint64 StackBytes in parallel with AssetParamsFieldNames
var AssetParamsFieldTypes []StackType

type assetParamsFieldSpec struct {
	field   AssetParamsField
	ftype   StackType
	version uint64
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
var assetParamsFieldSpecByName apfNameSpecMap

// simple interface used by doc generator for fields versioning
type apfNameSpecMap map[string]assetParamsFieldSpec

func (s apfNameSpecMap) getExtraFor(name string) (extra string) {
	// Uses 2 here because asset fields were introduced in 2
	if s[name].version > 2 {
		extra = fmt.Sprintf("LogicSigVersion >= %d.", s[name].version)
	}
	return
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

// AppParamsFieldTypes is StackUint64 StackBytes in parallel with AppParamsFieldNames
var AppParamsFieldTypes []StackType

type appParamsFieldSpec struct {
	field   AppParamsField
	ftype   StackType
	version uint64
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
var appParamsFieldSpecByName appNameSpecMap

// simple interface used by doc generator for fields versioning
type appNameSpecMap map[string]appParamsFieldSpec

func (s appNameSpecMap) getExtraFor(name string) (extra string) {
	// Uses 5 here because app fields were introduced in 5
	if s[name].version > 5 {
		extra = fmt.Sprintf("LogicSigVersion >= %d.", s[name].version)
	}
	return
}

func init() {
	TxnFieldNames = make([]string, int(invalidTxnField))
	for fi := Sender; fi < invalidTxnField; fi++ {
		TxnFieldNames[fi] = fi.String()
	}
	TxnFieldTypes = make([]StackType, int(invalidTxnField))
	txnFieldSpecByField = make(map[TxnField]txnFieldSpec, len(TxnFieldNames))
	for i, s := range txnFieldSpecs {
		if int(s.field) != i {
			panic("txnFieldSpecs disjoint with TxnField enum")
		}
		TxnFieldTypes[i] = s.ftype
		txnFieldSpecByField[s.field] = s
	}
	txnFieldSpecByName = make(tfNameSpecMap, len(TxnFieldNames))
	for i, tfn := range TxnFieldNames {
		txnFieldSpecByName[tfn] = txnFieldSpecByField[TxnField(i)]
	}

	GlobalFieldNames = make([]string, int(invalidGlobalField))
	for i := MinTxnFee; i < invalidGlobalField; i++ {
		GlobalFieldNames[int(i)] = i.String()
	}
	GlobalFieldTypes = make([]StackType, len(GlobalFieldNames))
	globalFieldSpecByField = make(map[GlobalField]globalFieldSpec, len(GlobalFieldNames))
	for i, s := range globalFieldSpecs {
		if int(s.field) != i {
			panic("globalFieldSpecs disjoint with GlobalField enum")
		}
		GlobalFieldTypes[i] = s.ftype
		globalFieldSpecByField[s.field] = s
	}
	globalFieldSpecByName = make(gfNameSpecMap, len(GlobalFieldNames))
	for i, gfn := range GlobalFieldNames {
		globalFieldSpecByName[gfn] = globalFieldSpecByField[GlobalField(i)]
	}

	EcdsaCurveNames = make([]string, int(invalidEcdsaCurve))
	for i := Secp256k1; i < invalidEcdsaCurve; i++ {
		EcdsaCurveNames[int(i)] = i.String()
	}
	ecdsaCurveSpecByField = make(map[EcdsaCurve]ecdsaCurveSpec, len(EcdsaCurveNames))
	for _, s := range ecdsaCurveSpecs {
		ecdsaCurveSpecByField[s.field] = s
	}

	ecdsaCurveSpecByName = make(ecDsaCurveNameSpecMap, len(EcdsaCurveNames))
	for i, ahfn := range EcdsaCurveNames {
		ecdsaCurveSpecByName[ahfn] = ecdsaCurveSpecByField[EcdsaCurve(i)]
	}

	base64AlphabetSpecByField = make(map[Base64Alphabet]base64AlphabetSpec, len(base64AlphabetNames))
	for _, s := range base64AlphbetSpecs {
		base64AlphabetSpecByField[s.field] = s
	}

	base64AlphabetSpecByName = make(base64AlphabetSpecMap, len(base64AlphabetNames))
	for i, alphname := range base64AlphabetNames {
		base64AlphabetSpecByName[alphname] = base64AlphabetSpecByField[Base64Alphabet(i)]
	}

	AssetHoldingFieldNames = make([]string, int(invalidAssetHoldingField))
	for i := AssetBalance; i < invalidAssetHoldingField; i++ {
		AssetHoldingFieldNames[int(i)] = i.String()
	}
	AssetHoldingFieldTypes = make([]StackType, len(AssetHoldingFieldNames))
	assetHoldingFieldSpecByField = make(map[AssetHoldingField]assetHoldingFieldSpec, len(AssetHoldingFieldNames))
	for _, s := range assetHoldingFieldSpecs {
		AssetHoldingFieldTypes[int(s.field)] = s.ftype
		assetHoldingFieldSpecByField[s.field] = s
	}
	assetHoldingFieldSpecByName = make(ahfNameSpecMap, len(AssetHoldingFieldNames))
	for i, ahfn := range AssetHoldingFieldNames {
		assetHoldingFieldSpecByName[ahfn] = assetHoldingFieldSpecByField[AssetHoldingField(i)]
	}

	AssetParamsFieldNames = make([]string, int(invalidAssetParamsField))
	for i := AssetTotal; i < invalidAssetParamsField; i++ {
		AssetParamsFieldNames[int(i)] = i.String()
	}
	AssetParamsFieldTypes = make([]StackType, len(AssetParamsFieldNames))
	assetParamsFieldSpecByField = make(map[AssetParamsField]assetParamsFieldSpec, len(AssetParamsFieldNames))
	for _, s := range assetParamsFieldSpecs {
		AssetParamsFieldTypes[int(s.field)] = s.ftype
		assetParamsFieldSpecByField[s.field] = s
	}
	assetParamsFieldSpecByName = make(apfNameSpecMap, len(AssetParamsFieldNames))
	for i, apfn := range AssetParamsFieldNames {
		assetParamsFieldSpecByName[apfn] = assetParamsFieldSpecByField[AssetParamsField(i)]
	}

	AppParamsFieldNames = make([]string, int(invalidAppParamsField))
	for i := AppApprovalProgram; i < invalidAppParamsField; i++ {
		AppParamsFieldNames[int(i)] = i.String()
	}
	AppParamsFieldTypes = make([]StackType, len(AppParamsFieldNames))
	appParamsFieldSpecByField = make(map[AppParamsField]appParamsFieldSpec, len(AppParamsFieldNames))
	for _, s := range appParamsFieldSpecs {
		AppParamsFieldTypes[int(s.field)] = s.ftype
		appParamsFieldSpecByField[s.field] = s
	}
	appParamsFieldSpecByName = make(appNameSpecMap, len(AppParamsFieldNames))
	for i, apfn := range AppParamsFieldNames {
		appParamsFieldSpecByName[apfn] = appParamsFieldSpecByField[AppParamsField(i)]
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
