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

//go:generate stringer -type=TxnField,GlobalField,AssetParamsField,AppParamsField,AssetHoldingField,OnCompletionConstType,EcdsaCurve -output=fields_string.go

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
	version    uint64 // When this field become available to txn/gtxn. 0=always
	itxVersion uint64 // When this field become available to itxn_field. 0=never
	effects    bool   // Is this a field on the "effects"? That is, something in ApplyData
}

var txnFieldSpecs = []txnFieldSpec{
	{Sender, StackBytes, 0, 5, false},
	{Fee, StackUint64, 0, 5, false},
	{FirstValid, StackUint64, 0, 0, false},
	{FirstValidTime, StackUint64, 0, 0, false},
	{LastValid, StackUint64, 0, 0, false},
	{Note, StackBytes, 0, 0, false},
	{Lease, StackBytes, 0, 0, false},
	{Receiver, StackBytes, 0, 5, false},
	{Amount, StackUint64, 0, 5, false},
	{CloseRemainderTo, StackBytes, 0, 5, false},
	{VotePK, StackBytes, 0, 0, false},
	{SelectionPK, StackBytes, 0, 0, false},
	{VoteFirst, StackUint64, 0, 0, false},
	{VoteLast, StackUint64, 0, 0, false},
	{VoteKeyDilution, StackUint64, 0, 0, false},
	{Type, StackBytes, 0, 5, false},
	{TypeEnum, StackUint64, 0, 5, false},
	{XferAsset, StackUint64, 0, 5, false},
	{AssetAmount, StackUint64, 0, 5, false},
	{AssetSender, StackBytes, 0, 5, false},
	{AssetReceiver, StackBytes, 0, 5, false},
	{AssetCloseTo, StackBytes, 0, 5, false},
	{GroupIndex, StackUint64, 0, 0, false},
	{TxID, StackBytes, 0, 0, false},
	{ApplicationID, StackUint64, 2, 0, false},
	{OnCompletion, StackUint64, 2, 0, false},
	{ApplicationArgs, StackBytes, 2, 0, false},
	{NumAppArgs, StackUint64, 2, 0, false},
	{Accounts, StackBytes, 2, 0, false},
	{NumAccounts, StackUint64, 2, 0, false},
	{ApprovalProgram, StackBytes, 2, 0, false},
	{ClearStateProgram, StackBytes, 2, 0, false},
	{RekeyTo, StackBytes, 2, 0, false},
	{ConfigAsset, StackUint64, 2, 5, false},
	{ConfigAssetTotal, StackUint64, 2, 5, false},
	{ConfigAssetDecimals, StackUint64, 2, 5, false},
	{ConfigAssetDefaultFrozen, StackUint64, 2, 5, false},
	{ConfigAssetUnitName, StackBytes, 2, 5, false},
	{ConfigAssetName, StackBytes, 2, 5, false},
	{ConfigAssetURL, StackBytes, 2, 5, false},
	{ConfigAssetMetadataHash, StackBytes, 2, 5, false},
	{ConfigAssetManager, StackBytes, 2, 5, false},
	{ConfigAssetReserve, StackBytes, 2, 5, false},
	{ConfigAssetFreeze, StackBytes, 2, 5, false},
	{ConfigAssetClawback, StackBytes, 2, 5, false},
	{FreezeAsset, StackUint64, 2, 5, false},
	{FreezeAssetAccount, StackBytes, 2, 5, false},
	{FreezeAssetFrozen, StackUint64, 2, 5, false},
	{Assets, StackUint64, 3, 0, false},
	{NumAssets, StackUint64, 3, 0, false},
	{Applications, StackUint64, 3, 0, false},
	{NumApplications, StackUint64, 3, 0, false},
	{GlobalNumUint, StackUint64, 3, 0, false},
	{GlobalNumByteSlice, StackUint64, 3, 0, false},
	{LocalNumUint, StackUint64, 3, 0, false},
	{LocalNumByteSlice, StackUint64, 3, 0, false},
	{ExtraProgramPages, StackUint64, 4, 0, false},
	{Nonparticipation, StackUint64, 5, 0, false},

	{Logs, StackBytes, 5, 5, true},
	{NumLogs, StackUint64, 5, 5, true},
	{CreatedAssetID, StackUint64, 5, 5, true},
	{CreatedApplicationID, StackUint64, 5, 5, true},
}

// TxnaFieldNames are arguments to the 'txna' opcode
// It is a subset of txn transaction fields so initialized here in-place
var TxnaFieldNames = []string{ApplicationArgs.String(), Accounts.String(), Assets.String(), Applications.String(), Logs.String()}

// TxnaFieldTypes is StackBytes or StackUint64 parallel to TxnaFieldNames
var TxnaFieldTypes = []StackType{
	txnaFieldSpecByField[ApplicationArgs].ftype,
	txnaFieldSpecByField[Accounts].ftype,
	txnaFieldSpecByField[Assets].ftype,
	txnaFieldSpecByField[Applications].ftype,
	txnaFieldSpecByField[Logs].ftype,
}

var txnaFieldSpecByField = map[TxnField]txnFieldSpec{
	ApplicationArgs: {ApplicationArgs, StackBytes, 2, 0, false},
	Accounts:        {Accounts, StackBytes, 2, 0, false},
	Assets:          {Assets, StackUint64, 3, 0, false},
	Applications:    {Applications, StackUint64, 3, 0, false},

	Logs: {Logs, StackBytes, 5, 5, true},
}

var innerTxnTypes = map[string]protocol.TxType{
	string(protocol.PaymentTx):       protocol.PaymentTx,
	string(protocol.AssetTransferTx): protocol.AssetTransferTx,
	string(protocol.AssetConfigTx):   protocol.AssetConfigTx,
	string(protocol.AssetFreezeTx):   protocol.AssetFreezeTx,
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
			panic("txnFieldTypePairs disjoint with TxnField enum")
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
	for _, s := range globalFieldSpecs {
		GlobalFieldTypes[int(s.field)] = s.ftype
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
