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

//go:generate stringer -type=TxnField,GlobalField,AssetParamsField,AssetHoldingField,OnCompletionConstType -output=fields_string.go

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

	// CreatableID basics.CreatableIndex
	CreatableID

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
	field   TxnField
	ftype   StackType
	version uint64
}

var txnFieldSpecs = []txnFieldSpec{
	{Sender, StackBytes, 0},
	{Fee, StackUint64, 0},
	{FirstValid, StackUint64, 0},
	{FirstValidTime, StackUint64, 0},
	{LastValid, StackUint64, 0},
	{Note, StackBytes, 0},
	{Lease, StackBytes, 0},
	{Receiver, StackBytes, 0},
	{Amount, StackUint64, 0},
	{CloseRemainderTo, StackBytes, 0},
	{VotePK, StackBytes, 0},
	{SelectionPK, StackBytes, 0},
	{VoteFirst, StackUint64, 0},
	{VoteLast, StackUint64, 0},
	{VoteKeyDilution, StackUint64, 0},
	{Type, StackBytes, 0},
	{TypeEnum, StackUint64, 0},
	{XferAsset, StackUint64, 0},
	{AssetAmount, StackUint64, 0},
	{AssetSender, StackBytes, 0},
	{AssetReceiver, StackBytes, 0},
	{AssetCloseTo, StackBytes, 0},
	{GroupIndex, StackUint64, 0},
	{TxID, StackBytes, 0},
	{ApplicationID, StackUint64, 2},
	{OnCompletion, StackUint64, 2},
	{ApplicationArgs, StackBytes, 2},
	{NumAppArgs, StackUint64, 2},
	{Accounts, StackBytes, 2},
	{NumAccounts, StackUint64, 2},
	{ApprovalProgram, StackBytes, 2},
	{ClearStateProgram, StackBytes, 2},
	{RekeyTo, StackBytes, 2},
	{ConfigAsset, StackUint64, 2},
	{ConfigAssetTotal, StackUint64, 2},
	{ConfigAssetDecimals, StackUint64, 2},
	{ConfigAssetDefaultFrozen, StackUint64, 2},
	{ConfigAssetUnitName, StackBytes, 2},
	{ConfigAssetName, StackBytes, 2},
	{ConfigAssetURL, StackBytes, 2},
	{ConfigAssetMetadataHash, StackBytes, 2},
	{ConfigAssetManager, StackBytes, 2},
	{ConfigAssetReserve, StackBytes, 2},
	{ConfigAssetFreeze, StackBytes, 2},
	{ConfigAssetClawback, StackBytes, 2},
	{FreezeAsset, StackUint64, 2},
	{FreezeAssetAccount, StackBytes, 2},
	{FreezeAssetFrozen, StackUint64, 2},
	{Assets, StackUint64, 3},
	{NumAssets, StackUint64, 3},
	{Applications, StackUint64, 3},
	{NumApplications, StackUint64, 3},
	{GlobalNumUint, StackUint64, 3},
	{GlobalNumByteSlice, StackUint64, 3},
	{LocalNumUint, StackUint64, 3},
	{LocalNumByteSlice, StackUint64, 3},
	{CreatableID, StackUint64, 4},
}

// TxnaFieldNames are arguments to the 'txna' opcode
// It is a subset of txn transaction fields so initialized here in-place
var TxnaFieldNames = []string{ApplicationArgs.String(), Accounts.String()}

// TxnaFieldTypes is StackBytes or StackUint64 parallel to TxnFieldNames
var TxnaFieldTypes = []StackType{
	txnaFieldSpecByField[ApplicationArgs].ftype,
	txnaFieldSpecByField[Accounts].ftype,
	txnaFieldSpecByField[Assets].ftype,
	txnaFieldSpecByField[Applications].ftype,
}

var txnaFieldSpecByField = map[TxnField]txnFieldSpec{
	ApplicationArgs: {ApplicationArgs, StackBytes, 2},
	Accounts:        {Accounts, StackBytes, 2},
	Assets:          {Assets, StackUint64, 3},
	Applications:    {Applications, StackUint64, 3},
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

	invalidGlobalField
)

// GlobalFieldNames are arguments to the 'global' opcode
var GlobalFieldNames []string

// GlobalFieldTypes is StackUint64 StackBytes in parallel with GlobalFieldNames
var GlobalFieldTypes []StackType

type globalFieldSpec struct {
	gfield  GlobalField
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

type assetHoldingFieldType struct {
	field AssetHoldingField
	ftype StackType
}

var assetHoldingFieldTypeList = []assetHoldingFieldType{
	{AssetBalance, StackUint64},
	{AssetFrozen, StackUint64},
}

// AssetHoldingFieldTypes is StackUint64 StackBytes in parallel with AssetHoldingFieldNames
var AssetHoldingFieldTypes []StackType

var assetHoldingFields map[string]uint64

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
	invalidAssetParamsField
)

// AssetParamsFieldNames are arguments to the 'asset_holding_get' opcode
var AssetParamsFieldNames []string

type assetParamsFieldType struct {
	field AssetParamsField
	ftype StackType
}

var assetParamsFieldTypeList = []assetParamsFieldType{
	{AssetTotal, StackUint64},
	{AssetDecimals, StackUint64},
	{AssetDefaultFrozen, StackUint64},
	{AssetUnitName, StackBytes},
	{AssetName, StackBytes},
	{AssetURL, StackBytes},
	{AssetMetadataHash, StackBytes},
	{AssetManager, StackBytes},
	{AssetReserve, StackBytes},
	{AssetFreeze, StackBytes},
	{AssetClawback, StackBytes},
}

// AssetParamsFieldTypes is StackUint64 StackBytes in parallel with AssetParamsFieldNames
var AssetParamsFieldTypes []StackType

var assetParamsFields map[string]uint64

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
		GlobalFieldTypes[int(s.gfield)] = s.ftype
		globalFieldSpecByField[s.gfield] = s
	}
	globalFieldSpecByName = make(gfNameSpecMap, len(GlobalFieldNames))
	for i, gfn := range GlobalFieldNames {
		globalFieldSpecByName[gfn] = globalFieldSpecByField[GlobalField(i)]
	}

	AssetHoldingFieldNames = make([]string, int(invalidAssetHoldingField))
	for i := AssetBalance; i < invalidAssetHoldingField; i++ {
		AssetHoldingFieldNames[int(i)] = i.String()
	}
	AssetHoldingFieldTypes = make([]StackType, len(AssetHoldingFieldNames))
	for _, ft := range assetHoldingFieldTypeList {
		AssetHoldingFieldTypes[int(ft.field)] = ft.ftype
	}
	assetHoldingFields = make(map[string]uint64)
	for i, fn := range AssetHoldingFieldNames {
		assetHoldingFields[fn] = uint64(i)
	}

	AssetParamsFieldNames = make([]string, int(invalidAssetParamsField))
	for i := AssetTotal; i < invalidAssetParamsField; i++ {
		AssetParamsFieldNames[int(i)] = i.String()
	}
	AssetParamsFieldTypes = make([]StackType, len(AssetParamsFieldNames))
	for _, ft := range assetParamsFieldTypeList {
		AssetParamsFieldTypes[int(ft.field)] = ft.ftype
	}
	assetParamsFields = make(map[string]uint64)
	for i, fn := range AssetParamsFieldNames {
		assetParamsFields[fn] = uint64(i)
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
