// Copyright (C) 2019-2020 Algorand, Inc.
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
	"github.com/algorand/go-algorand/protocol"
)

//go:generate stringer -type=TxnField,GlobalField,AssetParamsField,AssetHoldingField -output=fields_string.go

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
	// ApplicationArgs []basics.TealValue
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

	invalidTxnField // fence for some setup that loops from Sender..invalidTxnField
)

// TxnFieldNames are arguments to the 'txn' and 'txnById' opcodes
var TxnFieldNames []string
var txnFields map[string]uint

type txnFieldType struct {
	field TxnField
	ftype StackType
}

var txnFieldTypePairs = []txnFieldType{
	{Sender, StackBytes},
	{Fee, StackUint64},
	{FirstValid, StackUint64},
	{FirstValidTime, StackUint64},
	{LastValid, StackUint64},
	{Note, StackBytes},
	{Lease, StackBytes},
	{Receiver, StackBytes},
	{Amount, StackUint64},
	{CloseRemainderTo, StackBytes},
	{VotePK, StackBytes},
	{SelectionPK, StackBytes},
	{VoteFirst, StackUint64},
	{VoteLast, StackUint64},
	{VoteKeyDilution, StackUint64},
	{Type, StackBytes},
	{TypeEnum, StackUint64},
	{XferAsset, StackUint64},
	{AssetAmount, StackUint64},
	{AssetSender, StackBytes},
	{AssetReceiver, StackBytes},
	{AssetCloseTo, StackBytes},
	{GroupIndex, StackUint64},
	{TxID, StackBytes},
	{ApplicationID, StackUint64},
	{OnCompletion, StackUint64},
	{ApplicationArgs, StackBytes},
	{NumAppArgs, StackUint64},
	{Accounts, StackBytes},
	{NumAccounts, StackUint64},
	{ApprovalProgram, StackBytes},
	{ClearStateProgram, StackBytes},
}

// TxnFieldTypes is StackBytes or StackUint64 parallel to TxnFieldNames
var TxnFieldTypes []StackType

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
var txnTypeIndexes map[string]int

// map symbolic name to uint64 for assembleInt
var txnTypeConstToUint64 map[string]uint64

// GlobalField is an enum for `global` opcode
type GlobalField int

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
	// LogicSigVersion ConsensusParams.LogicSigVersion
	LogicSigVersion
	// Round basics.Round
	Round

	invalidGlobalField
)

// GlobalFieldNames are arguments to the 'global' opcode
var GlobalFieldNames []string

type globalFieldType struct {
	gfield GlobalField
	ftype  StackType
}

var globalFieldTypeList = []globalFieldType{
	{MinTxnFee, StackUint64},
	{MinBalance, StackUint64},
	{MaxTxnLife, StackUint64},
	{ZeroAddress, StackBytes},
	{GroupSize, StackUint64},
	{LogicSigVersion, StackUint64},
	{Round, StackUint64},
}

// GlobalFieldTypes is StackUint64 StackBytes in parallel with GlobalFieldNames
var GlobalFieldTypes []StackType

var globalFields map[string]uint

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

var assetHoldingFields map[string]uint

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
	// AssetAssetName AssetParams.AssetName
	AssetAssetName
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
	{AssetAssetName, StackBytes},
	{AssetURL, StackBytes},
	{AssetMetadataHash, StackBytes},
	{AssetManager, StackBytes},
	{AssetReserve, StackBytes},
	{AssetFreeze, StackBytes},
	{AssetClawback, StackBytes},
}

// AssetParamsFieldTypes is StackUint64 StackBytes in parallel with AssetParamsFieldNames
var AssetParamsFieldTypes []StackType

var assetParamsFields map[string]uint

func init() {
	TxnFieldNames = make([]string, int(invalidTxnField))
	for fi := Sender; fi < invalidTxnField; fi++ {
		TxnFieldNames[fi] = fi.String()
	}
	txnFields = make(map[string]uint)
	for i, tfn := range TxnFieldNames {
		txnFields[tfn] = uint(i)
	}

	TxnFieldTypes = make([]StackType, int(invalidTxnField))
	for i, ft := range txnFieldTypePairs {
		if int(ft.field) != i {
			panic("txnFieldTypePairs disjoint with TxnField enum")
		}
		TxnFieldTypes[i] = ft.ftype
	}

	GlobalFieldNames = make([]string, int(invalidGlobalField))
	for i := MinTxnFee; i < invalidGlobalField; i++ {
		GlobalFieldNames[int(i)] = i.String()
	}
	GlobalFieldTypes = make([]StackType, len(GlobalFieldNames))
	for _, ft := range globalFieldTypeList {
		GlobalFieldTypes[int(ft.gfield)] = ft.ftype
	}
	globalFields = make(map[string]uint)
	for i, gfn := range GlobalFieldNames {
		globalFields[gfn] = uint(i)
	}

	AssetHoldingFieldNames = make([]string, int(invalidAssetHoldingField))
	for i := AssetBalance; i < invalidAssetHoldingField; i++ {
		AssetHoldingFieldNames[int(i)] = i.String()
	}
	AssetHoldingFieldTypes = make([]StackType, len(AssetHoldingFieldNames))
	for _, ft := range assetHoldingFieldTypeList {
		AssetHoldingFieldTypes[int(ft.field)] = ft.ftype
	}
	assetHoldingFields = make(map[string]uint)
	for i, fn := range AssetHoldingFieldNames {
		assetHoldingFields[fn] = uint(i)
	}

	AssetParamsFieldNames = make([]string, int(invalidAssetParamsField))
	for i := AssetTotal; i < invalidAssetParamsField; i++ {
		AssetParamsFieldNames[int(i)] = i.String()
	}
	AssetParamsFieldTypes = make([]StackType, len(AssetParamsFieldNames))
	for _, ft := range assetParamsFieldTypeList {
		AssetParamsFieldTypes[int(ft.field)] = ft.ftype
	}
	assetParamsFields = make(map[string]uint)
	for i, fn := range AssetParamsFieldNames {
		assetParamsFields[fn] = uint(i)
	}

	txnTypeIndexes = make(map[string]int, len(TxnTypeNames))
	for i, tt := range TxnTypeNames {
		txnTypeIndexes[tt] = i
	}

	txnTypeConstToUint64 = make(map[string]uint64, len(TxnTypeNames))
	for tt, v := range txnTypeIndexes {
		symbol := TypeNameDescription(tt)
		txnTypeConstToUint64[symbol] = uint64(v)
	}
}
