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

package trackerdb

import (
	"context"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// BaseAccountData is the base struct used to store account data
type BaseAccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Status                     basics.Status     `codec:"a"`
	MicroAlgos                 basics.MicroAlgos `codec:"b"`
	RewardsBase                uint64            `codec:"c"`
	RewardedMicroAlgos         basics.MicroAlgos `codec:"d"`
	AuthAddr                   basics.Address    `codec:"e"`
	TotalAppSchemaNumUint      uint64            `codec:"f"`
	TotalAppSchemaNumByteSlice uint64            `codec:"g"`
	TotalExtraAppPages         uint32            `codec:"h"`
	TotalAssetParams           uint64            `codec:"i"`
	TotalAssets                uint64            `codec:"j"`
	TotalAppParams             uint64            `codec:"k"`
	TotalAppLocalStates        uint64            `codec:"l"`
	TotalBoxes                 uint64            `codec:"m"`
	TotalBoxBytes              uint64            `codec:"n"`
	IncentiveEligible          bool              `codec:"o"`
	LastProposed               basics.Round      `codec:"p"`
	LastHeartbeat              basics.Round      `codec:"q"`

	BaseVotingData

	// UpdateRound is the round that modified this account data last. Since we want all the nodes to have the exact same
	// value for this field, we'll be setting the value of this field to zero *before* the EnableAccountDataResourceSeparation
	// consensus parameter is being set. Once the above consensus takes place, this field would be populated with the
	// correct round number.
	UpdateRound uint64 `codec:"z"`
}

// ResourceFlags are bitmask used to indicate which portions ofa resources are used.
type ResourceFlags uint8

const (
	// ResourceFlagsHolding indicates "Holding"
	ResourceFlagsHolding ResourceFlags = 0
	// ResourceFlagsNotHolding indicates "Not Holding"
	ResourceFlagsNotHolding ResourceFlags = 1
	// ResourceFlagsOwnership indicates "Ownerhip"
	ResourceFlagsOwnership ResourceFlags = 2
	// ResourceFlagsEmptyAsset indicates "Empty Asset"
	ResourceFlagsEmptyAsset ResourceFlags = 4
	// ResourceFlagsEmptyApp indicates "Empty App"
	ResourceFlagsEmptyApp ResourceFlags = 8
)

//
// Resource flags interpretation:
//
// ResourceFlagsHolding - the resource contains the holding of asset/app.
// ResourceFlagsNotHolding - the resource is completely empty. This state should not be persisted.
// ResourceFlagsOwnership - the resource contains the asset parameter or application parameters.
// ResourceFlagsEmptyAsset - this is an asset resource, and it is empty.
// ResourceFlagsEmptyApp - this is an app resource, and it is empty.

// ResourcesData holds the resource data that will be stored.
type ResourcesData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// asset parameters ( basics.AssetParams )
	Total         uint64         `codec:"a"`
	Decimals      uint32         `codec:"b"`
	DefaultFrozen bool           `codec:"c"`
	UnitName      string         `codec:"d"`
	AssetName     string         `codec:"e"`
	URL           string         `codec:"f"`
	MetadataHash  [32]byte       `codec:"g"`
	Manager       basics.Address `codec:"h"`
	Reserve       basics.Address `codec:"i"`
	Freeze        basics.Address `codec:"j"`
	Clawback      basics.Address `codec:"k"`

	// asset holding ( basics.AssetHolding )
	Amount uint64 `codec:"l"`
	Frozen bool   `codec:"m"`

	// application local state ( basics.AppLocalState )
	SchemaNumUint      uint64              `codec:"n"`
	SchemaNumByteSlice uint64              `codec:"o"`
	KeyValue           basics.TealKeyValue `codec:"p"`

	// application global params ( basics.AppParams )
	ApprovalProgram               []byte              `codec:"q,allocbound=bounds.MaxAvailableAppProgramLen"`
	ClearStateProgram             []byte              `codec:"r,allocbound=bounds.MaxAvailableAppProgramLen"`
	GlobalState                   basics.TealKeyValue `codec:"s"`
	LocalStateSchemaNumUint       uint64              `codec:"t"`
	LocalStateSchemaNumByteSlice  uint64              `codec:"u"`
	GlobalStateSchemaNumUint      uint64              `codec:"v"`
	GlobalStateSchemaNumByteSlice uint64              `codec:"w"`
	ExtraProgramPages             uint32              `codec:"x"`

	// ResourceFlags helps to identify which portions of this structure should be used; in particular, it
	// helps to provide a marker - i.e. whether the account was, for instance, opted-in for the asset compared
	// to just being the owner of the asset. A comparison against the empty structure doesn't work here -
	// since both the holdings and the parameters are allowed to be all at their default values.
	ResourceFlags ResourceFlags `codec:"y"`

	// UpdateRound is the round that modified this resource last. Since we want all the nodes to have the exact same
	// value for this field, we'll be setting the value of this field to zero *before* the EnableAccountDataResourceSeparation
	// consensus parameter is being set. Once the above consensus takes place, this field would be populated with the
	// correct round number.
	UpdateRound uint64 `codec:"z"`

	Version uint64 `codec:"A"`

	SizeSponsor basics.Address `codec:"B"`
}

// BaseVotingData is the base struct used to store voting data
type BaseVotingData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	VoteID          crypto.OneTimeSignatureVerifier `codec:"A"`
	SelectionID     crypto.VRFVerifier              `codec:"B"`
	VoteFirstValid  basics.Round                    `codec:"C"`
	VoteLastValid   basics.Round                    `codec:"D"`
	VoteKeyDilution uint64                          `codec:"E"`
	StateProofID    merklesignature.Commitment      `codec:"F"`
}

// BaseOnlineAccountData is the base struct used to store online account data
type BaseOnlineAccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	BaseVotingData

	LastProposed      basics.Round      `codec:"V"`
	LastHeartbeat     basics.Round      `codec:"W"`
	IncentiveEligible bool              `codec:"X"`
	MicroAlgos        basics.MicroAlgos `codec:"Y"`
	RewardsBase       uint64            `codec:"Z"`
}

// PersistedKVData represents the stored entry behind a application boxed key/value.
type PersistedKVData struct {
	// kv value
	Value []byte
	// the round number that is associated with the kv value. This field is the corresponding one to the round field
	// in persistedAccountData, and serves the same purpose.
	Round basics.Round
}

// PersistedAccountData is used for representing a single account stored on the disk. In addition to the
// basics.AccountData, it also stores complete referencing information used to maintain the base accounts
// list.
type PersistedAccountData struct {
	// The address of the account. In contrasts to maps, having this value explicitly here allows us to use this
	// data structure in queues directly, without "attaching" the address as the address as the map key.
	Addr basics.Address
	// The underlaying account data
	AccountData BaseAccountData
	// The reference to the stored object, when available. If the entry was loaded from the disk, then we have the ref for it. Entries
	// that dont have ref ( hence, ref == nil ) represent either deleted accounts or non-existing accounts.
	Ref AccountRef
	// the round number that is associated with the accountData. This field is needed so that we can maintain a correct
	// lruAccounts cache. We use it to ensure that the entries on the lruAccounts.accountsList are the latest ones.
	// this becomes an issue since while we attempt to write an update to disk, we might be reading an entry and placing
	// it on the lruAccounts.pendingAccounts; The commitRound doesn't attempt to flush the pending accounts, but rather
	// just write the latest ( which is correct ) to the lruAccounts.accountsList. later on, during on newBlockImpl, we
	// want to ensure that the "real" written value isn't being overridden by the value from the pending accounts.
	Round basics.Round
}

// PersistedResourcesData is exported view of persistedResourcesData
type PersistedResourcesData struct {
	// AcctRef is the stored object reference of the account address that holds this resource.
	// it is used in update/delete operations so must be filled for existing records.
	// resolution is a multi stage process:
	// - baseResources cache might have valid entries
	// - baseAccount cache might have an entry for the address with rowid set
	// - when loading non-cached resources in resourcesLoadOld
	// - when creating new accounts in accountsNewRound
	AcctRef AccountRef
	// creatable index
	Aidx basics.CreatableIndex
	// actual resource data
	Data ResourcesData
	// the round number that is associated with the resourcesData. This field is the corresponding one to the round field
	// in persistedAccountData, and serves the same purpose.
	Round basics.Round
}

// PersistedResourcesDataWithCreator is exported view of persistedResourcesData inclusive of creator
type PersistedResourcesDataWithCreator struct {
	PersistedResourcesData

	// the address of the account that created this resource
	Creator basics.Address
}

// PersistedOnlineAccountData is exported view of persistedOnlineAccountData
type PersistedOnlineAccountData struct {
	Addr        basics.Address
	AccountData BaseOnlineAccountData
	Ref         OnlineAccountRef
	// the round number that is associated with the baseOnlineAccountData. This field is the corresponding one to the round field
	// in persistedAccountData, and serves the same purpose. This value comes from account rounds table and correspond to
	// the last trackers db commit round.
	Round basics.Round
	// the round number that the online account is for, i.e. account state change round.
	UpdRound basics.Round
}

// TxTailRound contains the information about a single round of transactions.
// The TxnIDs and LastValid would both be of the same length, and are stored
// in that way for efficient message=pack encoding. The Leases would point to the
// respective transaction index. Note that this isn’t optimized for storing
// leases, as leases are extremely rare.
type TxTailRound struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TxnIDs    []transactions.Txid     `codec:"i,allocbound=-"`
	LastValid []basics.Round          `codec:"v,allocbound=-"`
	Leases    []TxTailRoundLease      `codec:"l,allocbound=-"`
	Hdr       bookkeeping.BlockHeader `codec:"h,allocbound=-"`
}

// TxTailRoundLease is used as part of txTailRound for storing
// a single lease.
type TxTailRoundLease struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender basics.Address `codec:"s"`
	Lease  [32]byte       `codec:"l,allocbound=-"`
	TxnIdx uint64         `code:"i"` //!-- index of the entry in TxnIDs/LastValid
}

// AccountResource returns the corresponding account resource data based on the type of resource.
func (prd *PersistedResourcesData) AccountResource() ledgercore.AccountResource {
	var ret ledgercore.AccountResource
	if prd.Data.IsAsset() {
		if prd.Data.IsHolding() {
			holding := prd.Data.GetAssetHolding()
			ret.AssetHolding = &holding
		}
		if prd.Data.IsOwning() {
			assetParams := prd.Data.GetAssetParams()
			ret.AssetParams = &assetParams
		}
	}
	if prd.Data.IsApp() {
		if prd.Data.IsHolding() {
			localState := prd.Data.GetAppLocalState()
			ret.AppLocalState = &localState
		}
		if prd.Data.IsOwning() {
			appParams := prd.Data.GetAppParams()
			ret.AppParams = &appParams
		}
	}
	return ret
}

// NormalizedOnlineBalance getter for normalized online balance.
func (ba *BaseAccountData) NormalizedOnlineBalance(rewardUnit uint64) uint64 {
	return basics.NormalizedOnlineAccountBalance(ba.Status, ba.RewardsBase, ba.MicroAlgos, rewardUnit)
}

// SetCoreAccountData setter for core account data.
func (ba *BaseAccountData) SetCoreAccountData(ad *ledgercore.AccountData) {
	ba.Status = ad.Status
	ba.MicroAlgos = ad.MicroAlgos
	ba.RewardsBase = ad.RewardsBase
	ba.RewardedMicroAlgos = ad.RewardedMicroAlgos
	ba.AuthAddr = ad.AuthAddr
	ba.TotalAppSchemaNumUint = ad.TotalAppSchema.NumUint
	ba.TotalAppSchemaNumByteSlice = ad.TotalAppSchema.NumByteSlice
	ba.TotalExtraAppPages = ad.TotalExtraAppPages
	ba.TotalAssetParams = ad.TotalAssetParams
	ba.TotalAssets = ad.TotalAssets
	ba.TotalAppParams = ad.TotalAppParams
	ba.TotalAppLocalStates = ad.TotalAppLocalStates
	ba.TotalBoxes = ad.TotalBoxes
	ba.TotalBoxBytes = ad.TotalBoxBytes
	ba.IncentiveEligible = ad.IncentiveEligible

	ba.LastProposed = ad.LastProposed
	ba.LastHeartbeat = ad.LastHeartbeat

	ba.BaseVotingData.SetCoreAccountData(ad)
}

// SetAccountData setter for account data.
func (ba *BaseAccountData) SetAccountData(ad *basics.AccountData) {
	ba.Status = ad.Status
	ba.MicroAlgos = ad.MicroAlgos
	ba.RewardsBase = ad.RewardsBase
	ba.RewardedMicroAlgos = ad.RewardedMicroAlgos
	ba.AuthAddr = ad.AuthAddr
	ba.TotalAppSchemaNumUint = ad.TotalAppSchema.NumUint
	ba.TotalAppSchemaNumByteSlice = ad.TotalAppSchema.NumByteSlice
	ba.TotalExtraAppPages = ad.TotalExtraAppPages
	ba.TotalAssetParams = uint64(len(ad.AssetParams))
	ba.TotalAssets = uint64(len(ad.Assets))
	ba.TotalAppParams = uint64(len(ad.AppParams))
	ba.TotalAppLocalStates = uint64(len(ad.AppLocalStates))
	ba.TotalBoxes = ad.TotalBoxes
	ba.TotalBoxBytes = ad.TotalBoxBytes
	ba.IncentiveEligible = ad.IncentiveEligible

	ba.LastProposed = ad.LastProposed
	ba.LastHeartbeat = ad.LastHeartbeat

	ba.BaseVotingData.VoteID = ad.VoteID
	ba.BaseVotingData.SelectionID = ad.SelectionID
	ba.BaseVotingData.StateProofID = ad.StateProofID
	ba.BaseVotingData.VoteFirstValid = ad.VoteFirstValid
	ba.BaseVotingData.VoteLastValid = ad.VoteLastValid
	ba.BaseVotingData.VoteKeyDilution = ad.VoteKeyDilution
}

// GetLedgerCoreAccountData getter for account data.
func (ba *BaseAccountData) GetLedgerCoreAccountData() ledgercore.AccountData {
	return ledgercore.AccountData{
		AccountBaseData: ba.GetLedgerCoreAccountBaseData(),
		VotingData:      ba.GetLedgerCoreVotingData(),
	}
}

// GetLedgerCoreAccountBaseData getter for account base data.
func (ba *BaseAccountData) GetLedgerCoreAccountBaseData() ledgercore.AccountBaseData {
	return ledgercore.AccountBaseData{
		Status:             ba.Status,
		MicroAlgos:         ba.MicroAlgos,
		RewardsBase:        ba.RewardsBase,
		RewardedMicroAlgos: ba.RewardedMicroAlgos,
		AuthAddr:           ba.AuthAddr,
		TotalAppSchema: basics.StateSchema{
			NumUint:      ba.TotalAppSchemaNumUint,
			NumByteSlice: ba.TotalAppSchemaNumByteSlice,
		},
		TotalExtraAppPages:  ba.TotalExtraAppPages,
		TotalAppParams:      ba.TotalAppParams,
		TotalAppLocalStates: ba.TotalAppLocalStates,
		TotalAssetParams:    ba.TotalAssetParams,
		TotalAssets:         ba.TotalAssets,
		TotalBoxes:          ba.TotalBoxes,
		TotalBoxBytes:       ba.TotalBoxBytes,
		IncentiveEligible:   ba.IncentiveEligible,

		LastProposed:  ba.LastProposed,
		LastHeartbeat: ba.LastHeartbeat,
	}
}

// GetLedgerCoreVotingData getter for voting data.
func (ba *BaseAccountData) GetLedgerCoreVotingData() basics.VotingData {
	return basics.VotingData{
		VoteID:          ba.VoteID,
		SelectionID:     ba.SelectionID,
		StateProofID:    ba.StateProofID,
		VoteFirstValid:  ba.VoteFirstValid,
		VoteLastValid:   ba.VoteLastValid,
		VoteKeyDilution: ba.VoteKeyDilution,
	}
}

// GetAccountData getter for account data.
func (ba *BaseAccountData) GetAccountData() basics.AccountData {
	return basics.AccountData{
		Status:             ba.Status,
		MicroAlgos:         ba.MicroAlgos,
		RewardsBase:        ba.RewardsBase,
		RewardedMicroAlgos: ba.RewardedMicroAlgos,
		AuthAddr:           ba.AuthAddr,
		IncentiveEligible:  ba.IncentiveEligible,
		TotalAppSchema: basics.StateSchema{
			NumUint:      ba.TotalAppSchemaNumUint,
			NumByteSlice: ba.TotalAppSchemaNumByteSlice,
		},
		TotalExtraAppPages: ba.TotalExtraAppPages,
		TotalBoxes:         ba.TotalBoxes,
		TotalBoxBytes:      ba.TotalBoxBytes,

		VoteID:          ba.VoteID,
		SelectionID:     ba.SelectionID,
		StateProofID:    ba.StateProofID,
		VoteFirstValid:  ba.VoteFirstValid,
		VoteLastValid:   ba.VoteLastValid,
		VoteKeyDilution: ba.VoteKeyDilution,

		LastProposed:  ba.LastProposed,
		LastHeartbeat: ba.LastHeartbeat,
	}
}

// IsEmpty return true if any of the fields other then the UpdateRound are non-zero.
func (ba *BaseAccountData) IsEmpty() bool {
	return ba.Status == 0 &&
		ba.MicroAlgos.Raw == 0 &&
		ba.RewardsBase == 0 &&
		ba.RewardedMicroAlgos.Raw == 0 &&
		ba.AuthAddr.IsZero() &&
		!ba.IncentiveEligible &&
		ba.TotalAppSchemaNumUint == 0 &&
		ba.TotalAppSchemaNumByteSlice == 0 &&
		ba.TotalExtraAppPages == 0 &&
		ba.TotalAssetParams == 0 &&
		ba.TotalAssets == 0 &&
		ba.TotalAppParams == 0 &&
		ba.TotalAppLocalStates == 0 &&
		ba.TotalBoxes == 0 &&
		ba.TotalBoxBytes == 0 &&
		ba.LastProposed == 0 &&
		ba.LastHeartbeat == 0 &&
		ba.BaseVotingData.IsEmpty()
}

// IsEmpty returns true if all of the fields are zero.
func (bv BaseVotingData) IsEmpty() bool {
	return bv == BaseVotingData{}
}

// SetCoreAccountData initializes baseVotingData from ledgercore.AccountData
func (bv *BaseVotingData) SetCoreAccountData(ad *ledgercore.AccountData) {
	bv.VoteID = ad.VoteID
	bv.SelectionID = ad.SelectionID
	bv.StateProofID = ad.StateProofID
	bv.VoteFirstValid = ad.VoteFirstValid
	bv.VoteLastValid = ad.VoteLastValid
	bv.VoteKeyDilution = ad.VoteKeyDilution
}

// IsVotingEmpty checks if voting data fields are empty
func (bo *BaseOnlineAccountData) IsVotingEmpty() bool {
	return bo.BaseVotingData.IsEmpty()
}

// IsEmpty return true if all of the fields are zero.
func (bo *BaseOnlineAccountData) IsEmpty() bool {
	return bo.IsVotingEmpty() &&
		bo.MicroAlgos.Raw == 0 &&
		bo.RewardsBase == 0 &&
		bo.LastHeartbeat == 0 &&
		bo.LastProposed == 0 &&
		!bo.IncentiveEligible
}

// GetOnlineAccount returns ledgercore.OnlineAccount for top online accounts / voters
// TODO: unify
func (bo *BaseOnlineAccountData) GetOnlineAccount(addr basics.Address, normBalance uint64) ledgercore.OnlineAccount {
	return ledgercore.OnlineAccount{
		Address:                 addr,
		MicroAlgos:              bo.MicroAlgos,
		RewardsBase:             bo.RewardsBase,
		NormalizedOnlineBalance: normBalance,
		VoteFirstValid:          bo.VoteFirstValid,
		VoteLastValid:           bo.VoteLastValid,
		StateProofID:            bo.StateProofID,
	}
}

// GetOnlineAccountData returns basics.OnlineAccountData for lookup agreement
// TODO: unify with GetOnlineAccount/ledgercore.OnlineAccount
func (bo *BaseOnlineAccountData) GetOnlineAccountData(rewardUnit uint64, rewardsLevel uint64) basics.OnlineAccountData {
	microAlgos, _, _ := basics.WithUpdatedRewards(
		rewardUnit, basics.Online, bo.MicroAlgos, basics.MicroAlgos{}, bo.RewardsBase, rewardsLevel,
	)

	return basics.OnlineAccountData{
		MicroAlgosWithRewards: microAlgos,
		VotingData: basics.VotingData{
			VoteID:          bo.VoteID,
			SelectionID:     bo.SelectionID,
			StateProofID:    bo.StateProofID,
			VoteFirstValid:  bo.VoteFirstValid,
			VoteLastValid:   bo.VoteLastValid,
			VoteKeyDilution: bo.VoteKeyDilution,
		},
		IncentiveEligible: bo.IncentiveEligible,
		LastProposed:      bo.LastProposed,
		LastHeartbeat:     bo.LastHeartbeat,
	}
}

// NormalizedOnlineBalance getter for normalized online balance.
func (bo *BaseOnlineAccountData) NormalizedOnlineBalance(rewardUnit uint64) uint64 {
	return basics.NormalizedOnlineAccountBalance(basics.Online, bo.RewardsBase, bo.MicroAlgos, rewardUnit)
}

// SetCoreAccountData setter for core account data.
func (bo *BaseOnlineAccountData) SetCoreAccountData(ad *ledgercore.AccountData) {
	bo.BaseVotingData.SetCoreAccountData(ad)

	// These are updated by the evaluator when accounts are touched
	bo.MicroAlgos = ad.MicroAlgos
	bo.RewardsBase = ad.RewardsBase
	bo.IncentiveEligible = ad.IncentiveEligible
	bo.LastProposed = ad.LastProposed
	bo.LastHeartbeat = ad.LastHeartbeat
}

// MakeResourcesData returns a new empty instance of resourcesData.
// Using this constructor method is necessary because of the ResourceFlags field.
// An optional rnd args sets UpdateRound
func MakeResourcesData(rnd uint64) ResourcesData {
	return ResourcesData{ResourceFlags: ResourceFlagsNotHolding, UpdateRound: rnd}
}

// IsHolding returns true if the resource flag is ResourceFlagsHolding
func (rd *ResourcesData) IsHolding() bool {
	return (rd.ResourceFlags & ResourceFlagsNotHolding) == ResourceFlagsHolding
}

// IsOwning returns true if the resource flag is ResourceFlagsOwnership
func (rd *ResourcesData) IsOwning() bool {
	return (rd.ResourceFlags & ResourceFlagsOwnership) == ResourceFlagsOwnership
}

// IsEmpty returns true if the resource flag is not an app or asset.
func (rd *ResourcesData) IsEmpty() bool {
	return !rd.IsApp() && !rd.IsAsset()
}

// IsEmptyAppFields returns true if the app fields are empty.
func (rd *ResourcesData) IsEmptyAppFields() bool {
	return rd.SchemaNumUint == 0 &&
		rd.SchemaNumByteSlice == 0 &&
		len(rd.KeyValue) == 0 &&
		len(rd.ApprovalProgram) == 0 &&
		len(rd.ClearStateProgram) == 0 &&
		len(rd.GlobalState) == 0 &&
		rd.LocalStateSchemaNumUint == 0 &&
		rd.LocalStateSchemaNumByteSlice == 0 &&
		rd.GlobalStateSchemaNumUint == 0 &&
		rd.GlobalStateSchemaNumByteSlice == 0 &&
		rd.ExtraProgramPages == 0 &&
		rd.Version == 0 &&
		rd.SizeSponsor.IsZero()
}

// IsApp returns true if the flag is ResourceFlagsEmptyApp and the fields are not empty.
func (rd *ResourcesData) IsApp() bool {
	if (rd.ResourceFlags & ResourceFlagsEmptyApp) == ResourceFlagsEmptyApp {
		return true
	}
	return !rd.IsEmptyAppFields()
}

// IsEmptyAssetFields returns true if the asset fields are empty.
func (rd *ResourcesData) IsEmptyAssetFields() bool {
	return rd.Amount == 0 &&
		!rd.Frozen &&
		rd.Total == 0 &&
		rd.Decimals == 0 &&
		!rd.DefaultFrozen &&
		rd.UnitName == "" &&
		rd.AssetName == "" &&
		rd.URL == "" &&
		rd.MetadataHash == [32]byte{} &&
		rd.Manager.IsZero() &&
		rd.Reserve.IsZero() &&
		rd.Freeze.IsZero() &&
		rd.Clawback.IsZero()
}

// IsAsset returns true if the flag is ResourceFlagsEmptyAsset and the fields are not empty.
func (rd *ResourcesData) IsAsset() bool {
	if (rd.ResourceFlags & ResourceFlagsEmptyAsset) == ResourceFlagsEmptyAsset {
		return true
	}
	return !rd.IsEmptyAssetFields()
}

// ClearAssetParams clears the asset params.
func (rd *ResourcesData) ClearAssetParams() {
	rd.Total = 0
	rd.Decimals = 0
	rd.DefaultFrozen = false
	rd.UnitName = ""
	rd.AssetName = ""
	rd.URL = ""
	rd.MetadataHash = basics.Address{}
	rd.Manager = basics.Address{}
	rd.Reserve = basics.Address{}
	rd.Freeze = basics.Address{}
	rd.Clawback = basics.Address{}
	hadHolding := (rd.ResourceFlags & ResourceFlagsNotHolding) == ResourceFlagsHolding
	rd.ResourceFlags -= rd.ResourceFlags & ResourceFlagsOwnership
	rd.ResourceFlags &= ^ResourceFlagsEmptyAsset
	if rd.IsEmptyAssetFields() && hadHolding {
		rd.ResourceFlags |= ResourceFlagsEmptyAsset
	}
}

// SetAssetParams setter for asset params.
func (rd *ResourcesData) SetAssetParams(ap basics.AssetParams, haveHoldings bool) {
	rd.Total = ap.Total
	rd.Decimals = ap.Decimals
	rd.DefaultFrozen = ap.DefaultFrozen
	rd.UnitName = ap.UnitName
	rd.AssetName = ap.AssetName
	rd.URL = ap.URL
	rd.MetadataHash = ap.MetadataHash
	rd.Manager = ap.Manager
	rd.Reserve = ap.Reserve
	rd.Freeze = ap.Freeze
	rd.Clawback = ap.Clawback
	rd.ResourceFlags |= ResourceFlagsOwnership
	if !haveHoldings {
		rd.ResourceFlags |= ResourceFlagsNotHolding
	}
	rd.ResourceFlags &= ^ResourceFlagsEmptyAsset
	if rd.IsEmptyAssetFields() {
		rd.ResourceFlags |= ResourceFlagsEmptyAsset
	}
}

// GetAssetParams getter for asset params.
func (rd *ResourcesData) GetAssetParams() basics.AssetParams {
	ap := basics.AssetParams{
		Total:         rd.Total,
		Decimals:      rd.Decimals,
		DefaultFrozen: rd.DefaultFrozen,
		UnitName:      rd.UnitName,
		AssetName:     rd.AssetName,
		URL:           rd.URL,
		MetadataHash:  rd.MetadataHash,
		Manager:       rd.Manager,
		Reserve:       rd.Reserve,
		Freeze:        rd.Freeze,
		Clawback:      rd.Clawback,
	}
	return ap
}

// ClearAssetHolding clears asset holding.
func (rd *ResourcesData) ClearAssetHolding() {
	rd.Amount = 0
	rd.Frozen = false

	rd.ResourceFlags |= ResourceFlagsNotHolding
	hadParams := (rd.ResourceFlags & ResourceFlagsOwnership) == ResourceFlagsOwnership
	if hadParams && rd.IsEmptyAssetFields() {
		rd.ResourceFlags |= ResourceFlagsEmptyAsset
	} else {
		rd.ResourceFlags &= ^ResourceFlagsEmptyAsset
	}
}

// SetAssetHolding setter for asset holding.
func (rd *ResourcesData) SetAssetHolding(ah basics.AssetHolding) {
	rd.Amount = ah.Amount
	rd.Frozen = ah.Frozen
	rd.ResourceFlags &= ^(ResourceFlagsNotHolding + ResourceFlagsEmptyAsset)
	// ResourceFlagsHolding is set implicitly since it is zero
	if rd.IsEmptyAssetFields() {
		rd.ResourceFlags |= ResourceFlagsEmptyAsset
	}
}

// GetAssetHolding getter for asset holding.
func (rd *ResourcesData) GetAssetHolding() basics.AssetHolding {
	return basics.AssetHolding{
		Amount: rd.Amount,
		Frozen: rd.Frozen,
	}
}

// ClearAppLocalState clears app local state.
func (rd *ResourcesData) ClearAppLocalState() {
	rd.SchemaNumUint = 0
	rd.SchemaNumByteSlice = 0
	rd.KeyValue = nil

	rd.ResourceFlags |= ResourceFlagsNotHolding
	hadParams := (rd.ResourceFlags & ResourceFlagsOwnership) == ResourceFlagsOwnership
	if hadParams && rd.IsEmptyAppFields() {
		rd.ResourceFlags |= ResourceFlagsEmptyApp
	} else {
		rd.ResourceFlags &= ^ResourceFlagsEmptyApp
	}
}

// SetAppLocalState setter for app local state.
func (rd *ResourcesData) SetAppLocalState(als basics.AppLocalState) {
	rd.SchemaNumUint = als.Schema.NumUint
	rd.SchemaNumByteSlice = als.Schema.NumByteSlice
	rd.KeyValue = als.KeyValue
	rd.ResourceFlags &= ^(ResourceFlagsEmptyApp + ResourceFlagsNotHolding)
	if rd.IsEmptyAppFields() {
		rd.ResourceFlags |= ResourceFlagsEmptyApp
	}
}

// GetAppLocalState getter for app local state.
func (rd *ResourcesData) GetAppLocalState() basics.AppLocalState {
	return basics.AppLocalState{
		Schema: basics.StateSchema{
			NumUint:      rd.SchemaNumUint,
			NumByteSlice: rd.SchemaNumByteSlice,
		},
		KeyValue: rd.KeyValue,
	}
}

// ClearAppParams clears the app params.
func (rd *ResourcesData) ClearAppParams() {
	rd.ApprovalProgram = nil
	rd.ClearStateProgram = nil
	rd.GlobalState = nil
	rd.LocalStateSchemaNumUint = 0
	rd.LocalStateSchemaNumByteSlice = 0
	rd.GlobalStateSchemaNumUint = 0
	rd.GlobalStateSchemaNumByteSlice = 0
	rd.ExtraProgramPages = 0
	rd.Version = 0
	rd.SizeSponsor = basics.Address{}
	hadHolding := (rd.ResourceFlags & ResourceFlagsNotHolding) == ResourceFlagsHolding
	rd.ResourceFlags -= rd.ResourceFlags & ResourceFlagsOwnership
	rd.ResourceFlags &= ^ResourceFlagsEmptyApp
	if rd.IsEmptyAppFields() && hadHolding {
		rd.ResourceFlags |= ResourceFlagsEmptyApp
	}
}

// SetAppParams setter for app params.
func (rd *ResourcesData) SetAppParams(ap basics.AppParams, haveHoldings bool) {
	rd.ApprovalProgram = ap.ApprovalProgram
	rd.ClearStateProgram = ap.ClearStateProgram
	rd.GlobalState = ap.GlobalState
	rd.LocalStateSchemaNumUint = ap.LocalStateSchema.NumUint
	rd.LocalStateSchemaNumByteSlice = ap.LocalStateSchema.NumByteSlice
	rd.GlobalStateSchemaNumUint = ap.GlobalStateSchema.NumUint
	rd.GlobalStateSchemaNumByteSlice = ap.GlobalStateSchema.NumByteSlice
	rd.ExtraProgramPages = ap.ExtraProgramPages
	rd.Version = ap.Version
	rd.SizeSponsor = ap.SizeSponsor
	rd.ResourceFlags |= ResourceFlagsOwnership
	if !haveHoldings {
		rd.ResourceFlags |= ResourceFlagsNotHolding
	}
	rd.ResourceFlags &= ^ResourceFlagsEmptyApp
	if rd.IsEmptyAppFields() {
		rd.ResourceFlags |= ResourceFlagsEmptyApp
	}
}

// GetAppParams getter for app params.
func (rd *ResourcesData) GetAppParams() basics.AppParams {
	return basics.AppParams{
		ApprovalProgram:   rd.ApprovalProgram,
		ClearStateProgram: rd.ClearStateProgram,
		GlobalState:       rd.GlobalState,
		StateSchemas: basics.StateSchemas{
			LocalStateSchema: basics.StateSchema{
				NumUint:      rd.LocalStateSchemaNumUint,
				NumByteSlice: rd.LocalStateSchemaNumByteSlice,
			},
			GlobalStateSchema: basics.StateSchema{
				NumUint:      rd.GlobalStateSchemaNumUint,
				NumByteSlice: rd.GlobalStateSchemaNumByteSlice,
			},
		},
		ExtraProgramPages: rd.ExtraProgramPages,
		Version:           rd.Version,
		SizeSponsor:       rd.SizeSponsor,
	}
}

// SetAssetData setter for asset data.
func (rd *ResourcesData) SetAssetData(ap ledgercore.AssetParamsDelta, ah ledgercore.AssetHoldingDelta) {
	if ah.Holding != nil {
		rd.SetAssetHolding(*ah.Holding)
	} else if ah.Deleted {
		rd.ClearAssetHolding()
	}
	if ap.Params != nil {
		rd.SetAssetParams(*ap.Params, rd.IsHolding())
	} else if ap.Deleted {
		rd.ClearAssetParams()
	}
}

// SetAppData setter for app data.
func (rd *ResourcesData) SetAppData(ap ledgercore.AppParamsDelta, al ledgercore.AppLocalStateDelta) {
	if al.LocalState != nil {
		rd.SetAppLocalState(*al.LocalState)
	} else if al.Deleted {
		rd.ClearAppLocalState()
	}
	if ap.Params != nil {
		rd.SetAppParams(*ap.Params, rd.IsHolding())
	} else if ap.Deleted {
		rd.ClearAppParams()
	}
}

// Before compares the round numbers of two persistedAccountData and determines if the current persistedAccountData
// happened before the other.
func (pac *PersistedAccountData) Before(other *PersistedAccountData) bool {
	return pac.Round < other.Round
}

// Before compares the round numbers of two persistedResourcesData and determines if the current persistedResourcesData
// happened before the other.
func (prd *PersistedResourcesData) Before(other *PersistedResourcesData) bool {
	return prd.Round < other.Round
}

// Before compares the round numbers of two persistedKVData and determines if the current persistedKVData
// happened before the other.
func (prd PersistedKVData) Before(other *PersistedKVData) bool {
	return prd.Round < other.Round
}

// Before compares the round numbers of two persistedAccountData and determines if the current persistedAccountData
// happened before the other.
func (pac *PersistedOnlineAccountData) Before(other *PersistedOnlineAccountData) bool {
	return pac.UpdRound < other.UpdRound
}

// Encode the transaction tail data into a serialized form, and return the serialized data
// as well as the hash of the data.
func (t *TxTailRound) Encode() ([]byte, crypto.Digest) {
	tailData := protocol.Encode(t)
	hash := crypto.Hash(tailData)
	return tailData, hash
}

// TODO: this is currently public just for a test in txtail_test.go

// TxTailRoundFromBlock creates a TxTailRound for the given block
func TxTailRoundFromBlock(blk bookkeeping.Block) (*TxTailRound, error) {
	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil, err
	}

	tail := &TxTailRound{}

	tail.TxnIDs = make([]transactions.Txid, len(payset))
	tail.LastValid = make([]basics.Round, len(payset))
	tail.Hdr = blk.BlockHeader

	for txIdxtxid, txn := range payset {
		tail.TxnIDs[txIdxtxid] = txn.ID()
		tail.LastValid[txIdxtxid] = txn.Txn.LastValid
		if txn.Txn.Lease != [32]byte{} {
			tail.Leases = append(tail.Leases, TxTailRoundLease{
				Sender: txn.Txn.Sender,
				Lease:  txn.Txn.Lease,
				TxnIdx: uint64(txIdxtxid),
			})
		}
	}
	return tail, nil
}

// AccountDataResources calls outputResourceCb with the data resources for the specified account.
func AccountDataResources(
	ctx context.Context,
	accountData *basics.AccountData, rowid int64,
	outputResourceCb func(ctx context.Context, rowid int64, cidx basics.CreatableIndex, rd *ResourcesData) error,
) error {
	// handle all the assets we can find:
	for aidx, holding := range accountData.Assets {
		var rd ResourcesData
		rd.SetAssetHolding(holding)
		if ap, has := accountData.AssetParams[aidx]; has {
			rd.SetAssetParams(ap, true)
			delete(accountData.AssetParams, aidx)
		}
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}
	for aidx, aparams := range accountData.AssetParams {
		var rd ResourcesData
		rd.SetAssetParams(aparams, false)
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}

	// handle all the applications we can find:
	for aidx, localState := range accountData.AppLocalStates {
		var rd ResourcesData
		rd.SetAppLocalState(localState)
		if ap, has := accountData.AppParams[aidx]; has {
			rd.SetAppParams(ap, true)
			delete(accountData.AppParams, aidx)
		}
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}
	for aidx, aparams := range accountData.AppParams {
		var rd ResourcesData
		rd.SetAppParams(aparams, false)
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}

	return nil
}
