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

package basics

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// Status is the delegation status of an account's MicroAlgos
type Status byte

const (
	// Offline indicates that the associated account receives rewards but does not participate in the consensus.
	Offline Status = iota
	// Online indicates that the associated account participates in the consensus and receive rewards.
	Online
	// NotParticipating indicates that the associated account neither participates in the consensus, nor receives rewards.
	// Accounts that are marked as NotParticipating cannot change their status, but can receive and send Algos to other accounts.
	// Two special accounts that are defined as NotParticipating are the incentive pool (also know as rewards pool) and the fee sink.
	// These two accounts also have additional Algo transfer restrictions.
	NotParticipating

	// encodedMaxAssetsPerAccount is the decoder limit of number of assets stored per account.
	// it's being verified by the unit test TestEncodedAccountAllocationBounds to align
	// with config.Consensus[protocol.ConsensusCurrentVersion].MaxAssetsPerAccount; note that the decoded
	// parameter is used only for protecting the decoder against malicious encoded account data stream.
	// protocol-specific contains would be tested once the decoding is complete.
	encodedMaxAssetsPerAccount = 1024

	// EncodedMaxAppLocalStates is the decoder limit for number of opted-in apps in a single account.
	// It is verified in TestEncodedAccountAllocationBounds to align with
	// config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsOptedIn
	EncodedMaxAppLocalStates = 64

	// EncodedMaxAppParams is the decoder limit for number of created apps in a single account.
	// It is verified in TestEncodedAccountAllocationBounds to align with
	// config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsCreated
	EncodedMaxAppParams = 64

	// EncodedMaxKeyValueEntries is the decoder limit for the length of a key/value store.
	// It is verified in TestEncodedAccountAllocationBounds to align with
	// config.Consensus[protocol.ConsensusCurrentVersion].MaxLocalSchemaEntries and
	// config.Consensus[protocol.ConsensusCurrentVersion].MaxGlobalSchemaEntries
	EncodedMaxKeyValueEntries = 1024
)

func (s Status) String() string {
	switch s {
	case Offline:
		return "Offline"
	case Online:
		return "Online"
	case NotParticipating:
		return "Not Participating"
	}
	return ""
}

// UnmarshalStatus decodes string status value back to Status constant
func UnmarshalStatus(value string) (s Status, err error) {
	switch value {
	case "Offline":
		s = Offline
	case "Online":
		s = Online
	case "Not Participating":
		s = NotParticipating
	default:
		err = fmt.Errorf("unknown account status: %v", value)
	}
	return
}

// VotingData holds voting-related data
type VotingData struct {
	VoteID       crypto.OneTimeSignatureVerifier
	SelectionID  crypto.VRFVerifier
	StateProofID merklesignature.Commitment

	VoteFirstValid  Round
	VoteLastValid   Round
	VoteKeyDilution uint64
}

// OnlineAccountData contains the voting information for a single account.
//msgp:ignore OnlineAccountData
type OnlineAccountData struct {
	MicroAlgosWithRewards MicroAlgos
	VotingData
}

// AccountData contains the data associated with a given address.
//
// This includes the account balance, cryptographic public keys,
// consensus delegation status, asset data, and application data.
type AccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Status     Status     `codec:"onl"`
	MicroAlgos MicroAlgos `codec:"algo"`

	// RewardsBase is used to implement rewards.
	// This is not meaningful for accounts with Status=NotParticipating.
	//
	// Every block assigns some amount of rewards (algos) to every
	// participating account.  The amount is the product of how much
	// block.RewardsLevel increased from the previous block and
	// how many whole config.Protocol.RewardUnit algos this
	// account holds.
	//
	// For performance reasons, we do not want to walk over every
	// account to apply these rewards to AccountData.MicroAlgos.  Instead,
	// we defer applying the rewards until some other transaction
	// touches that participating account, and at that point, apply all
	// of the rewards to the account's AccountData.MicroAlgos.
	//
	// For correctness, we need to be able to determine how many
	// total algos are present in the system, including deferred
	// rewards (deferred in the sense that they have not been
	// reflected in the account's AccountData.MicroAlgos, as described
	// above).  To compute this total efficiently, we avoid
	// compounding rewards (i.e., no rewards on rewards) until
	// they are applied to AccountData.MicroAlgos.
	//
	// Mechanically, RewardsBase stores the block.RewardsLevel
	// whose rewards are already reflected in AccountData.MicroAlgos.
	// If the account is Status=Offline or Status=Online, its
	// effective balance (if a transaction were to be issued
	// against this account) may be higher, as computed by
	// AccountData.Money().  That function calls
	// AccountData.WithUpdatedRewards() to apply the deferred
	// rewards to AccountData.MicroAlgos.
	RewardsBase uint64 `codec:"ebase"`

	// RewardedMicroAlgos is used to track how many algos were given
	// to this account since the account was first created.
	//
	// This field is updated along with RewardBase; note that
	// it won't answer the question "how many algos did I make in
	// the past week".
	RewardedMicroAlgos MicroAlgos `codec:"ern"`

	VoteID       crypto.OneTimeSignatureVerifier `codec:"vote"`
	SelectionID  crypto.VRFVerifier              `codec:"sel"`
	StateProofID merklesignature.Commitment      `codec:"stprf"`

	VoteFirstValid  Round  `codec:"voteFst"`
	VoteLastValid   Round  `codec:"voteLst"`
	VoteKeyDilution uint64 `codec:"voteKD"`

	// If this account created an asset, AssetParams stores
	// the parameters defining that asset.  The params are indexed
	// by the Index of the AssetID; the Creator is this account's address.
	//
	// An account with any asset in AssetParams cannot be
	// closed, until the asset is destroyed.  An asset can
	// be destroyed if this account holds AssetParams.Total units
	// of that asset (in the Assets array below).
	//
	// NOTE: do not modify this value in-place in existing AccountData
	// structs; allocate a copy and modify that instead.  AccountData
	// is expected to have copy-by-value semantics.
	AssetParams map[AssetIndex]AssetParams `codec:"apar,allocbound=encodedMaxAssetsPerAccount"`

	// Assets is the set of assets that can be held by this
	// account.  Assets (i.e., slots in this map) are explicitly
	// added and removed from an account by special transactions.
	// The map is keyed by the AssetID, which is the address of
	// the account that created the asset plus a unique counter
	// to distinguish re-created assets.
	//
	// Each asset bumps the required MinBalance in this account.
	//
	// An account that creates an asset must have its own asset
	// in the Assets map until that asset is destroyed.
	//
	// NOTE: do not modify this value in-place in existing AccountData
	// structs; allocate a copy and modify that instead.  AccountData
	// is expected to have copy-by-value semantics.
	Assets map[AssetIndex]AssetHolding `codec:"asset,allocbound=encodedMaxAssetsPerAccount"`

	// AuthAddr is the address against which signatures/multisigs/logicsigs should be checked.
	// If empty, the address of the account whose AccountData this is is used.
	// A transaction may change an account's AuthAddr to "re-key" the account.
	// This allows key rotation, changing the members in a multisig, etc.
	AuthAddr Address `codec:"spend"`

	// AppLocalStates stores the local states associated with any applications
	// that this account has opted in to.
	AppLocalStates map[AppIndex]AppLocalState `codec:"appl,allocbound=EncodedMaxAppLocalStates"`

	// AppParams stores the global parameters and state associated with any
	// applications that this account has created.
	AppParams map[AppIndex]AppParams `codec:"appp,allocbound=EncodedMaxAppParams"`

	// TotalAppSchema stores the sum of all of the LocalStateSchemas
	// and GlobalStateSchemas in this account (global for applications
	// we created local for applications we opted in to), so that we don't
	// have to iterate over all of them to compute MinBalance.
	TotalAppSchema StateSchema `codec:"tsch"`

	// TotalExtraAppPages stores the extra length in pages (MaxAppProgramLen bytes per page)
	// requested for app program by this account
	TotalExtraAppPages uint32 `codec:"teap"`

	// Total number of boxes associated with this account, which implies it is an app account.
	TotalBoxes uint64 `codec:"tbx"`

	// TotalBoxBytes stores the sum of all len(keys) and len(values) of Boxes
	TotalBoxBytes uint64 `codec:"tbxb"`
}

// AppLocalState stores the LocalState associated with an application. It also
// stores a cached copy of the application's LocalStateSchema so that
// MinBalance requirements may be computed 1. without looking up the
// AppParams and 2. even if the application has been deleted
type AppLocalState struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Schema   StateSchema  `codec:"hsch"`
	KeyValue TealKeyValue `codec:"tkv"`
}

// AppParams stores the global information associated with an application
type AppParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ApprovalProgram   []byte       `codec:"approv,allocbound=config.MaxAvailableAppProgramLen"`
	ClearStateProgram []byte       `codec:"clearp,allocbound=config.MaxAvailableAppProgramLen"`
	GlobalState       TealKeyValue `codec:"gs"`
	StateSchemas
	ExtraProgramPages uint32 `codec:"epp"`
}

// StateSchemas is a thin wrapper around the LocalStateSchema and the
// GlobalStateSchema, since they are often needed together
type StateSchemas struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	LocalStateSchema  StateSchema `codec:"lsch"`
	GlobalStateSchema StateSchema `codec:"gsch"`
}

// Clone returns a copy of some AppParams that may be modified without
// affecting the original
func (ap *AppParams) Clone() (res AppParams) {
	res = *ap
	res.ApprovalProgram = make([]byte, len(ap.ApprovalProgram))
	copy(res.ApprovalProgram, ap.ApprovalProgram)
	res.ClearStateProgram = make([]byte, len(ap.ClearStateProgram))
	copy(res.ClearStateProgram, ap.ClearStateProgram)
	res.GlobalState = ap.GlobalState.Clone()
	return
}

// Clone returns a copy of some AppLocalState that may be modified without
// affecting the original
func (al *AppLocalState) Clone() (res AppLocalState) {
	res = *al
	res.KeyValue = al.KeyValue.Clone()
	return
}

// AccountDetail encapsulates meaningful details about a given account, for external consumption
type AccountDetail struct {
	Address Address
	Algos   MicroAlgos
	Status  Status
}

// SupplyDetail encapsulates meaningful details about the ledger's current token supply
type SupplyDetail struct {
	Round       Round
	TotalMoney  MicroAlgos
	OnlineMoney MicroAlgos
}

// BalanceDetail encapsulates meaningful details about the current balances of the ledger, for external consumption
type BalanceDetail struct {
	Round       Round
	TotalMoney  MicroAlgos
	OnlineMoney MicroAlgos
	Accounts    []AccountDetail
}

// AssetIndex is the unique integer index of an asset that can be used to look
// up the creator of the asset, whose balance record contains the AssetParams
type AssetIndex uint64

// AppIndex is the unique integer index of an application that can be used to
// look up the creator of the application, whose balance record contains the
// AppParams
type AppIndex uint64

// CreatableIndex represents either an AssetIndex or AppIndex, which come from
// the same namespace of indices as each other (both assets and apps are
// "creatables")
type CreatableIndex uint64

// CreatableType is an enum representing whether or not a given creatable is an
// application or an asset
type CreatableType uint64

const (
	// AssetCreatable is the CreatableType corresponding to assets
	// This value must be 0 to align with the applications database
	// upgrade. At migration time, we set the default 'ctype' column of the
	// creators table to 0 so that existing assets have the correct type.
	AssetCreatable CreatableType = 0

	// AppCreatable is the CreatableType corresponds to apps
	AppCreatable CreatableType = 1
)

// CreatableLocator stores both the creator, whose balance record contains
// the asset/app parameters, and the creatable index, which is the key into
// those parameters
type CreatableLocator struct {
	Type    CreatableType
	Creator Address
	Index   CreatableIndex
}

// AssetHolding describes an asset held by an account.
type AssetHolding struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Amount uint64 `codec:"a"`
	Frozen bool   `codec:"f"`
}

// AssetParams describes the parameters of an asset.
type AssetParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Total specifies the total number of units of this asset
	// created.
	Total uint64 `codec:"t"`

	// Decimals specifies the number of digits to display after the decimal
	// place when displaying this asset. A value of 0 represents an asset
	// that is not divisible, a value of 1 represents an asset divisible
	// into tenths, and so on. This value must be between 0 and 19
	// (inclusive).
	Decimals uint32 `codec:"dc"`

	// DefaultFrozen specifies whether slots for this asset
	// in user accounts are frozen by default or not.
	DefaultFrozen bool `codec:"df"`

	// UnitName specifies a hint for the name of a unit of
	// this asset.
	UnitName string `codec:"un"`

	// AssetName specifies a hint for the name of the asset.
	AssetName string `codec:"an"`

	// URL specifies a URL where more information about the asset can be
	// retrieved
	URL string `codec:"au"`

	// MetadataHash specifies a commitment to some unspecified asset
	// metadata. The format of this metadata is up to the application.
	MetadataHash [32]byte `codec:"am"`

	// Manager specifies an account that is allowed to change the
	// non-zero addresses in this AssetParams.
	Manager Address `codec:"m"`

	// Reserve specifies an account whose holdings of this asset
	// should be reported as "not minted".
	Reserve Address `codec:"r"`

	// Freeze specifies an account that is allowed to change the
	// frozen state of holdings of this asset.
	Freeze Address `codec:"f"`

	// Clawback specifies an account that is allowed to take units
	// of this asset from any account.
	Clawback Address `codec:"c"`
}

// ToBeHashed implements crypto.Hashable
func (app AppIndex) ToBeHashed() (protocol.HashID, []byte) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(app))
	return protocol.AppIndex, buf
}

// Address yields the "app address" of the app
func (app AppIndex) Address() Address {
	return Address(crypto.HashObj(app))
}

// MakeAccountData returns a UserToken
func MakeAccountData(status Status, algos MicroAlgos) AccountData {
	return AccountData{Status: status, MicroAlgos: algos}
}

// Money returns the amount of MicroAlgos associated with the user's account
func (u AccountData) Money(proto config.ConsensusParams, rewardsLevel uint64) (money MicroAlgos, rewards MicroAlgos) {
	e := u.WithUpdatedRewards(proto, rewardsLevel)
	return e.MicroAlgos, e.RewardedMicroAlgos
}

// PendingRewards computes the amount of rewards (in microalgos) that
// have yet to be added to the account balance.
func PendingRewards(ot *OverflowTracker, proto config.ConsensusParams, microAlgos MicroAlgos, rewardsBase uint64, rewardsLevel uint64) MicroAlgos {
	rewardsUnits := microAlgos.RewardUnits(proto)
	rewardsDelta := ot.Sub(rewardsLevel, rewardsBase)
	return MicroAlgos{Raw: ot.Mul(rewardsUnits, rewardsDelta)}
}

// WithUpdatedRewards returns an updated number of algos, total rewards and new rewards base
// to reflect rewards up to some rewards level.
func WithUpdatedRewards(
	proto config.ConsensusParams, status Status, microAlgosIn MicroAlgos, rewardedMicroAlgosIn MicroAlgos, rewardsBaseIn uint64, rewardsLevelIn uint64,
) (MicroAlgos, MicroAlgos, uint64) {
	if status == NotParticipating {
		return microAlgosIn, rewardedMicroAlgosIn, rewardsBaseIn
	}

	var ot OverflowTracker
	rewardsUnits := microAlgosIn.RewardUnits(proto)
	rewardsDelta := ot.Sub(rewardsLevelIn, rewardsBaseIn)
	rewards := MicroAlgos{Raw: ot.Mul(rewardsUnits, rewardsDelta)}
	microAlgosOut := ot.AddA(microAlgosIn, rewards)
	if ot.Overflowed {
		logging.Base().Panicf("AccountData.WithUpdatedRewards(): overflowed account balance when applying rewards %v + %d*(%d-%d)", microAlgosIn, rewardsUnits, rewardsLevelIn, rewardsBaseIn)
	}
	rewardsBaseOut := rewardsLevelIn
	// The total reward over the lifetime of the account could exceed a 64-bit value. As a result
	// this rewardAlgos counter could potentially roll over.
	rewardedMicroAlgosOut := MicroAlgos{Raw: rewardedMicroAlgosIn.Raw + rewards.Raw}
	return microAlgosOut, rewardedMicroAlgosOut, rewardsBaseOut
}

// WithUpdatedRewards returns an updated number of algos in an AccountData
// to reflect rewards up to some rewards level.
func (u AccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) AccountData {
	u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase = WithUpdatedRewards(
		proto, u.Status, u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase, rewardsLevel,
	)

	return u
}

// MinBalance computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func (u AccountData) MinBalance(proto *config.ConsensusParams) (res MicroAlgos) {
	return MinBalance(
		proto,
		uint64(len(u.Assets)),
		u.TotalAppSchema,
		uint64(len(u.AppParams)), uint64(len(u.AppLocalStates)),
		uint64(u.TotalExtraAppPages),
		u.TotalBoxes, u.TotalBoxBytes,
	)
}

// MinBalance computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func MinBalance(
	proto *config.ConsensusParams,
	totalAssets uint64,
	totalAppSchema StateSchema,
	totalAppParams uint64, totalAppLocalStates uint64,
	totalExtraAppPages uint64,
	totalBoxes uint64, totalBoxBytes uint64,
) (res MicroAlgos) {
	var min uint64

	// First, base MinBalance
	min = proto.MinBalance

	// MinBalance for each Asset
	assetCost := MulSaturate(proto.MinBalance, totalAssets)
	min = AddSaturate(min, assetCost)

	// Base MinBalance for each created application
	appCreationCost := MulSaturate(proto.AppFlatParamsMinBalance, totalAppParams)
	min = AddSaturate(min, appCreationCost)

	// Base MinBalance for each opted in application
	appOptInCost := MulSaturate(proto.AppFlatOptInMinBalance, totalAppLocalStates)
	min = AddSaturate(min, appOptInCost)

	// MinBalance for state usage measured by LocalStateSchemas and
	// GlobalStateSchemas
	schemaCost := totalAppSchema.MinBalance(proto)
	min = AddSaturate(min, schemaCost.Raw)

	// MinBalance for each extra app program page
	extraAppProgramLenCost := MulSaturate(proto.AppFlatParamsMinBalance, totalExtraAppPages)
	min = AddSaturate(min, extraAppProgramLenCost)

	// Base MinBalance for each created box
	boxBaseCost := MulSaturate(proto.BoxFlatMinBalance, totalBoxes)
	min = AddSaturate(min, boxBaseCost)

	// Per byte MinBalance for boxes
	boxByteCost := MulSaturate(proto.BoxByteMinBalance, totalBoxBytes)
	min = AddSaturate(min, boxByteCost)

	res.Raw = min
	return res
}

// OnlineAccountData returns subset of AccountData as OnlineAccountData data structure.
// Account is expected to be Online otherwise its is cleared out
func (u AccountData) OnlineAccountData() OnlineAccountData {
	if u.Status != Online {
		// if the account is not Online and agreement requests it for some reason, clear it out
		return OnlineAccountData{}
	}

	return OnlineAccountData{
		MicroAlgosWithRewards: u.MicroAlgos,
		VotingData: VotingData{
			VoteID:          u.VoteID,
			SelectionID:     u.SelectionID,
			StateProofID:    u.StateProofID,
			VoteFirstValid:  u.VoteFirstValid,
			VoteLastValid:   u.VoteLastValid,
			VoteKeyDilution: u.VoteKeyDilution,
		},
	}
}

// VotingStake returns the amount of MicroAlgos associated with the user's account
// for the purpose of participating in the Algorand protocol.  It assumes the
// caller has already updated rewards appropriately using WithUpdatedRewards().
func (u OnlineAccountData) VotingStake() MicroAlgos {
	return u.MicroAlgosWithRewards
}

// KeyDilution returns the key dilution for this account,
// returning the default key dilution if not explicitly specified.
func (u OnlineAccountData) KeyDilution(proto config.ConsensusParams) uint64 {
	if u.VoteKeyDilution != 0 {
		return u.VoteKeyDilution
	}

	return proto.DefaultKeyDilution
}

// IsZero checks if an AccountData value is the same as its zero value.
func (u AccountData) IsZero() bool {
	if u.Assets != nil && len(u.Assets) == 0 {
		u.Assets = nil
	}

	return reflect.DeepEqual(u, AccountData{})
}

// NormalizedOnlineBalance returns a ``normalized'' balance for this account.
//
// The normalization compensates for rewards that have not yet been applied,
// by computing a balance normalized to round 0.  To normalize, we estimate
// the microalgo balance that an account should have had at round 0, in order
// to end up at its current balance when rewards are included.
//
// The benefit of the normalization procedure is that an account's normalized
// balance does not change over time (unlike the actual algo balance that includes
// rewards).  This makes it possible to compare normalized balances between two
// accounts, to sort them, and get results that are close to what we would get
// if we computed the exact algo balance of the accounts at a given round number.
//
// The normalization can lead to some inconsistencies in comparisons between
// account balances, because the growth rate of rewards for accounts depends
// on how recently the account has been touched (our rewards do not implement
// compounding).  However, online accounts have to periodically renew
// participation keys, so the scale of the inconsistency is small.
func (u AccountData) NormalizedOnlineBalance(proto config.ConsensusParams) uint64 {
	return NormalizedOnlineAccountBalance(u.Status, u.RewardsBase, u.MicroAlgos, proto)
}

// NormalizedOnlineAccountBalance returns a ``normalized'' balance for an account
// with the given parameters.
//
// The normalization compensates for rewards that have not yet been applied,
// by computing a balance normalized to round 0.  To normalize, we estimate
// the microalgo balance that an account should have had at round 0, in order
// to end up at its current balance when rewards are included.
//
// The benefit of the normalization procedure is that an account's normalized
// balance does not change over time (unlike the actual algo balance that includes
// rewards).  This makes it possible to compare normalized balances between two
// accounts, to sort them, and get results that are close to what we would get
// if we computed the exact algo balance of the accounts at a given round number.
//
// The normalization can lead to some inconsistencies in comparisons between
// account balances, because the growth rate of rewards for accounts depends
// on how recently the account has been touched (our rewards do not implement
// compounding).  However, online accounts have to periodically renew
// participation keys, so the scale of the inconsistency is small.
func NormalizedOnlineAccountBalance(status Status, rewardsBase uint64, microAlgos MicroAlgos, genesisProto config.ConsensusParams) uint64 {
	if status != Online {
		return 0
	}

	// If this account had one RewardUnit of microAlgos in round 0, it would
	// have perRewardUnit microAlgos at the account's current rewards level.
	perRewardUnit := rewardsBase + genesisProto.RewardUnit

	// To normalize, we compute, mathematically,
	// u.MicroAlgos / perRewardUnit * proto.RewardUnit, as
	// (u.MicroAlgos * proto.RewardUnit) / perRewardUnit.
	norm, overflowed := Muldiv(microAlgos.ToUint64(), genesisProto.RewardUnit, perRewardUnit)

	// Mathematically should be impossible to overflow
	// because perRewardUnit >= proto.RewardUnit, as long
	// as u.RewardBase isn't huge enough to cause overflow..
	if overflowed {
		logging.Base().Panicf("overflow computing normalized balance %d * %d / (%d + %d)",
			microAlgos.ToUint64(), genesisProto.RewardUnit, rewardsBase, genesisProto.RewardUnit)
	}

	return norm
}

// BalanceRecord pairs an account's address with its associated data.
type BalanceRecord struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Addr Address `codec:"addr"`

	AccountData
}

// ToBeHashed implements the crypto.Hashable interface
func (u BalanceRecord) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.BalanceRecord, protocol.Encode(&u)
}
