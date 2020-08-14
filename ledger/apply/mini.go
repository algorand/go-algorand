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

package apply

import (
	"reflect"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// MiniAccountData is like AccountData, except it omits key-value
// stores.
type MiniAccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Status     basics.Status     `codec:"onl"`
	MicroAlgos basics.MicroAlgos `codec:"algo"`

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
	RewardedMicroAlgos basics.MicroAlgos `codec:"ern"`

	VoteID      crypto.OneTimeSignatureVerifier `codec:"vote"`
	SelectionID crypto.VRFVerifier              `codec:"sel"`

	VoteFirstValid  basics.Round `codec:"voteFst"`
	VoteLastValid   basics.Round `codec:"voteLst"`
	VoteKeyDilution uint64       `codec:"voteKD"`

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
	AssetParams map[basics.AssetIndex]basics.AssetParams `codec:"apar,allocbound=encodedMaxAssetsPerAccount"`

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
	Assets map[basics.AssetIndex]basics.AssetHolding `codec:"asset,allocbound=encodedMaxAssetsPerAccount"`

	// AuthAddr is the address against which signatures/multisigs/logicsigs should be checked.
	// If empty, the address of the account whose AccountData this is is used.
	// A transaction may change an account's AuthAddr to "re-key" the account.
	// This allows key rotation, changing the members in a multisig, etc.
	AuthAddr basics.Address `codec:"spend"`

	// TotalAppSchema stores the sum of all of the LocalStateSchemas
	// and GlobalStateSchemas in this account (global for applications
	// we created local for applications we opted in to), so that we don't
	// have to iterate over all of them to compute MinBalance.
	TotalAppSchema basics.StateSchema `codec:"tsch"`

	// AppLocalStates stores the local states associated with any applications
	// that this account has opted in to.
	AppLocalStates map[basics.AppIndex]AppLocalStateSansKV `codec:"appl,allocbound=encodedMaxAppLocalStates"`

	// AppParams stores the global parameters and state associated with any
	// applications that this account has created.
	AppParams map[basics.AppIndex]AppParamsSansKV `codec:"appp,allocbound=encodedMaxAppParams"`
}

// AppLocalState stores a cached copy of the application's LocalStateSchema
// so that MinBalance requirements may be computed 1. without looking up the
// AppParams and 2. even if the application has been deleted
type AppLocalStateSansKV struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Schema basics.StateSchema `codec:"hsch"`
}

type AppLocalState basics.AppLocalState

func (ls AppLocalState) WithoutKV() AppLocalStateSansKV {
	return AppLocalStateSansKV{Schema: ls.Schema}
}

func (ls0 AppLocalStateSansKV) ToAppLocalState() basics.AppLocalState {
	return basics.AppLocalState{Schema: ls0.Schema}
}

// AppParams stores the global information associated with an application
type AppParamsSansKV struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ApprovalProgram   []byte `codec:"approv,allocbound=config.MaxAppProgramLen"`
	ClearStateProgram []byte `codec:"clearp,allocbound=config.MaxAppProgramLen"`
	basics.StateSchemas
}

type AppParams basics.AppParams

func (gs AppParams) WithoutKV() AppParamsSansKV {
	return AppParamsSansKV{
		ApprovalProgram:   gs.ApprovalProgram,
		ClearStateProgram: gs.ClearStateProgram,
		StateSchemas:      gs.StateSchemas,
	}
}

func (gs0 AppParamsSansKV) ToAppParams() basics.AppParams {
	return basics.AppParams{
		ApprovalProgram:   gs0.ApprovalProgram,
		ClearStateProgram: gs0.ClearStateProgram,
		StateSchemas:      gs0.StateSchemas,
	}
}

type AccountData basics.AccountData

func (u AccountData) WithoutAppKV() (res MiniAccountData) {
	res.Status = u.Status
	res.MicroAlgos = u.MicroAlgos
	res.RewardsBase = u.RewardsBase
	res.RewardedMicroAlgos = u.RewardedMicroAlgos
	res.VoteID = u.VoteID
	res.SelectionID = u.SelectionID
	res.VoteFirstValid = u.VoteFirstValid
	res.VoteLastValid = u.VoteLastValid
	res.VoteKeyDilution = u.VoteKeyDilution
	res.AssetParams = u.AssetParams
	res.Assets = u.Assets
	res.AuthAddr = u.AuthAddr
	res.TotalAppSchema = u.TotalAppSchema

	res.AppLocalStates = make(map[basics.AppIndex]AppLocalStateSansKV, len(u.AppLocalStates))
	for k, v := range u.AppLocalStates {
		res.AppLocalStates[k] = AppLocalState(v).WithoutKV()
	}

	res.AppParams = make(map[basics.AppIndex]AppParamsSansKV, len(u.AppParams))
	for k, v := range u.AppParams {
		res.AppParams[k] = AppParams(v).WithoutKV()
	}

	return
}

func (u MiniAccountData) ToAccountData() (res basics.AccountData) {
	res.Status = u.Status
	res.MicroAlgos = u.MicroAlgos
	res.RewardsBase = u.RewardsBase
	res.RewardedMicroAlgos = u.RewardedMicroAlgos
	res.VoteID = u.VoteID
	res.SelectionID = u.SelectionID
	res.VoteFirstValid = u.VoteFirstValid
	res.VoteLastValid = u.VoteLastValid
	res.VoteKeyDilution = u.VoteKeyDilution
	res.AssetParams = u.AssetParams
	res.Assets = u.Assets
	res.AuthAddr = u.AuthAddr
	res.TotalAppSchema = u.TotalAppSchema

	res.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState, len(u.AppLocalStates))
	for k, v := range u.AppLocalStates {
		res.AppLocalStates[k] = v.ToAppLocalState()
	}

	res.AppParams = make(map[basics.AppIndex]basics.AppParams, len(u.AppParams))
	for k, v := range u.AppParams {
		res.AppParams[k] = v.ToAppParams()
	}

	return
}

// WithUpdatedRewards returns an updated number of algos in an AccountData
// to reflect rewards up to some rewards level.
func (u MiniAccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) MiniAccountData {
	if u.Status != basics.NotParticipating {
		var ot basics.OverflowTracker
		rewardsUnits := u.MicroAlgos.RewardUnits(proto)
		rewardsDelta := ot.Sub(rewardsLevel, u.RewardsBase)
		rewards := basics.MicroAlgos{Raw: ot.Mul(rewardsUnits, rewardsDelta)}
		u.MicroAlgos = ot.AddA(u.MicroAlgos, rewards)
		if ot.Overflowed {
			logging.Base().Panicf("AccountData.WithUpdatedRewards(): overflowed account balance when applying rewards %v + %d*(%d-%d)", u.MicroAlgos, rewardsUnits, rewardsLevel, u.RewardsBase)
		}
		u.RewardsBase = rewardsLevel
		// The total reward over the lifetime of the account could exceed a 64-bit value. As a result
		// this rewardAlgos counter could potentially roll over.
		u.RewardedMicroAlgos = basics.MicroAlgos{Raw: (u.RewardedMicroAlgos.Raw + rewards.Raw)}
	}

	return u
}

// IsZero checks if an AccountData value is the same as its zero value.
func (u MiniAccountData) IsZero() bool {
	if u.Assets != nil && len(u.Assets) == 0 {
		u.Assets = nil
	}

	return reflect.DeepEqual(u, MiniAccountData{})
}

// MinBalance computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func (u MiniAccountData) MinBalance(proto *config.ConsensusParams) (res basics.MicroAlgos) {
	var min uint64

	// First, base MinBalance
	min = proto.MinBalance

	// MinBalance for each Asset
	assetCost := basics.MulSaturate(proto.MinBalance, uint64(len(u.Assets)))
	min = basics.AddSaturate(min, assetCost)

	// Base MinBalance for each created application
	appCreationCost := basics.MulSaturate(proto.AppFlatParamsMinBalance, uint64(len(u.AppParams)))
	min = basics.AddSaturate(min, appCreationCost)

	// Base MinBalance for each opted in application
	appOptInCost := basics.MulSaturate(proto.AppFlatOptInMinBalance, uint64(len(u.AppLocalStates)))
	min = basics.AddSaturate(min, appOptInCost)

	// MinBalance for state usage measured by LocalStateSchemas and
	// GlobalStateSchemas
	schemaCost := u.TotalAppSchema.MinBalance(proto)
	min = basics.AddSaturate(min, schemaCost.Raw)

	res.Raw = min
	return res
}

// Money returns the amount of MicroAlgos associated with the user's account
func (u MiniAccountData) Money(proto config.ConsensusParams, rewardsLevel uint64) (money basics.MicroAlgos, rewards basics.MicroAlgos) {
	e := u.WithUpdatedRewards(proto, rewardsLevel)
	return e.MicroAlgos, e.RewardedMicroAlgos
}

// VotingStake returns the amount of MicroAlgos associated with the user's account
// for the purpose of participating in the Algorand protocol.  It assumes the
// caller has already updated rewards appropriately using WithUpdatedRewards().
func (u MiniAccountData) VotingStake() basics.MicroAlgos {
	if u.Status != basics.Online {
		return basics.MicroAlgos{Raw: 0}
	}

	return u.MicroAlgos
}

// KeyDilution returns the key dilution for this account,
// returning the default key dilution if not explicitly specified.
func (u MiniAccountData) KeyDilution(proto config.ConsensusParams) uint64 {
	if u.VoteKeyDilution != 0 {
		return u.VoteKeyDilution
	}

	return proto.DefaultKeyDilution
}

// TODO add reflect test to check that fields look almost the same
