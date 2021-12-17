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

package ledgercore

import (
	"reflect"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

// AccountData provides users of the Balances interface per-account data (like basics.AccountData)
// but without any maps containing AppParams, AppLocalState, AssetHolding, or AssetParams. This
// ensures that transaction evaluation must retrieve and mutate account, asset, and application data
// separately, to better support on-disk and in-memory schemas that do not store them together.
type AccountData struct {
	AccountBaseData
	VotingData
}

// AccountBaseData contains base account info like balance, status and total number of resources
type AccountBaseData struct {
	Status             basics.Status
	MicroAlgos         basics.MicroAlgos
	RewardsBase        uint64
	RewardedMicroAlgos basics.MicroAlgos
	AuthAddr           basics.Address

	TotalAppSchema      basics.StateSchema
	TotalExtraAppPages  uint32
	TotalAppParams      uint32
	TotalAppLocalStates uint32
	TotalAssetParams    uint32
	TotalAssets         uint32
}

// VotingData holds participation information
type VotingData struct {
	VoteID      crypto.OneTimeSignatureVerifier
	SelectionID crypto.VRFVerifier

	VoteFirstValid  basics.Round
	VoteLastValid   basics.Round
	VoteKeyDilution uint64

	// MicroAlgosWithReward basics.MicroAlgos
}

// ToAccountData returns apply.AccountData from basics.AccountData
func ToAccountData(acct basics.AccountData) AccountData {
	return AccountData{
		AccountBaseData: AccountBaseData{
			Status:             acct.Status,
			MicroAlgos:         acct.MicroAlgos,
			RewardsBase:        acct.RewardsBase,
			RewardedMicroAlgos: acct.RewardedMicroAlgos,

			AuthAddr: acct.AuthAddr,

			TotalAppSchema:      acct.TotalAppSchema,
			TotalExtraAppPages:  acct.TotalExtraAppPages,
			TotalAssetParams:    uint32(len(acct.AssetParams)),
			TotalAssets:         uint32(len(acct.Assets)),
			TotalAppParams:      uint32(len(acct.AppParams)),
			TotalAppLocalStates: uint32(len(acct.AppLocalStates)),
		},
		VotingData: VotingData{
			VoteID:          acct.VoteID,
			SelectionID:     acct.SelectionID,
			VoteFirstValid:  acct.VoteFirstValid,
			VoteLastValid:   acct.VoteLastValid,
			VoteKeyDilution: acct.VoteKeyDilution,
		},
	}
}

// AssignAccountData assigns the contents of AccountData to the fields in basics.AccountData,
// but does not touch the AppParams, AppLocalState, AssetHolding, or AssetParams data.
func AssignAccountData(a *basics.AccountData, acct AccountData) {
	a.Status = acct.Status
	a.MicroAlgos = acct.MicroAlgos
	a.RewardsBase = acct.RewardsBase
	a.RewardedMicroAlgos = acct.RewardedMicroAlgos

	a.VoteID = acct.VoteID
	a.SelectionID = acct.SelectionID
	a.VoteFirstValid = acct.VoteFirstValid
	a.VoteLastValid = acct.VoteLastValid
	a.VoteKeyDilution = acct.VoteKeyDilution

	a.AuthAddr = acct.AuthAddr
	a.TotalAppSchema = acct.TotalAppSchema
	a.TotalExtraAppPages = acct.TotalExtraAppPages
}

// WithUpdatedRewards calls basics account data WithUpdatedRewards
func (u AccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) AccountData {
	ad := basics.AccountData{
		Status:             u.Status,
		MicroAlgos:         u.MicroAlgos,
		RewardsBase:        u.RewardsBase,
		RewardedMicroAlgos: u.RewardedMicroAlgos,
	}
	ad = ad.WithUpdatedRewards(proto, rewardsLevel)

	u.MicroAlgos = ad.MicroAlgos
	u.RewardsBase = ad.RewardsBase
	u.RewardedMicroAlgos = ad.RewardedMicroAlgos
	return u
}

// ClearOnlineState resets the account's fields to indicate that the account is an offline account
func (u *AccountData) ClearOnlineState() {
	u.Status = basics.Offline
	u.VoteFirstValid = basics.Round(0)
	u.VoteLastValid = basics.Round(0)
	u.VoteKeyDilution = 0
	u.VoteID = crypto.OneTimeSignatureVerifier{}
	u.SelectionID = crypto.VRFVerifier{}
}

// MinBalance computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func (u AccountData) MinBalance(proto *config.ConsensusParams) (res basics.MicroAlgos) {
	return basics.MinBalance(
		proto,
		uint64(u.TotalAssets),
		u.TotalAppSchema,
		uint64(u.TotalAppParams), uint64(u.TotalAppLocalStates),
		uint64(u.TotalExtraAppPages),
	)
}

// IsZero checks if an AccountData value is the same as its zero value.
func (u AccountData) IsZero() bool {
	return reflect.DeepEqual(u, AccountData{})
}

// Money is similar to basics account data Money function
func (u AccountData) Money(proto config.ConsensusParams, rewardsLevel uint64) (money basics.MicroAlgos, rewards basics.MicroAlgos) {
	e := u.WithUpdatedRewards(proto, rewardsLevel)
	return e.MicroAlgos, e.RewardedMicroAlgos
}

// OnlineAccountData calculates the online account data given an AccountData, by adding the rewards.
func (u *AccountData) OnlineAccountData(proto config.ConsensusParams, rewardsLevel uint64) basics.OnlineAccountData {
	x := basics.AccountData{
		Status:             u.Status,
		MicroAlgos:         u.MicroAlgos,
		RewardsBase:        u.RewardsBase,
		RewardedMicroAlgos: u.RewardedMicroAlgos,
	}
	x = x.WithUpdatedRewards(proto, rewardsLevel)
	return basics.OnlineAccountData{
		MicroAlgosWithRewards: x.MicroAlgos,
		VoteID:                u.VoteID,
		SelectionID:           u.SelectionID,
		VoteFirstValid:        u.VoteFirstValid,
		VoteLastValid:         u.VoteLastValid,
		VoteKeyDilution:       u.VoteKeyDilution,
	}
}

// NormalizedOnlineBalance wraps basics.NormalizedOnlineAccountBalance
func (u *AccountData) NormalizedOnlineBalance(proto config.ConsensusParams) uint64 {
	return basics.NormalizedOnlineAccountBalance(u.Status, u.RewardsBase, u.MicroAlgos, proto)
}
