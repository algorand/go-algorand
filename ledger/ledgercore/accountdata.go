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

package ledgercore

import (
	"reflect"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
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

	TotalAppSchema      basics.StateSchema // Totals across created globals, and opted in locals.
	TotalExtraAppPages  uint32             // Total number of extra pages across all created apps
	TotalAppParams      uint64             // Total number of apps this account has created
	TotalAppLocalStates uint64             // Total number of apps this account is opted into.
	TotalAssetParams    uint64             // Total number of assets created by this account
	TotalAssets         uint64             // Total of asset creations and optins (i.e. number of holdings)
	TotalBoxes          uint64             // Total number of boxes associated to this account
	TotalBoxBytes       uint64             // Total bytes for this account's boxes. keys _and_ values count
}

// VotingData holds participation information
type VotingData struct {
	VoteID       crypto.OneTimeSignatureVerifier
	SelectionID  crypto.VRFVerifier
	StateProofID merklesignature.Verifier

	VoteFirstValid  basics.Round
	VoteLastValid   basics.Round
	VoteKeyDilution uint64

	// MicroAlgosWithReward basics.MicroAlgos
}

// ToAccountData returns ledgercore.AccountData from basics.AccountData
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
			TotalAssetParams:    uint64(len(acct.AssetParams)),
			TotalAssets:         uint64(len(acct.Assets)),
			TotalAppParams:      uint64(len(acct.AppParams)),
			TotalAppLocalStates: uint64(len(acct.AppLocalStates)),
		},
		VotingData: VotingData{
			VoteID:          acct.VoteID,
			SelectionID:     acct.SelectionID,
			StateProofID:    acct.StateProofID,
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
	a.StateProofID = acct.StateProofID
	a.VoteFirstValid = acct.VoteFirstValid
	a.VoteLastValid = acct.VoteLastValid
	a.VoteKeyDilution = acct.VoteKeyDilution

	a.AuthAddr = acct.AuthAddr
	a.TotalAppSchema = acct.TotalAppSchema
	a.TotalExtraAppPages = acct.TotalExtraAppPages
}

// WithUpdatedRewards calls basics account data WithUpdatedRewards
func (u AccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) AccountData {
	u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase = basics.WithUpdatedRewards(
		proto, u.Status, u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase, rewardsLevel,
	)
	return u
}

// ClearOnlineState resets the account's fields to indicate that the account is an offline account
func (u *AccountData) ClearOnlineState() {
	u.Status = basics.Offline
	u.VotingData = VotingData{}
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
		u.TotalBoxes, u.TotalBoxBytes,
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
	if u.Status != basics.Online {
		// if the account is not Online and agreement requests it for some reason, clear it out
		return basics.OnlineAccountData{}
	}

	microAlgos, _, _ := basics.WithUpdatedRewards(
		proto, u.Status, u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase, rewardsLevel,
	)
	return basics.OnlineAccountData{
		MicroAlgosWithRewards: microAlgos,
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
