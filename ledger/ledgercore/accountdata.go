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

package ledgercore

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

// AccountData provides users of the Balances interface per-account data (like basics.AccountData)
// but without any maps containing AppParams, AppLocalState, AssetHolding, or AssetParams. This
// ensures that transaction evaluation must retrieve and mutate account, asset, and application data
// separately, to better support on-disk and in-memory schemas that do not store them together.
type AccountData struct {
	AccountBaseData
	basics.VotingData
}

// AccountBaseData contains base account info like balance, status and total number of resources
type AccountBaseData struct {
	Status             basics.Status
	MicroAlgos         basics.MicroAlgos
	RewardsBase        uint64
	RewardedMicroAlgos basics.MicroAlgos
	AuthAddr           basics.Address
	IncentiveEligible  bool

	TotalAppSchema      basics.StateSchema // Totals across created globals, and opted in locals.
	TotalExtraAppPages  uint32             // Total number of extra pages across all created apps
	TotalAppParams      uint64             // Total number of apps this account has created
	TotalAppLocalStates uint64             // Total number of apps this account is opted into.
	TotalAssetParams    uint64             // Total number of assets created by this account
	TotalAssets         uint64             // Total of asset creations and optins (i.e. number of holdings)
	TotalBoxes          uint64             // Total number of boxes associated to this account
	TotalBoxBytes       uint64             // Total bytes for this account's boxes. keys _and_ values count

	LastProposed  basics.Round // The last round that this account proposed the winning block.
	LastHeartbeat basics.Round // The last round that this account sent a heartbeat to show it was online.
}

// ToAccountData returns ledgercore.AccountData from basics.AccountData
func ToAccountData(acct basics.AccountData) AccountData {
	return AccountData{
		AccountBaseData: AccountBaseData{
			Status:             acct.Status,
			MicroAlgos:         acct.MicroAlgos,
			RewardsBase:        acct.RewardsBase,
			RewardedMicroAlgos: acct.RewardedMicroAlgos,
			AuthAddr:           acct.AuthAddr,
			IncentiveEligible:  acct.IncentiveEligible,

			TotalAppSchema:      acct.TotalAppSchema,
			TotalExtraAppPages:  acct.TotalExtraAppPages,
			TotalAssetParams:    uint64(len(acct.AssetParams)),
			TotalAssets:         uint64(len(acct.Assets)),
			TotalAppParams:      uint64(len(acct.AppParams)),
			TotalAppLocalStates: uint64(len(acct.AppLocalStates)),
			TotalBoxes:          acct.TotalBoxes,
			TotalBoxBytes:       acct.TotalBoxBytes,

			LastProposed:  acct.LastProposed,
			LastHeartbeat: acct.LastHeartbeat,
		},
		VotingData: basics.VotingData{
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
	a.AuthAddr = acct.AuthAddr
	a.IncentiveEligible = acct.IncentiveEligible

	a.VoteID = acct.VoteID
	a.SelectionID = acct.SelectionID
	a.StateProofID = acct.StateProofID
	a.VoteFirstValid = acct.VoteFirstValid
	a.VoteLastValid = acct.VoteLastValid
	a.VoteKeyDilution = acct.VoteKeyDilution

	a.TotalAppSchema = acct.TotalAppSchema
	a.TotalExtraAppPages = acct.TotalExtraAppPages
	a.TotalBoxes = acct.TotalBoxes
	a.TotalBoxBytes = acct.TotalBoxBytes

	a.LastProposed = acct.LastProposed
	a.LastHeartbeat = acct.LastHeartbeat
}

// WithUpdatedRewards calls basics account data WithUpdatedRewards
func (u AccountData) WithUpdatedRewards(rewardUnit uint64, rewardsLevel uint64) AccountData {
	u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase = basics.WithUpdatedRewards(
		rewardUnit, u.Status, u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase, rewardsLevel,
	)
	return u
}

// ClearOnlineState resets the account's fields to indicate that the account is an offline account
func (u *AccountData) ClearOnlineState() {
	u.Status = basics.Offline
	u.VotingData = basics.VotingData{}
}

// Suspend sets the status to Offline, but does _not_ clear voting keys, so
// that a heartbeat can bring the account back Online
func (u *AccountData) Suspend() {
	u.Status = basics.Offline
	// To regain eligibility, the account will have to `keyreg` with the extra fee.
	u.IncentiveEligible = false
}

// Suspended returns true if the account is suspended (offline with keys)
func (u AccountData) Suspended() bool {
	return u.Status == basics.Offline && !u.VoteID.IsEmpty()
}

// LastSeen returns the last round that the account was seen online
func (u AccountData) LastSeen() basics.Round {
	return max(u.LastProposed, u.LastHeartbeat)
}

// MinBalance computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func (u AccountData) MinBalance(proto *config.ConsensusParams) basics.MicroAlgos {
	return basics.MinBalance(
		proto.BalanceRequirements(),
		u.TotalAssets,
		u.TotalAppSchema,
		u.TotalAppParams, u.TotalAppLocalStates,
		uint64(u.TotalExtraAppPages),
		u.TotalBoxes, u.TotalBoxBytes,
	)
}

// AvailableBalance returns the amount of MicroAlgos that are available for
// spending without fully closing the account.
func (u AccountData) AvailableBalance(proto *config.ConsensusParams) basics.MicroAlgos {
	if left, o := basics.OSubA(u.MicroAlgos, u.MinBalance(proto)); !o {
		return left
	}
	return basics.MicroAlgos{}
}

// IsZero checks if an AccountData value is the same as its zero value.
func (u AccountData) IsZero() bool {
	return u == AccountData{}
}

// Money is similar to basics account data Money function
func (u AccountData) Money(rewardUnit uint64, rewardsLevel uint64) (money basics.MicroAlgos, rewards basics.MicroAlgos) {
	e := u.WithUpdatedRewards(rewardUnit, rewardsLevel)
	return e.MicroAlgos, e.RewardedMicroAlgos
}

// OnlineAccountData calculates the online account data given an AccountData, by adding the rewards.
func (u AccountData) OnlineAccountData(rewardUnit uint64, rewardsLevel uint64) basics.OnlineAccountData {
	if u.Status != basics.Online {
		// if the account is not Online and agreement requests it for some reason, clear it out
		return basics.OnlineAccountData{}
	}

	microAlgos, _, _ := basics.WithUpdatedRewards(
		rewardUnit, u.Status, u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase, rewardsLevel,
	)
	return basics.OnlineAccountData{
		MicroAlgosWithRewards: microAlgos,
		VotingData:            u.VotingData,
		IncentiveEligible:     u.IncentiveEligible,
		LastProposed:          u.LastProposed,
		LastHeartbeat:         u.LastHeartbeat,
	}
}

// NormalizedOnlineBalance wraps basics.NormalizedOnlineAccountBalance
func (u *AccountData) NormalizedOnlineBalance(rewardUnit uint64) uint64 {
	return basics.NormalizedOnlineAccountBalance(u.Status, u.RewardsBase, u.MicroAlgos, rewardUnit)
}
