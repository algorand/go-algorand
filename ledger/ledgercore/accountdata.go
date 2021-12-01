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
func (ad AccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) AccountData {
	u := basics.AccountData{
		Status:             ad.Status,
		MicroAlgos:         ad.MicroAlgos,
		RewardsBase:        ad.RewardsBase,
		RewardedMicroAlgos: ad.RewardedMicroAlgos,
	}
	u = u.WithUpdatedRewards(proto, rewardsLevel)

	ad.MicroAlgos = u.MicroAlgos
	ad.RewardsBase = u.RewardsBase
	ad.RewardedMicroAlgos = u.RewardedMicroAlgos
	return ad
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
	var min uint64

	// First, base MinBalance
	min = proto.MinBalance

	// MinBalance for each Asset
	assetCost := basics.MulSaturate(proto.MinBalance, uint64(u.TotalAssets))
	min = basics.AddSaturate(min, assetCost)

	// Base MinBalance for each created application
	appCreationCost := basics.MulSaturate(proto.AppFlatParamsMinBalance, uint64(u.TotalAppParams))
	min = basics.AddSaturate(min, appCreationCost)

	// Base MinBalance for each opted in application
	appOptInCost := basics.MulSaturate(proto.AppFlatOptInMinBalance, uint64(u.TotalAppLocalStates))
	min = basics.AddSaturate(min, appOptInCost)

	// MinBalance for state usage measured by LocalStateSchemas and
	// GlobalStateSchemas
	schemaCost := u.TotalAppSchema.MinBalance(proto)
	min = basics.AddSaturate(min, schemaCost.Raw)

	// MinBalance for each extra app program page
	extraAppProgramLenCost := basics.MulSaturate(proto.AppFlatParamsMinBalance, uint64(u.TotalExtraAppPages))
	min = basics.AddSaturate(min, extraAppProgramLenCost)

	res.Raw = min
	return res
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
