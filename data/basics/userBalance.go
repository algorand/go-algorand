// Copyright (C) 2019 Algorand, Inc.
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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// Status is the delegation status of an account's MicroAlgos
type Status byte

const (
	// Offline indicates that the associated account is delegated.
	Offline Status = iota
	// Online indicates that the associated account used as part of the delegation pool.
	Online
	// NotParticipating indicates that the associated account is neither a delegator nor a delegate. Currently it is reserved for the incentive pool.
	NotParticipating
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

// AccountData contains the data associated with a given address.
//
// This includes the account balance, delegation keys, delegation status, and a custom note.
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

	VoteID      crypto.OneTimeSignatureVerifier `codec:"vote"`
	SelectionID crypto.VRFVerifier              `codec:"sel"`

	VoteFirstValid  Round  `codec:"voteFst"`
	VoteLastValid   Round  `codec:"voteLst"`
	VoteKeyDilution uint64 `codec:"voteKD"`
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

// MakeAccountData returns a UserToken
func MakeAccountData(status Status, algos MicroAlgos) AccountData {
	return AccountData{Status: status, MicroAlgos: algos}
}

// Money returns the amount of MicroAlgos associated with the user's account
func (u AccountData) Money(proto config.ConsensusParams, rewardsLevel uint64) (money MicroAlgos, rewards MicroAlgos) {
	e := u.WithUpdatedRewards(proto, rewardsLevel)
	return e.MicroAlgos, e.RewardedMicroAlgos
}

// WithUpdatedRewards returns an updated number of algos in an AccountData
// to reflect rewards up to some rewards level.
func (u AccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) AccountData {
	if u.Status != NotParticipating {
		var ot OverflowTracker
		rewardsUnits := u.MicroAlgos.RewardUnits(proto)
		rewardsDelta := ot.Sub(rewardsLevel, u.RewardsBase)
		rewards := MicroAlgos{Raw: ot.Mul(rewardsUnits, rewardsDelta)}
		u.MicroAlgos = ot.AddA(u.MicroAlgos, rewards)
		if ot.Overflowed {
			logging.Base().Panicf("AccountData.WithUpdatedRewards(): overflowed account balance when applying rewards %v + %d*(%d-%d)", u.MicroAlgos, rewardsUnits, rewardsLevel, u.RewardsBase)
		}
		u.RewardsBase = rewardsLevel
		// The total reward over the lifetime of the account could exceed a 64-bit value. As a result
		// this rewardAlgos counter could potentially roll over.
		u.RewardedMicroAlgos = MicroAlgos{Raw: (u.RewardedMicroAlgos.Raw + rewards.Raw)}
	}

	return u
}

// VotingStake returns the amount of MicroAlgos associated with the user's account
// for the purpose of participating in the Algorand protocol.  It assumes the
// caller has already updated rewards appropriately using WithUpdatedRewards().
func (u AccountData) VotingStake() MicroAlgos {
	if u.Status != Online {
		return MicroAlgos{Raw: 0}
	}

	return u.MicroAlgos
}

// KeyDilution returns the key dilution for this account,
// returning the default key dilution if not explicitly specified.
func (u AccountData) KeyDilution(proto config.ConsensusParams) uint64 {
	if u.VoteKeyDilution != 0 {
		return u.VoteKeyDilution
	}

	return proto.DefaultKeyDilution
}

// BalanceRecord pairs an account's address with its associated data.
type BalanceRecord struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Addr Address `codec:"addr"`

	AccountData
}

// ToBeHashed implements the crypto.Hashable interface
func (u BalanceRecord) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.BalanceRecord, protocol.Encode(u)
}
