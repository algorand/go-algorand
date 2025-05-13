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

package config

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

/* Functions that simplify the ways that ConsensusParams affect rewards */

// RewardUnits returns the number of reward units in some number of algos
func (proto ConsensusParams) RewardUnits(a basics.MicroAlgos) uint64 {
	return a.Raw / proto.RewardUnit
}

// Money returns the amount of MicroAlgos associated with the user's account
func (proto ConsensusParams) Money(u basics.AccountData, rewardsLevel uint64) (money basics.MicroAlgos, rewards basics.MicroAlgos) {
	e := proto.WithUpdatedRewards(u, rewardsLevel)
	return e.MicroAlgos, e.RewardedMicroAlgos
}

// PendingRewards computes the amount of rewards (in microalgos) that
// have yet to be added to the account balance.
func (proto ConsensusParams) PendingRewards(ot *basics.OverflowTracker, microAlgos basics.MicroAlgos, rewardsBase uint64, rewardsLevel uint64) basics.MicroAlgos {
	rewardsUnits := proto.RewardUnits(microAlgos)
	rewardsDelta := ot.Sub(rewardsLevel, rewardsBase)
	return basics.MicroAlgos{Raw: ot.Mul(rewardsUnits, rewardsDelta)}
}

// WithUpdatedRewards returns an updated number of algos, total rewards and new rewards base
// to reflect rewards up to some rewards level.
func WithUpdatedRewards(
	proto ConsensusParams, status basics.Status, microAlgosIn basics.MicroAlgos, rewardedMicroAlgosIn basics.MicroAlgos, rewardsBaseIn uint64, rewardsLevelIn uint64,
) (basics.MicroAlgos, basics.MicroAlgos, uint64) {
	if status == basics.NotParticipating {
		return microAlgosIn, rewardedMicroAlgosIn, rewardsBaseIn
	}

	var ot basics.OverflowTracker
	rewardsUnits := proto.RewardUnits(microAlgosIn)
	rewardsDelta := ot.Sub(rewardsLevelIn, rewardsBaseIn)
	rewards := basics.MicroAlgos{Raw: ot.Mul(rewardsUnits, rewardsDelta)}
	microAlgosOut := ot.AddA(microAlgosIn, rewards)
	if ot.Overflowed {
		panic(fmt.Sprintf("AccountData.WithUpdatedRewards(): overflowed account balance when applying rewards %v + %d*(%d-%d)", microAlgosIn, rewardsUnits, rewardsLevelIn, rewardsBaseIn))
	}
	rewardsBaseOut := rewardsLevelIn
	// The total reward over the lifetime of the account could exceed a 64-bit
	// value. As a result this rewardAlgos counter could potentially roll over.
	rewardedMicroAlgosOut := basics.MicroAlgos{Raw: rewardedMicroAlgosIn.Raw + rewards.Raw}
	return microAlgosOut, rewardedMicroAlgosOut, rewardsBaseOut
}

// WithUpdatedRewards returns an updated number of algos in an AccountData
// to reflect rewards up to some rewards level.
func (proto ConsensusParams) WithUpdatedRewards(u basics.AccountData, rewardsLevel uint64) basics.AccountData {
	u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase = WithUpdatedRewards(
		proto, u.Status, u.MicroAlgos, u.RewardedMicroAlgos, u.RewardsBase, rewardsLevel,
	)

	return u
}

// NormalizedOnlineBalance returns a “normalized” balance for this account.
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
func (proto ConsensusParams) NormalizedOnlineBalance(u basics.AccountData) uint64 {
	return NormalizedOnlineAccountBalance(u.Status, u.RewardsBase, u.MicroAlgos, proto)
}

// NormalizedOnlineAccountBalance returns a “normalized” balance for an account
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
func NormalizedOnlineAccountBalance(status basics.Status, rewardsBase uint64, microAlgos basics.MicroAlgos, proto ConsensusParams) uint64 {
	if status != basics.Online {
		return 0
	}

	// If this account had one RewardUnit of microAlgos in round 0, it would
	// have perRewardUnit microAlgos at the account's current rewards level.
	perRewardUnit := rewardsBase + proto.RewardUnit

	// To normalize, we compute, mathematically,
	// u.MicroAlgos / perRewardUnit * proto.RewardUnit, as
	// (u.MicroAlgos * proto.RewardUnit) / perRewardUnit.
	norm, overflowed := basics.Muldiv(microAlgos.ToUint64(), proto.RewardUnit, perRewardUnit)

	// Mathematically should be impossible to overflow
	// because perRewardUnit >= proto.RewardUnit, as long
	// as u.RewardBase isn't huge enough to cause overflow..
	if overflowed {
		panic(fmt.Sprintf("overflow computing normalized balance %d * %d / (%d + %d)",
			microAlgos.ToUint64(), proto.RewardUnit, rewardsBase, proto.RewardUnit))
	}

	return norm
}
