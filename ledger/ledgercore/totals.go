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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// AlgoCount represents a total of algos of a certain class
// of accounts (split up by their Status value).
type AlgoCount struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Sum of algos of all accounts in this class.
	Money basics.MicroAlgos `codec:"mon"`

	// Total number of whole reward units in accounts.
	RewardUnits uint64 `codec:"rwd"`
}

func (ac *AlgoCount) applyRewards(rewardsPerUnit uint64, ot *basics.OverflowTracker) {
	rewardsGottenThisRound := basics.MicroAlgos{Raw: ot.Mul(ac.RewardUnits, rewardsPerUnit)}
	ac.Money = ot.AddA(ac.Money, rewardsGottenThisRound)
}

// AccountTotals represents the totals of algos in the system
// grouped by different account status values.
type AccountTotals struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Online           AlgoCount `codec:"online"`
	Offline          AlgoCount `codec:"offline"`
	NotParticipating AlgoCount `codec:"notpart"`

	// Total number of algos received per reward unit since genesis
	RewardsLevel uint64 `codec:"rwdlvl"`
}

func (at *AccountTotals) statusField(status basics.Status) *AlgoCount {
	switch status {
	case basics.Online:
		return &at.Online
	case basics.Offline:
		return &at.Offline
	case basics.NotParticipating:
		return &at.NotParticipating
	default:
		logging.Base().Panicf("AccountTotals: unknown status %v", status)

		// Go's compiler does not know that Panicf() will not return.
		return nil
	}
}

// AddAccount adds an account algos from the total money
func (at *AccountTotals) AddAccount(proto config.ConsensusParams, data basics.AccountData, ot *basics.OverflowTracker) {
	sum := at.statusField(data.Status)
	algos, _ := data.Money(proto, at.RewardsLevel)
	sum.Money = ot.AddA(sum.Money, algos)
	sum.RewardUnits = ot.Add(sum.RewardUnits, data.MicroAlgos.RewardUnits(proto))
}

// DelAccount removes an account algos from the total money
func (at *AccountTotals) DelAccount(proto config.ConsensusParams, data basics.AccountData, ot *basics.OverflowTracker) {
	sum := at.statusField(data.Status)
	algos, _ := data.Money(proto, at.RewardsLevel)
	sum.Money = ot.SubA(sum.Money, algos)
	sum.RewardUnits = ot.Sub(sum.RewardUnits, data.MicroAlgos.RewardUnits(proto))
}

// ApplyRewards adds the reward to the account totals based on the new rewards level
func (at *AccountTotals) ApplyRewards(rewardsLevel uint64, ot *basics.OverflowTracker) {
	rewardsPerUnit := ot.Sub(rewardsLevel, at.RewardsLevel)
	at.RewardsLevel = rewardsLevel
	at.Online.applyRewards(rewardsPerUnit, ot)
	at.Offline.applyRewards(rewardsPerUnit, ot)
}

// All returns the sum of algos held under all different status values.
func (at *AccountTotals) All() basics.MicroAlgos {
	participating := at.Participating()
	res, overflowed := basics.OAddA(at.NotParticipating.Money, participating)
	if overflowed {
		logging.Base().Panicf("AccountTotals.All(): overflow %v + %v", at.NotParticipating, participating)
	}
	return res
}

// Participating returns the sum of algos held under ``participating''
// account status values (Online and Offline).  It excludes MicroAlgos held
// by NotParticipating accounts.
func (at *AccountTotals) Participating() basics.MicroAlgos {
	res, overflowed := basics.OAddA(at.Online.Money, at.Offline.Money)
	if overflowed {
		logging.Base().Panicf("AccountTotals.Participating(): overflow %v + %v", at.Online, at.Offline)
	}
	return res
}

// RewardUnits returns the sum of reward units held under ``participating''
// account status values (Online and Offline).  It excludes units held
// by NotParticipating accounts.
func (at *AccountTotals) RewardUnits() uint64 {
	res, overflowed := basics.OAdd(at.Online.RewardUnits, at.Offline.RewardUnits)
	if overflowed {
		logging.Base().Panicf("AccountTotals.RewardUnits(): overflow %v + %v", at.Online, at.Offline)
	}
	return res
}

// add adds in the delta from an algoDelta
func (ac *AlgoCount) add(delta *algoDelta, ot *basics.OverflowTracker) {
	ac.Money.Raw = ot.AddUS(ac.Money.Raw, delta.microAlgos)
	ac.RewardUnits = ot.AddUS(ac.RewardUnits, delta.rewardUnits)
}

// Add adds in the delta from an AccountTotalsDelta
func (at *AccountTotals) Add(delta *AccountTotalsDelta) error {
	if at.RewardsLevel != delta.RewardsLevel {
		return fmt.Errorf("AccountTotals.Add(): mismatched reward levels: %d != %d", at.RewardsLevel, delta.RewardsLevel)
	}

	var ot basics.OverflowTracker
	at.Online.add(&delta.online, &ot)
	at.Offline.add(&delta.offline, &ot)
	at.NotParticipating.add(&delta.notParticipating, &ot)
	if ot.Overflowed {
		return fmt.Errorf("AccountTotals.Add(): overflow")
	}

	return nil
}

// algoDelta represents a change in algos and reward units for a particular
// class of accounts (online, offline, etc).  Such deltas are used in tracking
// cumulative updates to some base totals.  These deltas are not serialized.
// Since the delta can be negative, we use int64, and in particular, we don't
// use the basics.MicroAlgos type, which is always a positive amount.
type algoDelta struct {
	microAlgos  int64
	rewardUnits int64
}

// AccountTotalsDelta represents a change to the totals of algos in the system
// grouped by different account status values.
type AccountTotalsDelta struct {
	// Change to money held by accounts of a particular status.
	online           algoDelta
	offline          algoDelta
	notParticipating algoDelta

	// Total number of algos received per reward unit since genesis
	RewardsLevel uint64
}

func (ad *AccountTotalsDelta) statusField(status basics.Status) *algoDelta {
	switch status {
	case basics.Online:
		return &ad.online
	case basics.Offline:
		return &ad.offline
	case basics.NotParticipating:
		return &ad.notParticipating
	default:
		logging.Base().Panicf("AccountTotalsDelta: unknown status %v", status)

		// Go's compiler does not know that Panicf() will not return.
		return nil
	}
}

// AddAccount adds an account to the delta
func (ad *AccountTotalsDelta) AddAccount(proto config.ConsensusParams, data basics.AccountData, ot *basics.OverflowTracker) {
	sum := ad.statusField(data.Status)
	algos, _ := data.Money(proto, ad.RewardsLevel)
	sum.microAlgos = ot.AddS(sum.microAlgos, ot.ToS(algos.Raw))
	sum.rewardUnits = ot.AddS(sum.rewardUnits, ot.ToS(data.MicroAlgos.RewardUnits(proto)))
}

// DelAccount removes an account from the delta
func (ad *AccountTotalsDelta) DelAccount(proto config.ConsensusParams, data basics.AccountData, ot *basics.OverflowTracker) {
	sum := ad.statusField(data.Status)
	algos, _ := data.Money(proto, ad.RewardsLevel)
	sum.microAlgos = ot.SubS(sum.microAlgos, ot.ToS(algos.Raw))
	sum.rewardUnits = ot.SubS(sum.rewardUnits, ot.ToS(data.MicroAlgos.RewardUnits(proto)))
}

// SetRewardsLevel initializes the new rewards level
func (ad *AccountTotalsDelta) SetRewardsLevel(newRewardsLevel uint64) {
	ad.RewardsLevel = newRewardsLevel
}

// add adds the delta from another algoDelta
func (ad *algoDelta) add(other *algoDelta, ot *basics.OverflowTracker) {
	ad.microAlgos = ot.AddS(ad.microAlgos, other.microAlgos)
	ad.rewardUnits = ot.AddS(ad.rewardUnits, other.rewardUnits)
}

// Add adds in the delta from another AccountTotalsDelta
func (ad *AccountTotalsDelta) Add(other *AccountTotalsDelta) error {
	if ad.RewardsLevel != other.RewardsLevel {
		return fmt.Errorf("AccountTotalsDelta.Add(): mismatched reward levels: %d != %d", ad.RewardsLevel, other.RewardsLevel)
	}

	var ot basics.OverflowTracker
	ad.online.add(&other.online, &ot)
	ad.offline.add(&other.offline, &ot)
	ad.notParticipating.add(&other.notParticipating, &ot)
	if ot.Overflowed {
		return fmt.Errorf("AccountTotalsDelta.Add(): overflow")
	}

	return nil
}
