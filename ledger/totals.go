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

package ledger

import (
	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// AlgoCount represents a total of algos of a certain class
// of accounts (split up by their Status value).
type AlgoCount struct {
	// Sum of algos of all accounts in this class.
	Money basics.MicroAlgos

	// Total number of whole reward units in accounts.
	RewardUnits uint64
}

func (ac *AlgoCount) applyRewards(rewardsPerUnit uint64, ot *basics.OverflowTracker) {
	rewardsGottenThisRound := basics.MicroAlgos{Raw: ot.Mul(ac.RewardUnits, rewardsPerUnit)}
	ac.Money = ot.AddA(ac.Money, rewardsGottenThisRound)
}

// AccountTotals represents the totals of algos in the system
// grouped by different account status values.
type AccountTotals struct {
	Online           AlgoCount
	Offline          AlgoCount
	NotParticipating AlgoCount

	// Total number of algos received per reward unit since genesis
	RewardsLevel uint64
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

func (at *AccountTotals) addAccount(proto config.ConsensusParams, data basics.AccountData, ot *basics.OverflowTracker) {
	sum := at.statusField(data.Status)
	algos, _ := data.Money(proto, at.RewardsLevel)
	sum.Money = ot.AddA(sum.Money, algos)
	sum.RewardUnits = ot.Add(sum.RewardUnits, data.MicroAlgos.RewardUnits(proto))
}

func (at *AccountTotals) delAccount(proto config.ConsensusParams, data basics.AccountData, ot *basics.OverflowTracker) {
	sum := at.statusField(data.Status)
	algos, _ := data.Money(proto, at.RewardsLevel)
	sum.Money = ot.SubA(sum.Money, algos)
	sum.RewardUnits = ot.Sub(sum.RewardUnits, data.MicroAlgos.RewardUnits(proto))
}

func (at *AccountTotals) applyRewards(rewardsLevel uint64, ot *basics.OverflowTracker) {
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

// CanMarshalMsg implements msgp.Marshaler
func (AccountTotals) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(AccountTotals)
	return ok
}

// MarshalMsg implements msgp.Marshaler
func (at AccountTotals) MarshalMsg(b []byte) (o []byte, err error) {
	o, err = at.Online.MarshalMsg(b)
	if err != nil {
		return
	}
	o, err = at.Offline.MarshalMsg(o)
	if err != nil {
		return
	}
	o, err = at.NotParticipating.MarshalMsg(o)
	if err != nil {
		return
	}
	o = msgp.Require(o, msgp.Uint64Size)
	o = msgp.AppendUint64(o, at.RewardsLevel)
	return
}

// CanUnmarshalMsg implements msgp.Unmarshaler
func (*AccountTotals) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*AccountTotals)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (at *AccountTotals) UnmarshalMsg(bts []byte) (o []byte, err error) {
	bts, err = at.Online.UnmarshalMsg(bts)
	if err != nil {
		return bts, err
	}
	bts, err = at.Offline.UnmarshalMsg(bts)
	if err != nil {
		return bts, err
	}
	bts, err = at.NotParticipating.UnmarshalMsg(bts)
	if err != nil {
		return bts, err
	}
	at.RewardsLevel, o, err = msgp.ReadUint64Bytes(bts)
	return
}

// MarshalMsg implements msgp.Marshaler
func (ac AlgoCount) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, msgp.Uint64Size*2)
	o = msgp.AppendUint64(o, ac.Money.Raw)
	o = msgp.AppendUint64(o, ac.RewardUnits)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (ac *AlgoCount) UnmarshalMsg(bts []byte) (o []byte, err error) {
	ac.Money.Raw, o, err = msgp.ReadUint64Bytes(bts)
	if err != nil {
		return o, err
	}
	ac.RewardUnits, o, err = msgp.ReadUint64Bytes(o)
	return
}
