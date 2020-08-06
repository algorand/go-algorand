// Copyright (C) 2020 Algorand, Inc.
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
	"bytes"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// An onlineAccount corresponds to an account whose AccountData.Status
// is Online.  This is used for a Merkle tree commitment of online
// accounts, which is subsequently used to validate participants for
// a compact certificate.
type onlineAccount struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// These are a subset of the fields from the corresponding AccountData.
	MicroAlgos      basics.MicroAlgos               `codec:"algo"`
	RewardsBase     uint64                          `codec:"ebase"`
	VoteID          crypto.OneTimeSignatureVerifier `codec:"vote"`
	VoteFirstValid  basics.Round                    `codec:"voteFst"`
	VoteLastValid   basics.Round                    `codec:"voteLst"`
	VoteKeyDilution uint64                          `codec:"voteKD"`
}

// normalizedBalance returns a ``normalized'' balance for this account.
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
func (oa onlineAccount) normBalance(proto config.ConsensusParams) uint64 {
	// If this account had one RewardUnit of microAlgos in round 0, it would
	// have perRewardUnit microAlgos at the account's current rewards level.
	perRewardUnit := oa.RewardsBase + proto.RewardUnit

	// To normalize, we compute, mathematically,
	// oa.MicroAlgos / perRewardUnit * proto.RewardUnit, as
	// (oa.MicroAlgos * proto.RewardUnit) / perRewardUnit.
	norm, overflowed := basics.Muldiv(oa.MicroAlgos.ToUint64(), proto.RewardUnit, perRewardUnit)

	// Mathematically should be impossible to overflow
	// because perRewardUnit >= proto.RewardUnit, as long
	// as oa.RewardBase isn't huge enough to cause overflow..
	if overflowed {
		logging.Base().Panicf("overflow computing normalized balance %d * %d / (%d + %d)",
			oa.MicroAlgos.ToUint64(), proto.RewardUnit, oa.RewardsBase, proto.RewardUnit)
	}

	return norm
}

// onlineAccountWithAddress is used to sort accounts by normalized balance + address.
type onlineAccountWithAddress struct {
	oa          *onlineAccount
	addr        basics.Address
	normBalance uint64
}

// onlineTopHeap implements heap.Interface for tracking top N online accounts.
type onlineTopHeap struct {
	accts []onlineAccountWithAddress
}

// Len implements sort.Interface
func (h *onlineTopHeap) Len() int {
	return len(h.accts)
}

// Less implements sort.Interface
func (h *onlineTopHeap) Less(i, j int) bool {
	// For the heap, "less" means the element is returned earlier by Pop(),
	// so we actually implement "greater-than" here.
	ibal := h.accts[i].normBalance
	jbal := h.accts[j].normBalance

	if ibal > jbal {
		return true
	}
	if ibal < jbal {
		return false
	}

	bcmp := bytes.Compare(h.accts[i].addr[:], h.accts[j].addr[:])
	if bcmp > 0 {
		return true
	}

	return false
}

// Swap implements sort.Interface
func (h *onlineTopHeap) Swap(i, j int) {
	h.accts[i], h.accts[j] = h.accts[j], h.accts[i]
}

// Push implements heap.Interface
func (h *onlineTopHeap) Push(x interface{}) {
	h.accts = append(h.accts, x.(onlineAccountWithAddress))
}

// Pop implements heap.Interface
func (h *onlineTopHeap) Pop() interface{} {
	res := h.accts[len(h.accts)-1]
	h.accts = h.accts[:len(h.accts)-1]
	return res
}
