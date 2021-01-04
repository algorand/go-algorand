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

package auction

import (
	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
)

// SerializedRunningAuction provides a wrapper around RunningAuction
// and guarantees that all calls to RunningAuction are serialized.
type SerializedRunningAuction struct {
	*RunningAuction
	mu deadlock.RWMutex
}

// MakeSerializedLogic initializes a SerSerializedRunningAuction
func MakeSerializedLogic(params Params) (*SerializedRunningAuction, error) {
	sra := SerializedRunningAuction{}

	ra, err := Init(params)
	if err != nil {
		return &SerializedRunningAuction{}, err
	}

	sra.RunningAuction = ra
	return &sra, nil
}

// LastRound provides a wrapper for RunningAuction's LastRound
func (sra *SerializedRunningAuction) LastRound() uint64 {
	sra.mu.RLock()
	defer sra.mu.RUnlock()

	return sra.RunningAuction.LastRound()
}

// CurrentPrice provides a wrapper for RunningAuction's CurrentPrice
func (sra *SerializedRunningAuction) CurrentPrice(rnd uint64) uint64 {
	sra.mu.RLock()
	defer sra.mu.RUnlock()

	return sra.RunningAuction.CurrentPrice(rnd)
}

// PlaceDeposit provides a wrapper for RunningAuction's PlaceDeposit
func (sra *SerializedRunningAuction) PlaceDeposit(d Deposit, rnd uint64) (err error) {
	sra.mu.Lock()
	defer sra.mu.Unlock()

	return sra.RunningAuction.PlaceDeposit(d, rnd)
}

// PlaceSignedDeposit provides a wrapper for RunningAuction's PlaceSignedDeposit
func (sra *SerializedRunningAuction) PlaceSignedDeposit(sd SignedDeposit, rnd uint64) (err error) {
	sra.mu.Lock()
	defer sra.mu.Unlock()

	return sra.RunningAuction.PlaceSignedDeposit(sd, rnd)
}

// PlaceBid provides a wrapper for RunningAuction's PlaceBid
func (sra *SerializedRunningAuction) PlaceBid(b Bid, rnd uint64) (err error) {
	sra.mu.Lock()
	defer sra.mu.Unlock()

	return sra.RunningAuction.PlaceBid(b, rnd)
}

// PlaceSignedBid provides a wrapper for RunningAuction's PlaceSignedBid
func (sra *SerializedRunningAuction) PlaceSignedBid(sb SignedBid, rnd uint64) (err error) {
	sra.mu.Lock()
	defer sra.mu.Unlock()

	return sra.RunningAuction.PlaceSignedBid(sb, rnd)
}

// Settle provides a wrapper for RunningAuction's Settle
func (sra *SerializedRunningAuction) Settle(cancel bool) BidOutcomes {
	sra.mu.Lock()
	defer sra.mu.Unlock()

	return sra.RunningAuction.Settle(cancel)
}

// Balance provides a wrapper for RunningAuction's Balance
func (sra *SerializedRunningAuction) Balance(addr crypto.Digest) uint64 {
	sra.mu.Lock()
	defer sra.mu.Unlock()

	return sra.RunningAuction.Balance(addr)
}

// Cleared provides a wrapper for RunningAuction's Cleared
func (sra *SerializedRunningAuction) Cleared() bool {
	sra.mu.RLock()
	defer sra.mu.RUnlock()

	return sra.RunningAuction.Cleared()
}

// Params provides a wrapper for RunningAuction's Params
func (sra *SerializedRunningAuction) Params() Params {
	sra.mu.RLock()
	defer sra.mu.RUnlock()

	return sra.RunningAuction.Params
}

// Bids provides a wrapper for RunningAuction's Bids
func (sra *SerializedRunningAuction) Bids() []RunningBid {
	sra.mu.RLock()
	defer sra.mu.RUnlock()

	var bids []RunningBid

	for rnd := sra.RunningAuction.Params.FirstRound; rnd <= sra.RunningAuction.LastRound(); rnd++ {
		bids = append(bids, sra.RunningAuction.Bids[rnd]...)
	}

	return bids
}
