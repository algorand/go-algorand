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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

func mkParams() Params {
	return Params{
		AuctionKey:       auctionKey,
		AuctionID:        5,
		NumAlgos:         10000,
		DepositRound:     1000,
		FirstRound:       1100,
		PriceChunkRounds: 100,
		NumChunks:        3,
		MaxPriceMultiple: 100,
		LastPrice:        10,
		MinBidAlgos:      1,
	}
}

func mkParams2() Params {
	return Params{
		AuctionKey:       auctionKey,
		AuctionID:        0,
		NumAlgos:         1,
		DepositRound:     0,
		FirstRound:       0,
		PriceChunkRounds: 1,
		NumChunks:        1,
		MaxPriceMultiple: 1,
		LastPrice:        1,
		MinBidAlgos:      1,
	}
}

var auctionKey crypto.Digest
var nextDepositID uint64
var nextBidID uint64

func init() {
	crypto.RandBytes(auctionKey[:])
}

func mkRunningAuction(t *testing.T) *RunningAuction {
	p := mkParams()
	ra, err := Init(p)
	require.NoError(t, err)
	return ra
}

func initError(p Params) error {
	_, err := Init(p)
	return err
}

func TestInitValidation(t *testing.T) {
	p := mkParams()
	require.NoError(t, initError(p))

	p = mkParams()
	p.NumAlgos = 0
	require.Error(t, initError(p))

	p = mkParams()
	p.DepositRound = 1200
	require.Error(t, initError(p))

	p = mkParams()
	p.FirstRound = 100
	require.Error(t, initError(p))

	p = mkParams()
	p.PriceChunkRounds = 0
	require.Error(t, initError(p))

	p = mkParams()
	p.NumChunks = 0
	require.Error(t, initError(p))

	p = mkParams()
	p.MaxPriceMultiple = 0
	require.Error(t, initError(p))

	p = mkParams2()
	require.NoError(t, initError(p))
}

func TestDepositValidation(t *testing.T) {
	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	ra := mkRunningAuction(t)
	d0 := Deposit{
		BidderKey:  bidderKey,
		Currency:   100,
		AuctionKey: auctionKey,
		AuctionID:  5,
		DepositID:  10,
	}

	// Check that duplicate deposit IDs are dropped
	require.NoError(t, ra.PlaceDeposit(d0, 1000))
	require.Error(t, ra.PlaceDeposit(d0, 1000))

	// Check that another deposit ID works
	d1 := d0
	d1.DepositID++
	require.NoError(t, ra.PlaceDeposit(d1, 1000))

	// Check round validation
	d2 := d0
	d2.DepositID = 20
	require.Error(t, ra.PlaceDeposit(d2, 999))
	require.Error(t, ra.PlaceDeposit(d2, 1400))
	require.NoError(t, ra.PlaceDeposit(d2, 1399))
	require.Error(t, ra.PlaceDeposit(d2, 1399))

	// Check auction and auction ID validation
	d3 := d0
	d3.AuctionID = 99
	d3.DepositID = 30
	require.Error(t, ra.PlaceDeposit(d3, 1000))

	d4 := d0
	crypto.RandBytes(d4.AuctionKey[:])
	d4.DepositID = 40
	require.Error(t, ra.PlaceDeposit(d4, 1000))

	// Check for overflow
	d5 := d0
	d5.DepositID = 50
	d5.Currency = 18446744073709551610
	require.Error(t, ra.PlaceDeposit(d5, 1000))

	// Check for another dispensing address, should throw an error
	var anotherKey crypto.Digest
	crypto.RandBytes(anotherKey[:])

	d6 := d0
	d6.DepositID = 30
	d6.WinningsAddress = anotherKey
	require.Error(t, ra.PlaceDeposit(d6, 1000))

	// Check for dispensing address that is different than the bidder key
	var anotherBidder crypto.Digest
	crypto.RandBytes(anotherKey[:])

	d7 := d0
	d7.DepositID = 31
	d7.BidderKey = anotherBidder
	d7.WinningsAddress = anotherKey
	require.NoError(t, ra.PlaceDeposit(d7, 1000))
	require.Equal(t, anotherKey, ra.Bidders[d7.BidderKey].WinningsAddress)
	_, ok := ra.Bidders[d7.BidderKey]
	require.True(t, ok)
	require.NotEqual(t, d7.BidderKey, ra.Bidders[d7.BidderKey].WinningsAddress)

	// Try to send onw w/o it, should throw an error
	d8 := d7
	d8.DepositID = 32
	d8.BidderKey = anotherBidder
	d8.WinningsAddress = crypto.Digest{}
	require.Error(t, ra.PlaceDeposit(d8, 1000))
}

func TestBidValidation(t *testing.T) {
	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	ra := mkRunningAuction(t)
	d0 := Deposit{
		BidderKey:  bidderKey,
		Currency:   10000,
		AuctionKey: auctionKey,
		AuctionID:  5,
		DepositID:  10,
	}

	// Initialize balance
	require.NoError(t, ra.PlaceDeposit(d0, 1000))

	b0 := Bid{
		BidderKey:   bidderKey,
		BidCurrency: 1000,
		MaxPrice:    1000,
		BidID:       5,
		AuctionKey:  auctionKey,
		AuctionID:   5,
	}

	// Check bid ID duplicates
	require.NoError(t, ra.PlaceBid(b0, 1100))
	require.Error(t, ra.PlaceBid(b0, 1100))

	// Check auction validation
	b1 := b0
	crypto.RandBytes(b1.AuctionKey[:])
	b1.BidID = 6
	require.Error(t, ra.PlaceBid(b1, 1100))

	b2 := b0
	b2.AuctionID++
	b2.BidID = 7
	require.Error(t, ra.PlaceBid(b2, 1100))

	// Check round validation
	b3 := b0
	b3.BidID = 8
	require.Error(t, ra.PlaceBid(b3, 1099))
	require.Error(t, ra.PlaceBid(b3, 1400))
	require.NoError(t, ra.PlaceBid(b3, 1399))

	// Check price validation
	b4 := b0
	b4.BidID = 9
	b4.MaxPrice = 999
	require.Error(t, ra.PlaceBid(b4, 1100))
	require.Error(t, ra.PlaceBid(b4, 1199))
	require.NoError(t, ra.PlaceBid(b4, 1200))

	// Check price descent
	b5 := b0
	b5.BidID = 10
	b5.MaxPrice = 504
	require.Error(t, ra.PlaceBid(b5, 1199))
	require.Error(t, ra.PlaceBid(b5, 1200))

	b5.MaxPrice = 505
	require.NoError(t, ra.PlaceBid(b5, 1200))

	// Check round prices
	require.True(t, ra.CurrentPrice(1100) == 1000)
	require.True(t, ra.CurrentPrice(1199) == 1000)
	require.True(t, ra.CurrentPrice(1200) == 505)
	require.True(t, ra.CurrentPrice(1299) == 505)
	require.True(t, ra.CurrentPrice(1300) == 10)
	require.True(t, ra.CurrentPrice(1399) == 10)

	// Check running out of money
	b6 := b0
	b6.BidID = 11
	b6.BidCurrency = 9000
	require.Error(t, ra.PlaceBid(b6, 1100))

	d1 := d0
	d1.DepositID++
	require.NoError(t, ra.PlaceDeposit(d1, 1100))
	require.NoError(t, ra.PlaceBid(b6, 1100))

	// Check unknown bidder
	b7 := b0
	crypto.RandBytes(b7.BidderKey[:])
	require.Error(t, ra.PlaceBid(b7, 1399))

	// Check bidding below one algo
	b8 := b0
	b8.BidID = 12
	b8.BidCurrency = 999
	require.Error(t, ra.PlaceBid(b8, 1100))
	require.Error(t, ra.PlaceBid(b8, 1200))
	b8.MaxPrice = 999
	require.NoError(t, ra.PlaceBid(b8, 1200))
}

func TestSlowPriceDecay(t *testing.T) {
	p := mkParams2()
	p.NumChunks = 100
	ra, err := Init(p)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		require.Equal(t, int(ra.CurrentPrice(uint64(i))), 1)
	}

	p.MaxPriceMultiple = 2
	ra, err = Init(p)
	require.NoError(t, err)

	require.Equal(t, int(ra.CurrentPrice(0)), 2)
	for i := 1; i < 100; i++ {
		require.Equal(t, int(ra.CurrentPrice(uint64(i))), 1)
	}

	p.MaxPriceMultiple = 3
	ra, err = Init(p)
	require.NoError(t, err)

	require.Equal(t, int(ra.CurrentPrice(0)), 3)
	for i := 1; i < 50; i++ {
		require.Equal(t, int(ra.CurrentPrice(uint64(i))), 2)
	}

	for i := 50; i < 100; i++ {
		require.Equal(t, int(ra.CurrentPrice(uint64(i))), 1)
	}
}

func placeBid(t *testing.T, ra *RunningAuction, bidder int, amount uint64, price uint64, rnd uint64) {
	var bidderKey crypto.Digest
	bidderKey[0] = byte(bidder)

	require.NoError(t, ra.PlaceDeposit(Deposit{
		BidderKey:  bidderKey,
		Currency:   amount,
		AuctionKey: auctionKey,
		AuctionID:  ra.Params.AuctionID,
		DepositID:  nextDepositID,
	}, rnd))
	require.NoError(t, ra.PlaceBid(Bid{
		BidderKey:   bidderKey,
		BidCurrency: amount,
		MaxPrice:    price,
		BidID:       nextBidID,
		AuctionKey:  auctionKey,
		AuctionID:   ra.Params.AuctionID,
	}, rnd))

	nextDepositID++
	nextBidID++
}

func won(out BidOutcomes, bidder int) uint64 {
	var bidderKey crypto.Digest
	bidderKey[0] = byte(bidder)

	var winnings uint64
	for _, x := range out.Outcomes {
		if x.BidderKey == bidderKey {
			winnings += x.AlgosWon
		}
	}

	return winnings
}

func TestSettlementBasic(t *testing.T) {
	ra := mkRunningAuction(t)
	for i := 0; i < 10; i++ {
		placeBid(t, ra, i, 1000, 1000, 1100)
	}

	out := ra.Settle(false)
	require.False(t, out.Cleared)

	require.Equal(t, out.AuctionID, ra.Params.AuctionID)
	require.True(t, out.Price == 10)
	require.Equal(t, len(out.Outcomes), 10)

	for i := 0; i < 10; i++ {
		require.Equal(t, out.Outcomes[i].WinningsAddress, out.Outcomes[i].BidderKey)
	}

	for i := 0; i < 10; i++ {
		require.True(t, won(out, i) == 100)
	}
}

func TestSettlementMultibid(t *testing.T) {
	ra := mkRunningAuction(t)
	for i := 0; i < 10; i++ {
		placeBid(t, ra, 0, 1000, 1000, 1100)
	}

	out := ra.Settle(false)
	require.False(t, out.Cleared)

	require.Equal(t, out.AuctionID, ra.Params.AuctionID)
	require.True(t, out.Price == 10)
	require.Equal(t, len(out.Outcomes), 10)
	require.True(t, won(out, 0) == 1000)
}

func TestSettlementDuringIdle(t *testing.T) {
	ra := mkRunningAuction(t)
	placeBid(t, ra, 0, 6000000, 1000, 1100)

	out := ra.Settle(false)
	require.True(t, out.Cleared)

	require.Equal(t, out.AuctionID, ra.Params.AuctionID)
	require.Equal(t, int(out.Price), 505)
	require.Equal(t, len(out.Outcomes), 1)
	require.True(t, won(out, 0) == 10000)
}

func TestSettlementDuringIdleWithFinalBid(t *testing.T) {
	ra := mkRunningAuction(t)
	placeBid(t, ra, 0, 6000000, 1000, 1100)
	placeBid(t, ra, 1, 10, 10, 1300)

	out := ra.Settle(false)
	require.True(t, out.Cleared)

	require.Equal(t, out.AuctionID, ra.Params.AuctionID)
	require.Equal(t, int(out.Price), 505)
	require.Equal(t, len(out.Outcomes), 1)
	require.True(t, won(out, 0) == 10000)
}

func TestSettlementMultibidCancel(t *testing.T) {
	ra := mkRunningAuction(t)
	for i := 0; i < 5; i++ {
		placeBid(t, ra, 0, 1000, 1000, 1100)
	}

	out := ra.Settle(true)
	require.False(t, out.Cleared)

	require.Equal(t, out.AuctionID, ra.Params.AuctionID)
	require.True(t, out.Price == 0)
	require.Equal(t, len(out.Outcomes), 0)
	require.True(t, won(out, 0) == 0)
}

func TestSettlementCancelNoBid(t *testing.T) {
	ra := mkRunningAuction(t)

	out := ra.Settle(true)
	require.False(t, out.Cleared)

	require.Equal(t, out.AuctionID, ra.Params.AuctionID)
	require.Equal(t, out.AuctionKey, ra.Params.AuctionKey)
	require.True(t, out.Price == 0)
	require.Equal(t, len(out.Outcomes), 0)
}
