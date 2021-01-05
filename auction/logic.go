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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

// RunningBid keeps track of an outstanding bid.
type RunningBid struct {
	// Bidder represents the bidder's key.
	Bidder crypto.Digest

	// Currency represents the bid's amount of external currency.
	Currency uint64

	// BidID represents the bid ID
	BidID uint64
}

// BidderState keeps track of the different data points for each bidder
type BidderState struct {
	// WinningsAddresses keeps track of the of each bidder's winnings address
	WinningsAddress crypto.Digest

	// DepositAmount keeps track of the deposit amounts for
	// every bidder.
	DepositAmount uint64

	// PlacedBidIDs keeps track of bids placed by a bidder.
	PlacedBidIDs []uint64
}

// RunningAuction keeps track of the state of an in-progress auction.
type RunningAuction struct {
	// Params specifies the initial parameters
	Params Params

	// DepositIDs keeps track of deposits that have been made.
	DepositIDs map[uint64]struct{}

	// Bidders keeps track of every bidder'a data.
	Bidders map[crypto.Digest]BidderState

	// Bids keeps track of the bids so far, by round in which
	// the bid was placed.
	Bids map[uint64][]RunningBid

	// TotalCurrency keeps track of the sum of all bids in Bids
	// (in units of external currency, e.g., USD).  This is tracked
	// to ensure that settlement arithmetic cannot overflow.
	TotalCurrency uint64

	// Outcome describes the outcome of the auction. Outcome is set only
	// after the auction was settled.
	Outcome *BidOutcomes
}

// validate checks some ad-hoc invariants on the Params object.
func validate(p Params) error {
	if p.DepositRound > p.FirstRound {
		return fmt.Errorf("DepositRound %d > FirstRound %d", p.DepositRound, p.FirstRound)
	}

	if p.NumAlgos == 0 {
		return fmt.Errorf("NumAlgos == 0")
	}

	if p.PriceChunkRounds == 0 {
		return fmt.Errorf("PriceChunkRounds == 0")
	}

	if p.NumChunks == 0 {
		return fmt.Errorf("NumChunks == 0")
	}

	if p.MaxPriceMultiple == 0 {
		return fmt.Errorf("MaxPriceMultiple == 0")
	}

	maxPrice, overflowed := basics.OMul(p.LastPrice, p.MaxPriceMultiple)
	if overflowed {
		return fmt.Errorf("MaxPrice overflow: %d * %d", p.LastPrice, p.MaxPriceMultiple)
	}

	_, overflowed = basics.OMul(p.NumAlgos, maxPrice)
	if overflowed {
		return fmt.Errorf("NumAlgos * MaxPrice overflow: %d * (%d * %d)", p.NumAlgos, p.LastPrice, p.MaxPriceMultiple)
	}

	if p.MinBidAlgos == 0 {
		return fmt.Errorf("MinBidAlgos == 0")
	}

	return nil
}

// Init initializes an auction.
func Init(p Params) (*RunningAuction, error) {
	err := validate(p)
	if err != nil {
		return nil, err
	}

	ra := &RunningAuction{}
	ra.Params = p
	ra.DepositIDs = make(map[uint64]struct{})
	ra.Bidders = make(map[crypto.Digest]BidderState)
	ra.Bids = make(map[uint64][]RunningBid)

	return ra, nil
}

// InitSigned checks the signature on a SignedParams and then calls Init.
// As with VerifySignedParams(), it does not check the AuctionID.
func InitSigned(sp SignedParams, auctionKey crypto.Digest) (*RunningAuction, error) {
	if !VerifySignedParams(sp, auctionKey) {
		return nil, fmt.Errorf("signature mismatch on SignedParams")
	}

	return Init(sp.Params)
}

// LastRound computes the last round for valid deposits and bids.
func (ra *RunningAuction) LastRound() uint64 {
	return ra.Params.FirstRound + ra.Params.NumChunks*ra.Params.PriceChunkRounds - 1
}

// CurrentPrice computes the current unit price (external currency per Algo)
// in a particular round [rnd] for a running auction.
func (ra *RunningAuction) CurrentPrice(rnd uint64) uint64 {
	if rnd < ra.Params.FirstRound {
		panic("CurrentPrice undefined for rounds before FirstRound")
	}

	if rnd > ra.LastRound() {
		panic("CurrentPrice undefined for rounds after LastRound")
	}

	// Compute the chunk in which [rnd] falls for this auction.
	chunkNum := (rnd - ra.Params.FirstRound) / ra.Params.PriceChunkRounds

	// How many chunk price increase steps are we away from the
	// LastPrice (reserve)?
	chunksToEnd := ra.Params.NumChunks - chunkNum - 1

	// We want to compute the price increase over LastPrice for this
	// chunk.  The total increase from LastPrice to the first chunk
	// is:
	//
	//   x := LastPrice * (MaxPriceMultiple-1)
	//
	// With arbitrary-precision real numbers, each chunk step would
	// thus increase the price by:
	//
	//   y := x / (ra.Params.NumChunks-1)
	//
	// because there are NumChunks-1 steps between NumChunks chunks.
	// And finally, the increase for our case would be
	//
	//   z := y * chunksToEnd
	//
	// To minimize rounding error, we do all of the multiplication
	// first, followed by the division, and we overflow-check the
	// multiplication just in case (mostly to guard against auction
	// configuration errors).

	// Already checked for possible overflow in validate().
	x := ra.Params.LastPrice * (ra.Params.MaxPriceMultiple - 1)

	w, overflowed := basics.OMul(x, chunksToEnd)
	if overflowed {
		panic("Overflow while computing chunk increase")
	}

	// Guard against an auction with a single chunk: avoiding divide-by-zero.
	var z uint64
	if w == 0 {
		z = 0
	} else {
		z = w / (ra.Params.NumChunks - 1)
	}

	return ra.Params.LastPrice + z
}

// PlaceDeposit handles a Deposit message [d] from round [rnd].
// The return value indicates if the message was processed
// (valid) or not (invalid).
//
// A deposit is considered valid iff:
// - The deposit is for the correct auction key and ID.
// - The deposit is placed in an allowed round (DepositRound to LastRound).
// - The deposit has not been deposited before (by DepositID).
// - The deposit does not overflow the bidder's balance.
func (ra *RunningAuction) PlaceDeposit(d Deposit, rnd uint64) (err error) {
	if d.AuctionKey != ra.Params.AuctionKey {
		err = fmt.Errorf("tried to place a deposit with mismatched auctionkey (deposit was regarding %v but tracker is concerned with %v. Dropping message", d.AuctionKey.String(), ra.Params.AuctionKey.String())
		log.Error(err)
		return
	}

	if d.AuctionID != ra.Params.AuctionID {
		err = fmt.Errorf("tried to place a deposit with mismatched auctionID (deposit was regarding auction %d but tracker is concerned with auction %d), dropping message", d.AuctionID, ra.Params.AuctionID)
		log.Error(err)
		return
	}

	if rnd < ra.Params.DepositRound || rnd > ra.LastRound() {
		err = fmt.Errorf("tried to place a deposit with mismatched deposit round. Round: %d. Valid range: %d - %d, dropping message", rnd, ra.Params.DepositRound, ra.LastRound())
		log.Error(err)
		return
	}

	_, deposited := ra.DepositIDs[d.DepositID]
	if deposited {
		err = fmt.Errorf("tried to place a deposit, but a deposit with ID %d has already been placed, dropping message", d.DepositID)
		log.Error(err)
		return
	}

	bidder := ra.Bidders[d.BidderKey]

	// Winning key update - if we see a deposit from a bidder for the first time,
	// we update its winnings address.
	// ** A winning key cannot be updated during an auction
	if bidder.WinningsAddress.IsZero() {
		// New bidder
		bidder.WinningsAddress = d.WinningAddress()
	} else {
		// Check that we don't try to change the dispensing address
		if bidder.WinningsAddress != d.WinningAddress() {
			err = fmt.Errorf("tried to place a deposit, but a received a different winning address %v than current %v, dropping message", d.WinningAddress(), bidder.WinningsAddress)
			log.Error(err)
			return
		}
	}

	newAmount, overflowed := basics.OAdd(bidder.DepositAmount, d.Currency)
	if overflowed {
		err = fmt.Errorf("deposit would cause overflow, dropping message")
		log.Error(err)
		return
	}

	ra.DepositIDs[d.DepositID] = struct{}{}
	bidder.DepositAmount = newAmount
	ra.Bidders[d.BidderKey] = bidder
	return
}

// PlaceSignedDeposit checks the signature on a SignedDeposit and calls
// PlaceDeposit if the signature check passes.
func (ra *RunningAuction) PlaceSignedDeposit(sd SignedDeposit, rnd uint64) (err error) {
	if !ra.Params.VerifySignedDeposit(sd) {
		err = fmt.Errorf("failed to verify signed deposit with id %+v", sd)
		log.Error(err)
		return
	}

	return ra.PlaceDeposit(sd.Deposit, rnd)
}

// PlaceBid handles a Bid message [b] from round [rnd].  The return value
// indicates if the message was processed (valid) or not (invalid).
//
// A bid is considered valid iff:
// - The bid is for the correct auction key and ID.
// - The bid's round is between the auction's first and the last round.
// - The bid price is at least as high as the current round's price.
// - The bid amount does not exceed the bidder's currency balance.
// - The bid has at least enough currency for one algo at the current price.
// - The bid has not been already placed (duplicate BidID).
// - The bid does not overflow the total currency.
func (ra *RunningAuction) PlaceBid(b Bid, rnd uint64) (err error) {
	if b.AuctionKey != ra.Params.AuctionKey {
		err = fmt.Errorf("tried to place a bid with mismatched auctionkey (deposit was regarding %v, but tracker is concerned with %v, dropping message", b.AuctionKey.String(), ra.Params.AuctionKey.String())
		log.Error(err)
		return
	}

	if b.AuctionID != ra.Params.AuctionID {
		err = fmt.Errorf("tried to place a bid with mismatched AuctionID. Bid's auctionID: %d. Tracker's auctionID: %d, dropping message", b.AuctionID, ra.Params.AuctionID)
		log.Error(err)
		return
	}

	if rnd < ra.Params.FirstRound || rnd > ra.LastRound() {
		err = fmt.Errorf("tried to place a bid with mismatched deposit round. Round: %d. Valid range: %d - %d, dropping message", rnd, ra.Params.FirstRound, ra.LastRound())
		log.Error(err)
		return
	}

	if b.MaxPrice < ra.CurrentPrice(rnd) {
		err = fmt.Errorf("tried to place a bid with bad price (bid's max price of %d is less than current price of %d, dropping message", b.MaxPrice, ra.CurrentPrice(rnd))
		log.Error(err)
		return
	}

	minBidCurrency, overflowed := basics.OMul(b.MaxPrice, ra.Params.MinBidAlgos)
	if overflowed {
		err = fmt.Errorf("overflow in computing minBidCurrency = %d * %d, dropping message", b.MaxPrice, ra.Params.MinBidAlgos)
		log.Error(err)
		return
	}

	if b.BidCurrency < minBidCurrency {
		err = fmt.Errorf("the amount of bid currency %d is not enough for MinBidAlgos %d at price %d, dropping message", b.BidCurrency, ra.Params.MinBidAlgos, b.MaxPrice)
		log.Error(err)
		return
	}

	bidder := ra.Bidders[b.BidderKey]

	if b.BidCurrency > bidder.DepositAmount {
		err = fmt.Errorf("the amount of bid currency %d exceeds the deposited amount %d, dropping message", b.BidCurrency, bidder.DepositAmount)
		log.Error(err)
		return
	}

	bidIDs := bidder.PlacedBidIDs
	for _, id := range bidIDs {
		if id == b.BidID {
			err = fmt.Errorf("already have a bid with bidID %d, dropping message", b.BidID)
			log.Error(err)
			return
		}
	}
	bidIDs = append(bidIDs, b.BidID)

	newTotalCurrency, overflowed := basics.OAdd(ra.TotalCurrency, b.BidCurrency)
	if overflowed {
		err = fmt.Errorf("the bid overflows the total currency, dropping message")
		log.Error(err)
		return
	}

	bidder.PlacedBidIDs = bidIDs
	bidder.DepositAmount -= b.BidCurrency
	ra.TotalCurrency = newTotalCurrency
	ra.Bidders[b.BidderKey] = bidder
	ra.Bids[rnd] = append(ra.Bids[rnd], RunningBid{
		Bidder:   b.BidderKey,
		Currency: b.BidCurrency,
		BidID:    b.BidID,
	})
	return
}

// PlaceSignedBid checks the signature on a SignedBid and calls PlaceBid
// if the signature check passes.
func (ra *RunningAuction) PlaceSignedBid(sb SignedBid, rnd uint64) (err error) {
	if !ra.Params.VerifySignedBid(sb) {
		err = fmt.Errorf("failed to verify signed bid with id %+v", sb)
		log.Error(err)
		return
	}

	return ra.PlaceBid(sb.Bid, rnd)
}

// currencyTarget computes the target external currency for the auction
// at the price as of round [rnd].
func (ra *RunningAuction) currencyTarget(rnd uint64) uint64 {
	// Overflow checked in Init().
	return ra.Params.NumAlgos * ra.CurrentPrice(rnd)
}

// Settle settles the auction, after all of the auction's rounds have
// completed.  Returns the bid outcomes, which includes the cleared flag.
//
// Settle should *NOT* be called before the last round has passed any
// time the cancel flag isn't true.
func (ra *RunningAuction) Settle(cancel bool) BidOutcomes {
	if cancel {
		return ra.cancel()
	}

	var finalPrice uint64
	var cleared bool
	var winningBids []RunningBid
	var winningCurrency uint64

	for rnd := ra.Params.FirstRound; rnd <= ra.LastRound(); rnd++ {
		for _, bid := range ra.Bids[rnd] {
			winningCurrency += bid.Currency
			winningBids = append(winningBids, bid)
		}

		if winningCurrency >= ra.currencyTarget(rnd) {
			finalPrice = ra.CurrentPrice(rnd)
			cleared = true
			break
		}
	}

	// If the auction does not clear in any round, settle in last round.
	if !cleared {
		// This computes out to ra.Params.LastPrice.
		finalPrice = ra.CurrentPrice(ra.LastRound())
	}

	out := BidOutcomes{}
	out.AuctionKey = ra.Params.AuctionKey
	out.AuctionID = ra.Params.AuctionID
	out.Price = finalPrice
	out.Cleared = cleared

	algosAvailable := ra.Params.NumAlgos
	for _, bid := range winningBids {
		wonAlgos := bid.Currency / finalPrice
		if wonAlgos > algosAvailable {
			wonAlgos = algosAvailable
		}

		if wonAlgos >= ra.Params.MinBidAlgos {
			out.Outcomes = append(out.Outcomes, BidderOutcome{
				BidderKey:       bid.Bidder,
				AlgosWon:        wonAlgos,
				BidID:           bid.BidID,
				WinningsAddress: ra.Bidders[bid.Bidder].WinningsAddress,
			})

			algosAvailable -= wonAlgos
		}
	}

	ra.Outcome = &out
	return out
}

// Cancel cancels the current auction and returns the canceled BidOutcomes message
func (ra *RunningAuction) cancel() BidOutcomes {
	out := BidOutcomes{}
	out.AuctionKey = ra.Params.AuctionKey
	out.AuctionID = ra.Params.AuctionID

	ra.Outcome = &out
	return out
}

// Cleared returns true if the auction is cleared, false otherwise
func (ra *RunningAuction) Cleared() bool {
	if ra.Outcome != nil {
		return ra.Outcome.Cleared
	}

	panic("Cleared was called before auction was settled")
}

// Balance returns an address' balance, if the user hasn't deposit, it reruns 0
func (ra *RunningAuction) Balance(addr crypto.Digest) uint64 {
	return ra.Bidders[addr].DepositAmount
}
