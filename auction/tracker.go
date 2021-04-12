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
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var (
	log = logging.Base()
)

// State represents the state of the auction
//msgp:ignore State
type State int

const (
	// Uninitialized indicates that no auction has started
	Uninitialized State = iota

	// Active indicates that the auction is currently running and accepting bids and deposits
	Active

	// Closed indicates that the auction does not accepts bids nor deposits but has not settled yet
	Closed

	// Settled indicates that the auction is settled
	Settled
)

// Tracker is in charge of the running auction. Tracker holds the state of all seen auctions.
// Each auction is modeled as a simple FSM with 4 states defined above with the following transitions:
// - Uninitialized -> Active | Params
// - Active -> Active  | Bid, Deposit
// - Active -> Closed  | round has passed but no settlement message was received yet
// - Active -> Settled | Settlement
// - Closed -> Settled | Settlement
// - Settled -> Active | Params
type Tracker struct {
	// Auctions is a map from AuctionID to a RunningAuction.
	// It may not be modified after initialization.
	Auctions map[uint64]*SerializedRunningAuction

	// AuctionKey is the Auctioneer's address.
	// It may not be modified after initialization.
	AuctionKey basics.Address

	// lastRound indicates the last round the tracker has seen.
	lastRound uint64

	// lastAuction indicates the last auction the tracker has seen.
	lastAuction uint64

	// Auctions and AuctionKey are constant after initialization,
	// so this guards access to lastRound and lastAuction.
	mu deadlock.Mutex
}

// MakeTracker initialized an Tracker
func MakeTracker(startRound uint64, auctionKey string) (*Tracker, error) {
	am := Tracker{}
	am.lastRound = startRound

	ak, err := basics.UnmarshalChecksumAddress(auctionKey)
	if err != nil {
		return nil, err
	}

	am.Auctions = make(map[uint64]*SerializedRunningAuction)
	am.AuctionKey = ak
	return &am, nil
}

// ProcessMessage gets a transaction, decodes its note field,
// checks for signature validity and places it in Tracker.
func (am *Tracker) ProcessMessage(txn v1.Transaction) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	from, err := basics.UnmarshalChecksumAddress(txn.From)
	if err != nil {
		return fmt.Errorf("failed to unmarshal %s - %v", from, err)
	}

	dec := protocol.NewDecoderBytes(txn.Note)

	for {
		var msg NoteField
		err = dec.Decode(&msg)
		if err != nil {
			break
		}

		switch msg.Type {
		case NoteParams:
			if crypto.Digest(from) != msg.SignedParams.Params.AuctionKey {
				log.Warn("Params message is not from the auction key, dropping message.")
				continue
			}

			if !VerifySignedParams(msg.SignedParams, crypto.Digest(am.AuctionKey)) {
				log.Warn("Signature verification failed, dropping params message.")
				continue
			}

			if !am.placeParams(msg.SignedParams.Params, txn.ConfirmedRound) {
				log.Warn("Placing params failed, dropping message.")
				continue
			}

		case NoteDeposit:
			auctionID := msg.SignedDeposit.Deposit.AuctionID
			if _, ok := am.Auctions[auctionID]; !ok {
				log.Warnf("Invalid auction ID %v, dropping deposit message", auctionID)
				continue
			}

			if !am.Auctions[auctionID].Params().VerifySignedDeposit(msg.SignedDeposit) {
				log.Warn("Signature verification failed, dropping deposit message.")
				continue
			}

			if err = am.placeDeposit(msg.SignedDeposit.Deposit, txn.ConfirmedRound); err != nil {
				log.Warnf("Placing deposit failed, dropping message, err: %v", err)
				continue
			}

		case NoteBid:
			auctionID := msg.SignedBid.Bid.AuctionID
			if _, ok := am.Auctions[auctionID]; !ok {
				log.Warnf("Invalid auction ID %v, dropping bid message", auctionID)
				continue
			}

			if !am.Auctions[auctionID].Params().VerifySignedBid(msg.SignedBid) {
				log.Warn("Signature verification failed, dropping bid message.")
				continue
			}

			if err = am.placeBid(msg.SignedBid.Bid, txn.ConfirmedRound); err != nil {
				log.Warnf("Placing bid failed, dropping message, err: %v", err)
				continue
			}

		case NoteSettlement:
			s := am.auctionState(msg.SignedSettlement.Settlement.AuctionID)
			if s == Uninitialized || s == Settled {
				log.Warnf("Got a settlement but the auction state is %v, dropping message.", s)
				continue
			}

			if crypto.Digest(from) != msg.SignedSettlement.Settlement.AuctionKey {
				log.Warn("Settlement message is not from the auction key, dropping message.")
				continue
			}

			if !am.Auctions[msg.SignedSettlement.Settlement.AuctionID].Params().VerifySignedSettlement(msg.SignedSettlement) {
				log.Warn("Signature verification failed, dropping settlement message.")
				continue
			}

			if !am.placeSettlement(msg.SignedSettlement.Settlement, txn.ConfirmedRound) {
				log.Warn("Placing settlement failed, dropping message.")
				continue
			}

		default:
			log.Warnf("Received an unknown type %v, ignoring message", msg.Type)
			continue
		}
	}
	return nil
}

func (am *Tracker) placeParams(params Params, rnd uint64) bool {
	if am.auctionState(am.lastAuction) == Active {
		log.Panicf("Got a start auction message before the auction was settled - %v", params)
	}

	log.Debugf("Making the logic with these params %+v", params)
	au, err := MakeSerializedLogic(params)
	if err != nil {
		log.Panicf("couldn't initialize the auction - %v", err)
	}

	am.lastAuction = params.AuctionID
	am.Auctions[params.AuctionID] = au
	return true
}

func (am *Tracker) placeBid(bid Bid, rnd uint64) (err error) {
	if am.auctionState(bid.AuctionID) != Active {
		err = fmt.Errorf("auction %d is not active for bid %+v", bid.AuctionID, bid)
		log.Error(err)
		return
	}
	return am.Auctions[bid.AuctionID].PlaceBid(bid, rnd)
}

func (am *Tracker) placeDeposit(deposit Deposit, rnd uint64) (err error) {
	if am.auctionState(deposit.AuctionID) != Active {
		err = fmt.Errorf("auction %d is not active for deposit %+v", deposit.AuctionID, deposit)
		log.Error(err)
		return
	}
	return am.Auctions[deposit.AuctionID].PlaceDeposit(deposit, rnd)
}

func (am *Tracker) placeSettlement(settlement Settlement, rnd uint64) bool {
	outcomes := am.Auctions[settlement.AuctionID].Settle(settlement.Canceled)

	if !settlement.VerifyBidOutcomes(outcomes) {
		panic("the settlement message hash isn't equal to the expected one")
	}

	return true
}

// AuctionState returns the current auction state

func (am *Tracker) auctionState(id uint64) State {
	var auction *SerializedRunningAuction
	var ok bool

	if auction, ok = am.Auctions[id]; !ok {
		return Uninitialized
	}

	if auction.Outcome != nil {
		return Settled
	}

	if am.lastRound >= auction.LastRound() {
		return Closed
	}

	return Active

}

// LiveUpdate fetches data from the blockchain and updates the RunningAuction with
// every new block. LiveUpdate blocks and should be ran in a go routine.
func (am *Tracker) LiveUpdate(rc client.RestClient) {
	var wg sync.WaitGroup
	wg.Add(1)
	am.LiveUpdateWithContext(context.Background(), &wg, rc)
	return
}

// LiveUpdateWithContext is as LiveUpdate, but with an arbitrary wrapping context
func (am *Tracker) LiveUpdateWithContext(ctx context.Context, wg *sync.WaitGroup, rc client.RestClient) {
	defer wg.Done()

	am.mu.Lock()
	lastRound := am.lastRound
	am.mu.Unlock()
	for {
		// break from loop if context is canceled
		if ctx.Err() != nil {
			log.Info(ctx.Err())
			return
		}

		log.Debugf("waiting for block after round %v", lastRound)
		status, err := rc.StatusAfterBlock(lastRound)
		if err != nil {
			log.Warnf("StatusAfterBlock returned an error: %v", err)
			fmt.Println(err)
			return
		}

		log.Debugf("Getting transactions for %d-%d",
			lastRound+1, status.LastRound)

		transactions, err := rc.TransactionsByAddr(am.AuctionKey.String(), lastRound+1, status.LastRound, math.MaxUint64)
		if err != nil {
			log.Error(err)
			fmt.Println(err)
			return
		}

		log.Debugf("Received %d transactions", len(transactions.Transactions))
		for _, txn := range transactions.Transactions {
			err := am.ProcessMessage(txn)
			if err != nil {
				log.Error(err)
			}
		}

		am.mu.Lock()
		lastRound = status.LastRound
		am.lastRound = status.LastRound
		am.mu.Unlock()
	}
}

// LastAuctionID returns the last known auction ID
func (am *Tracker) LastAuctionID() (uint64, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.lastAuction == 0 {
		return 0, errors.New("no auction has been seen yet")
	}
	return am.lastAuction, nil
}
