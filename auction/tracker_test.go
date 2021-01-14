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
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// Testing strategy -
// start, bids, settle - Regular
// start, start --> should panic
// Settle, start --> should ignore the settle
// start, end --> should work
// start, bids, end, end' --> should panic
// start, bids, end, end --> should not panic
// {start, bids, end} * 10 - Regular
// Wrong message type - should panic

const AuctionKey = 0
const BankKey = 1
const BidderKey = 2

func genConfirmedTx(msg interface{}, round uint64, from, to basics.Address,
	secret *crypto.SignatureSecrets) v1.Transaction {

	nf := NoteField{}
	switch v := msg.(type) {
	case Settlement:
		nf.Type = NoteSettlement
		nf.SignedSettlement = SignedSettlement{Settlement: v, Sig: secret.Sign(v)}
	case Bid:
		nf.Type = NoteBid
		nf.SignedBid = SignedBid{Bid: v, Sig: secret.Sign(v)}
	case Deposit:
		nf.Type = NoteDeposit
		nf.SignedDeposit = SignedDeposit{Deposit: v, Sig: secret.Sign(v)}
	case Params:
		nf.Type = NoteParams
		nf.SignedParams = SignedParams{Params: v, Sig: secret.Sign(v)}

	}
	return v1.Transaction{
		ConfirmedRound: round,
		From:           from.String(),
		Payment: &v1.PaymentTransactionType{
			To: to.String(),
		},
		Note: protocol.Encode(&nf),
	}
}

func TestTracker_Transition(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1, addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1, addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	// Place a deposit
	d0 := Deposit{
		BidderKey:  crypto.Digest(addrs[BidderKey]),
		Currency:   10000,
		AuctionKey: crypto.Digest(addrs[AuctionKey]),
		AuctionID:  5,
		DepositID:  10,
	}

	am.ProcessMessage(genConfirmedTx(d0, 1001, addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))

	b0 := Bid{
		BidderKey:   crypto.Digest(addrs[BidderKey]),
		BidCurrency: 1000,
		MaxPrice:    1000,
		BidID:       5,
		AuctionKey:  crypto.Digest(addrs[AuctionKey]),
		AuctionID:   5,
	}

	am.ProcessMessage(genConfirmedTx(b0, 1100,
		addrs[BidderKey], addrs[AuctionKey], secrets[BidderKey]))
	require.Equal(t, Active, am.auctionState(p.AuctionID))

	o := am.Auctions[p.AuctionID].Settle(false)
	h := crypto.HashObj(o)
	s := Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: o.Cleared, OutcomesHash: h}

	// Tricking the system for testing
	am.Auctions[p.AuctionID].Outcome = nil

	am.ProcessMessage(genConfirmedTx(s, 1401,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Settled, am.auctionState(p.AuctionID))
}

func TestTracker_WrongParams(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1, addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1, addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	// Place a deposit
	d0 := Deposit{
		BidderKey:  crypto.Digest(addrs[BidderKey]),
		Currency:   10000,
		AuctionKey: crypto.Digest(addrs[AuctionKey]),
		AuctionID:  5,
		DepositID:  10,
	}

	am.ProcessMessage(genConfirmedTx(d0, 1001, addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))

	b0 := Bid{
		BidderKey:   crypto.Digest(addrs[BidderKey]),
		BidCurrency: 1000,
		MaxPrice:    1000,
		BidID:       5,
		AuctionKey:  crypto.Digest(addrs[AuctionKey]),
		AuctionID:   5,
	}

	am.ProcessMessage(genConfirmedTx(b0, 1100,
		addrs[BidderKey], addrs[AuctionKey], secrets[BidderKey]))
	require.Equal(t, Active, am.auctionState(p.AuctionID))

	o := am.Auctions[p.AuctionID].Settle(false)
	h := crypto.HashObj(o)
	s := Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: o.Cleared, OutcomesHash: h}

	// Tricking the system for testing
	am.Auctions[p.AuctionID].Outcome = nil

	am.ProcessMessage(genConfirmedTx(s, 1401,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Settled, am.auctionState(p.AuctionID))

	p2 := mkParams2()
	p2.AuctionID = 8
}

func TestTracker_Transition_Settle_Start(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1,
		addrs[AuctionKey].String())
	require.NoError(t, err)

	// Process settle
	s := Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: true}

	am.ProcessMessage(genConfirmedTx(s, 1,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Uninitialized, am.auctionState(p.AuctionID))

	am.ProcessMessage(genConfirmedTx(p, 2,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())
}

func TestTracker_Transition_Multiple_Auctions(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1,
		addrs[AuctionKey].String())
	require.NoError(t, err)

	require.Equal(t, Uninitialized, am.auctionState(p.AuctionID))

	am.ProcessMessage(genConfirmedTx(p, p.FirstRound-5,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	for i := 0; i < 10; i++ {
		// Place a deposit
		d0 := Deposit{
			BidderKey:  crypto.Digest(addrs[BidderKey]),
			Currency:   10000,
			AuctionKey: crypto.Digest(addrs[AuctionKey]),
			AuctionID:  am.lastAuction,
			DepositID:  10,
		}

		am.ProcessMessage(genConfirmedTx(d0, am.Auctions[am.lastAuction].Params().DepositRound+1,
			addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))
		require.Equal(t, Active, am.auctionState(am.lastAuction))

		b0 := Bid{
			BidderKey:   crypto.Digest(addrs[BidderKey]),
			BidCurrency: 1000,
			MaxPrice:    1000,
			BidID:       5,
			AuctionKey:  crypto.Digest(addrs[AuctionKey]),
			AuctionID:   am.lastAuction,
		}

		am.ProcessMessage(genConfirmedTx(b0, am.Auctions[am.lastAuction].Params().FirstRound+1,
			addrs[BidderKey], addrs[AuctionKey], secrets[BidderKey]))
		require.Equal(t, Active, am.auctionState(am.lastAuction))

		o := am.Auctions[am.lastAuction].Settle(false)
		h := crypto.HashObj(o)
		s := Settlement{AuctionID: am.lastAuction, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: o.Cleared,
			OutcomesHash: h}

		am.Auctions[am.lastAuction].Outcome = nil

		am.ProcessMessage(genConfirmedTx(s, am.Auctions[am.lastAuction].LastRound(), addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

		require.Equal(t, Settled, am.auctionState(p.AuctionID))

		nextP := am.Auctions[am.lastAuction].Params()

		// increase values
		nextP.AuctionID++

		am.ProcessMessage(genConfirmedTx(nextP, am.Auctions[am.lastAuction].LastRound()+1, addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

		require.Empty(t, am.Auctions[nextP.AuctionID].DepositIDs)
		require.Empty(t, am.Auctions[nextP.AuctionID].Bidders)
		require.Empty(t, am.Auctions[nextP.AuctionID].Bids())
	}
}

func TestTracker_Transition_DoubleStart(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1,
		addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	p2 := mkParams2()
	p2.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p2.BankKey = crypto.Digest(addrs[BankKey])
	p2.AuctionID = p.AuctionID

	require.Panics(t, func() {
		am.ProcessMessage(genConfirmedTx(p2, 2,
			addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))
	}, "should have panicked")

}

func TestTracker_Transition_NoBids(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1,
		addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	o := am.Auctions[p.AuctionID].Settle(false)
	h := crypto.HashObj(o)
	s := Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: o.Cleared, OutcomesHash: h}

	am.Auctions[p.AuctionID].Outcome = nil

	am.ProcessMessage(genConfirmedTx(s, 1401, addrs[AuctionKey],
		addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Settled, am.auctionState(p.AuctionID))
}

func TestTracker_Transition_Double_Settlement_Different(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1,
		addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	// Place a deposit
	d0 := Deposit{
		BidderKey:  crypto.Digest(addrs[BidderKey]),
		Currency:   10000,
		AuctionKey: crypto.Digest(addrs[AuctionKey]),
		AuctionID:  5,
		DepositID:  10,
	}

	am.ProcessMessage(genConfirmedTx(d0, 1001,
		addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))
	require.Equal(t, Active, am.auctionState(p.AuctionID))

	b0 := Bid{
		BidderKey:   crypto.Digest(addrs[BidderKey]),
		BidCurrency: 1000,
		MaxPrice:    1000,
		BidID:       5,
		AuctionKey:  crypto.Digest(addrs[AuctionKey]),
		AuctionID:   5,
	}

	am.ProcessMessage(genConfirmedTx(b0, 1100,
		addrs[BidderKey], addrs[AuctionKey], secrets[BidderKey]))
	require.Equal(t, Active, am.auctionState(p.AuctionID))

	o := am.Auctions[p.AuctionID].Settle(false)
	h := crypto.HashObj(o)
	s := Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: o.Cleared, OutcomesHash: h}

	am.Auctions[p.AuctionID].Outcome = nil

	am.ProcessMessage(genConfirmedTx(s, 1401, addrs[AuctionKey],
		addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Settled, am.auctionState(p.AuctionID))

	s = Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: !o.Cleared, OutcomesHash: h}

	am.ProcessMessage(genConfirmedTx(s, 1401, addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Settled, am.auctionState(p.AuctionID))
	require.Equal(t, *am.Auctions[p.AuctionID].Outcome, o)

}

func TestTracker_Transition_Double_Settlement(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1,
		addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	// Place a deposit
	d0 := Deposit{
		BidderKey:  crypto.Digest(addrs[BidderKey]),
		Currency:   10000,
		AuctionKey: crypto.Digest(addrs[AuctionKey]),
		AuctionID:  5,
		DepositID:  10,
	}

	am.ProcessMessage(genConfirmedTx(d0, 1001,
		addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))
	require.Equal(t, Active, am.auctionState(p.AuctionID))

	b0 := Bid{
		BidderKey:   crypto.Digest(addrs[BidderKey]),
		BidCurrency: 1000,
		MaxPrice:    1000,
		BidID:       5,
		AuctionKey:  crypto.Digest(addrs[AuctionKey]),
		AuctionID:   5,
	}

	am.ProcessMessage(genConfirmedTx(b0, 1100,
		addrs[BidderKey], addrs[AuctionKey], secrets[BidderKey]))
	require.Equal(t, Active, am.auctionState(p.AuctionID))

	o := am.Auctions[p.AuctionID].Settle(false)
	h := crypto.HashObj(o)
	s := Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: o.Cleared, OutcomesHash: h}

	am.Auctions[p.AuctionID].Outcome = nil

	am.ProcessMessage(genConfirmedTx(s, 1401, addrs[AuctionKey],
		addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Settled, am.auctionState(p.AuctionID))

	s = Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Cleared: o.Cleared, OutcomesHash: h}
	require.Equal(t, Settled, am.auctionState(p.AuctionID))

}

func TestTracker_WrongAuctionIDInDeposit(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1, addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1, addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	// Place a deposit
	d0 := Deposit{
		BidderKey:  crypto.Digest(addrs[BidderKey]),
		Currency:   10000,
		AuctionKey: crypto.Digest(addrs[AuctionKey]),
		AuctionID:  65000000,
		DepositID:  10,
	}

	am.ProcessMessage(genConfirmedTx(d0, 1001, addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))

	b, ok := am.Auctions[p.AuctionID].Bidders[crypto.Digest(addrs[BidderKey])]
	require.False(t, ok)
	require.Empty(t, b)
}

func TestTracker_WrongAuctionIDInBid(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1, addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1, addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	// Place a deposit
	d0 := Deposit{
		BidderKey:  crypto.Digest(addrs[BidderKey]),
		Currency:   10000,
		AuctionKey: crypto.Digest(addrs[AuctionKey]),
		AuctionID:  p.AuctionID,
		DepositID:  10,
	}

	am.ProcessMessage(genConfirmedTx(d0, 1001, addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))

	require.Equal(t, uint64(10000), am.Auctions[p.AuctionID].Bidders[crypto.Digest(addrs[BidderKey])].DepositAmount)

	b0 := Bid{
		BidderKey:   crypto.Digest(addrs[BidderKey]),
		BidCurrency: 1000,
		MaxPrice:    1000,
		BidID:       5,
		AuctionKey:  crypto.Digest(addrs[AuctionKey]),
		AuctionID:   p.AuctionID + 10,
	}

	am.ProcessMessage(genConfirmedTx(b0, 1100, addrs[BidderKey], addrs[AuctionKey], secrets[BidderKey]))

	// Should ignore the bid
	require.Equal(t, 0, len(am.Auctions[p.AuctionID].Bidders[crypto.Digest(addrs[BidderKey])].PlacedBidIDs))
}

func TestTracker_Cancel(t *testing.T) {
	secrets, addrs := generateTestObjects(10)

	var bidderKey crypto.Digest
	crypto.RandBytes(bidderKey[:])

	p := mkParams()
	p.AuctionKey = crypto.Digest(addrs[AuctionKey])
	p.BankKey = crypto.Digest(addrs[BankKey])

	am, err := MakeTracker(1, addrs[AuctionKey].String())
	require.NoError(t, err)

	am.ProcessMessage(genConfirmedTx(p, 1, addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))
	require.Equal(t, p, am.Auctions[p.AuctionID].Params())

	// Place a deposit
	d0 := Deposit{
		BidderKey:  crypto.Digest(addrs[BidderKey]),
		Currency:   10000,
		AuctionKey: crypto.Digest(addrs[AuctionKey]),
		AuctionID:  5,
		DepositID:  10,
	}

	am.ProcessMessage(genConfirmedTx(d0, 1001, addrs[BankKey], addrs[AuctionKey], secrets[BankKey]))

	require.Equal(t, Active, am.auctionState(p.AuctionID))

	b0 := Bid{
		BidderKey:   crypto.Digest(addrs[BidderKey]),
		BidCurrency: 1000,
		MaxPrice:    1000,
		BidID:       5,
		AuctionKey:  crypto.Digest(addrs[AuctionKey]),
		AuctionID:   5,
	}

	am.ProcessMessage(genConfirmedTx(b0, 1100,
		addrs[BidderKey], addrs[AuctionKey], secrets[BidderKey]))
	require.Equal(t, Active, am.auctionState(p.AuctionID))

	o := am.Auctions[p.AuctionID].Settle(true)
	h := crypto.HashObj(o)
	s := Settlement{AuctionID: 5, AuctionKey: crypto.Digest(addrs[AuctionKey]), Canceled: true, OutcomesHash: h}

	am.Auctions[p.AuctionID].Outcome = nil

	am.ProcessMessage(genConfirmedTx(s, 1401,
		addrs[AuctionKey], addrs[AuctionKey], secrets[AuctionKey]))

	require.Equal(t, Settled, am.auctionState(p.AuctionID))
}

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func generateTestObjects(numAccs int) ([]*crypto.SignatureSecrets, []basics.Address) {
	secrets := make([]*crypto.SignatureSecrets, numAccs)
	addresses := make([]basics.Address, numAccs)

	for i := 0; i < numAccs; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}
	return secrets, addresses
}
