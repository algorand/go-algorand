// Copyright (C) 2019-2024 Algorand, Inc.
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

package heartbeat

import (
	"fmt"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"
)

type table map[basics.Address]ledgercore.AccountData

type mockedLedger struct {
	mu      deadlock.Mutex
	waiters map[basics.Round]chan struct{}
	history []table
	hdr     bookkeeping.BlockHeader
	t       *testing.T
}

func newMockedLedger(t *testing.T) mockedLedger {
	return mockedLedger{
		waiters: make(map[basics.Round]chan struct{}),
		history: []table{nil}, // some genesis accounts could go here
		hdr: bookkeeping.BlockHeader{
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusFuture,
			},
		},
	}
}

func (l *mockedLedger) LastRound() basics.Round {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastRound()
}
func (l *mockedLedger) lastRound() basics.Round {
	return basics.Round(len(l.history) - 1)
}

func (l *mockedLedger) WaitMem(r basics.Round) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.waiters[r] == nil {
		l.waiters[r] = make(chan struct{})
	}

	// Return an already-closed channel if we already have the block.
	if r <= l.lastRound() {
		close(l.waiters[r])
		retChan := l.waiters[r]
		delete(l.waiters, r)
		return retChan
	}

	return l.waiters[r]
}

// BlockHdr allows the service access to consensus values
func (l *mockedLedger) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r > l.lastRound() {
		return bookkeeping.BlockHeader{}, fmt.Errorf("%d is beyond current block (%d)", r, l.LastRound())
	}
	// return the template hdr, with round
	hdr := l.hdr
	hdr.Round = r
	return hdr, nil
}

// setSeed allows the mock to return a specific seed
func (l *mockedLedger) setSeed(seed committee.Seed) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.hdr.Seed = seed
}

func (l *mockedLedger) addBlock(delta table) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.history = append(l.history, delta)

	for r, ch := range l.waiters {
		switch {
		case r < l.lastRound():
			l.t.Logf("%d < %d", r, l.lastRound())
			panic("why is there a waiter for an old block?")
		case r == l.lastRound():
			close(ch)
			delete(l.waiters, r)
		case r > l.lastRound():
			/* waiter keeps waiting */
		}
	}
	return nil
}

func (l *mockedLedger) LookupAccount(round basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, basics.MicroAlgos, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if round > l.lastRound() {
		panic("mockedLedger.LookupAccount: future round")
	}

	for r := round; r <= round; r-- {
		if acct, ok := l.history[r][addr]; ok {
			more := basics.MicroAlgos{Raw: acct.MicroAlgos.Raw + 1}
			return acct, round, more, nil
		}
	}
	return ledgercore.AccountData{}, round, basics.MicroAlgos{}, nil
}

func (l *mockedLedger) LookupAgreement(round basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if round > l.lastRound() {
		panic("mockedLedger.LookupAgreement: future round")
	}

	for r := round; r <= round; r-- {
		if acct, ok := l.history[r][addr]; ok {
			oad := basics.OnlineAccountData{
				MicroAlgosWithRewards: acct.MicroAlgos,
				VotingData:            acct.VotingData,
				IncentiveEligible:     acct.IncentiveEligible,
				LastProposed:          acct.LastProposed,
				LastHeartbeat:         acct.LastHeartbeat,
			}
			return oad, nil
		}
	}
	return basics.OnlineAccountData{}, nil
}

// waitFor confirms that the Service made it through the last block in the
// ledger and is waiting for the next. The Service is written such that it
// operates properly without this sort of wait, but for testing, we often want
// to wait so that we can confirm that the Service *didn't* do something.
func (l *mockedLedger) waitFor(s *Service, a *require.Assertions) {
	a.Eventually(func() bool { // delay and confirm that the service advances to wait for next block
		_, ok := l.waiters[l.LastRound()+1]
		return ok
	}, time.Second, 10*time.Millisecond)
}

type mockedAcctManager []account.ParticipationRecordForRound

func (am *mockedAcctManager) Keys(rnd basics.Round) []account.ParticipationRecordForRound {
	return *am
}

func (am *mockedAcctManager) addParticipant(addr basics.Address, otss *crypto.OneTimeSignatureSecrets) {
	*am = append(*am, account.ParticipationRecordForRound{
		ParticipationRecord: account.ParticipationRecord{
			ParticipationID: [32]byte{},
			Account:         addr,
			Voting:          otss,
			FirstValid:      0,
			LastValid:       1_000_000,
			KeyDilution:     7,
		},
	})
}

type txnSink struct {
	t    *testing.T
	txns [][]transactions.SignedTxn
}

func (ts *txnSink) BroadcastInternalSignedTxGroup(group []transactions.SignedTxn) error {
	ts.t.Logf("sinking %+v", group[0].Txn.Header)
	ts.txns = append(ts.txns, group)
	return nil
}

func TestStartStop(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)
	sink := txnSink{t: t}
	ledger := newMockedLedger(t)
	s := NewService(&mockedAcctManager{}, &ledger, &sink, logging.TestingLog(t))
	a.NotNil(s)
	a.NoError(ledger.addBlock(nil))
	s.Start()
	a.NoError(ledger.addBlock(nil))
	s.Stop()
}

func makeBlock(r basics.Round) bookkeeping.Block {
	return bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{Round: r},
		Payset:      []transactions.SignedTxnInBlock{},
	}
}

func TestHeartbeatOnlyWhenChallenged(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)
	sink := txnSink{t: t}
	ledger := newMockedLedger(t)
	participants := &mockedAcctManager{}
	s := NewService(participants, &ledger, &sink, logging.TestingLog(t))
	s.Start()

	joe := basics.Address{0xcc}  // 0xcc will matter when we set the challenge
	mary := basics.Address{0xaa} // 0xaa will matter when we set the challenge

	acct := ledgercore.AccountData{}

	a.NoError(ledger.addBlock(table{joe: acct}))
	ledger.waitFor(s, a)
	a.Empty(sink.txns)

	// make "part keys" and install them
	kd := uint64(100)
	startBatch := basics.OneTimeIDForRound(ledger.LastRound(), kd).Batch
	const batches = 50 // gives 50 * kd rounds = 5000
	otss1 := crypto.GenerateOneTimeSignatureSecrets(startBatch, batches)
	otss2 := crypto.GenerateOneTimeSignatureSecrets(startBatch, batches)
	participants.addParticipant(joe, otss1)
	participants.addParticipant(joe, otss2) // Simulate overlapping part keys, so Keys() returns both
	participants.addParticipant(mary, otss1)

	// now they are online, but not challenged, so no heartbeat
	acct.Status = basics.Online
	acct.VoteKeyDilution = kd
	acct.VoteID = otss1.OneTimeSignatureVerifier
	a.NoError(ledger.addBlock(table{joe: acct, mary: acct})) // in effect, "keyreg" with otss1
	ledger.waitFor(s, a)
	a.Empty(sink.txns)

	// now we have to make it seem like joe has been challenged. We obtain the
	// payout rules to find the first challenge round, skip forward to it, then
	// go forward half a grace period. Only then should the service heartbeat
	ledger.setSeed(committee.Seed{0xc8}) // share 5 bits with 0xcc
	hdr, err := ledger.BlockHdr(ledger.LastRound())
	a.NoError(err)
	rules := config.Consensus[hdr.CurrentProtocol].Payouts
	for ledger.LastRound() < basics.Round(rules.ChallengeInterval+rules.ChallengeGracePeriod/2) {
		a.NoError(ledger.addBlock(table{}))
		ledger.waitFor(s, a)
		a.Empty(sink.txns)
	}

	a.NoError(ledger.addBlock(table{joe: acct}))
	ledger.waitFor(s, a)
	a.Empty(sink.txns) // Just kidding, no heartbeat yet, joe isn't eligible

	acct.IncentiveEligible = true
	a.NoError(ledger.addBlock(table{joe: acct}))
	ledger.waitFor(s, a)
	// challenge is already in place, it counts immediately, so service will heartbeat
	a.Len(sink.txns, 1) // only one heartbeat (for joe) despite having two part records
	a.Len(sink.txns[0], 1)
	a.Equal(sink.txns[0][0].Txn.Type, protocol.HeartbeatTx)
	a.Equal(sink.txns[0][0].Txn.HbAddress, joe)

	s.Stop()
}
