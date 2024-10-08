// Copyright (C) 2019-2023 Algorand, Inc.
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

	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"
)

type mockParticipants struct {
	accts map[basics.Address]struct{}
}

func (p *mockParticipants) Keys(rnd basics.Round) []account.ParticipationRecordForRound {
	var ret []account.ParticipationRecordForRound
	for addr, _ := range p.accts {
		ret = append(ret, account.ParticipationRecordForRound{
			ParticipationRecord: account.ParticipationRecord{
				ParticipationID:   [32]byte{},
				Account:           addr,
				FirstValid:        0,
				LastValid:         0,
				KeyDilution:       0,
				LastVote:          0,
				LastBlockProposal: 0,
			},
		})
	}
	return ret
}

func (p *mockParticipants) add(addr basics.Address) {
	if p.accts == nil {
		p.accts = make(map[basics.Address]struct{})
	}
	p.accts[addr] = struct{}{}
}

type table map[basics.Address]ledgercore.AccountData

type mockedLedger struct {
	mu      deadlock.Mutex
	waiters map[basics.Round]chan struct{}
	history []table
	version protocol.ConsensusVersion
}

func newMockedLedger() mockedLedger {
	return mockedLedger{
		waiters: make(map[basics.Round]chan struct{}),
		history: []table{nil}, // some genesis accounts could go here
		version: protocol.ConsensusFuture,
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
	var hdr bookkeeping.BlockHeader
	hdr.Round = r
	hdr.CurrentProtocol = l.version
	return hdr, nil
}

func (l *mockedLedger) addBlock(delta table) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Printf("addBlock %d\n", l.lastRound()+1)
	l.history = append(l.history, delta)

	for r, ch := range l.waiters {
		switch {
		case r < l.lastRound():
			fmt.Printf("%d < %d\n", r, l.lastRound())
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

type txnSink [][]transactions.SignedTxn

func (ts *txnSink) BroadcastInternalSignedTxGroup(group []transactions.SignedTxn) error {
	fmt.Printf("sinking %+v\n", group[0].Txn.Header)
	*ts = append(*ts, group)
	return nil
}

func TestStartStop(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)
	sink := txnSink{}
	accts := &mockParticipants{}
	ledger := newMockedLedger()
	s := NewService(accts, &ledger, &sink, logging.TestingLog(t))
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

func TestHeartBeatOnlyWhenSuspended(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)
	sink := txnSink{}
	accts := &mockParticipants{}
	ledger := newMockedLedger()
	s := NewService(accts, &ledger, &sink, logging.TestingLog(t))
	s.Start()

	// ensure Donor can pay
	a.NoError(ledger.addBlock(table{Donor: ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			MicroAlgos: basics.MicroAlgos{Raw: 1_000_000},
		},
	}}))
	a.Empty(sink)

	joe := basics.Address{1, 1}
	accts.add(joe)

	acct := ledgercore.AccountData{}

	a.NoError(ledger.addBlock(table{joe: acct}))
	ledger.waitFor(s, a)
	a.Empty(sink)

	acct.Status = basics.Online

	a.NoError(ledger.addBlock(table{joe: acct}))
	a.Empty(sink)

	acct.Status = basics.Suspended

	a.NoError(ledger.addBlock(table{joe: acct}))
	ledger.waitFor(s, a)
	a.Len(sink, 1)    // only one heartbeat so far
	a.Len(sink[0], 1) // will probably end up being 3 to pay for `heartbeat` opcode

	s.Stop()
}

func TestHeartBeatOnlyWhenDonorFunded(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)
	sink := txnSink{}
	accts := &mockParticipants{}
	ledger := newMockedLedger()
	s := NewService(accts, &ledger, &sink, logging.TestingLog(t))
	s.Start()

	joe := basics.Address{1, 1}
	accts.add(joe)

	acct := ledgercore.AccountData{}

	a.NoError(ledger.addBlock(table{joe: acct}))
	a.Empty(sink)

	acct.Status = basics.Suspended

	a.NoError(ledger.addBlock(table{joe: acct}))
	ledger.waitFor(s, a)
	a.Empty(sink) // no funded donor, no heartbeat

	// Donor exists, has enough for fee, but not enough when MBR is considered
	a.NoError(ledger.addBlock(table{Donor: ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			MicroAlgos: basics.MicroAlgos{Raw: 100_000},
		},
	}}))
	a.NoError(ledger.addBlock(table{joe: acct}))
	ledger.waitFor(s, a)
	a.Empty(sink)

	a.NoError(ledger.addBlock(table{Donor: ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			MicroAlgos: basics.MicroAlgos{Raw: 200_000},
		},
	}}))
	ledger.waitFor(s, a)
	a.Len(sink, 1)    // only one heartbeat so far
	a.Len(sink[0], 1) // will probably end up being 3 to pay for `heartbeat` opcode
	s.Stop()
}

func TestHeartBeatForm(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)
	sink := txnSink{}
	accts := &mockParticipants{}
	ledger := newMockedLedger()
	s := NewService(accts, &ledger, &sink, logging.TestingLog(t))
	s.Start()

	joe := basics.Address{1, 1}
	accts.add(joe)

	// Fund the donor, suspend joe
	a.NoError(ledger.addBlock(table{
		Donor: ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{
				MicroAlgos: basics.MicroAlgos{Raw: 200_000},
			},
		},
		joe: ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{
				Status:     basics.Suspended,
				MicroAlgos: basics.MicroAlgos{Raw: 2_000_000},
			},
		},
	}))
	ledger.waitFor(s, a)
	a.Len(sink, 1)    // only one heartbeat so far
	a.Len(sink[0], 1) // will probably end up being 3 to pay for `heartbeat` opcode

	grp := sink[0]
	require.Equal(t, grp[0].Txn.Sender, Donor)
	require.Equal(t, grp[0].Lsig, transactions.LogicSig{Logic: DonorByteCode})

	a.NoError(ledger.addBlock(nil))
	ledger.waitFor(s, a)
	a.Len(sink, 2) // still suspended, another heartbeat
	inc := sink[0]
	inc[0].Txn.FirstValid++
	inc[0].Txn.LastValid++
	a.Equal(inc, sink[1])

	// mark joe online again
	a.NoError(ledger.addBlock(table{
		joe: ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{
				Status:     basics.Online,
				MicroAlgos: basics.MicroAlgos{Raw: 2_000_000},
			},
		},
	}))
	ledger.waitFor(s, a)
	a.Len(sink, 2) // no further heartbeat

	s.Stop()

}
