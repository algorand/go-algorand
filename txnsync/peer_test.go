// Copyright (C) 2019-2022 Algorand, Inc.
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

package txnsync

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestGetSetTransactionGroupCounterTracker tests the get/set capabilities for the counter
func TestGetSetTransactionGroupCounterTracker(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	grp := transactionGroupCounterTracker{}

	a.Equal(grp.get(0, 0), uint64(0))

	grp.set(0, 0, 2)
	a.Equal(grp.get(0, 0), uint64(2))
	grp.set(1, 0, 5)
	a.Equal(grp.get(1, 0), uint64(5))

	grp = transactionGroupCounterTracker{}

	for i := 0; i < maxTransactionGroupTrackers+1; i++ {
		grp.set(byte(i+1), 0, uint64(i+1))
	}

	a.True(reflect.DeepEqual(grp[0], requestParamsGroupCounterState{offset: 2, groupCounters: [bloomFilterRetryCount]uint64{2, 0, 0}}))

	for i := 1; i < maxTransactionGroupTrackers; i++ {
		if !reflect.DeepEqual(grp[i], requestParamsGroupCounterState{offset: byte(i + 2), groupCounters: [bloomFilterRetryCount]uint64{uint64(i + 2), 0, 0}}) {
			t.Errorf("For value %d got: %v", i, grp[i])
		}
	}

}

// TestIndexTransactionGroupCounterTracker tests the index function specifically
func TestIndexTransactionGroupCounterTracker(t *testing.T) {
	partitiontest.PartitionTest(t)

	grp := transactionGroupCounterTracker{
		{
			offset:        0,
			modulator:     0,
			groupCounters: [bloomFilterRetryCount]uint64{},
		},
		{
			offset:        1,
			modulator:     23,
			groupCounters: [bloomFilterRetryCount]uint64{},
		},
	}

	a := require.New(t)
	a.Equal(grp.index(2, 2), -1)
	a.Equal(grp.index(0, 0), 0)
	a.Equal(grp.index(1, 23), 1)
}

// TestRollTransactionGroupCounterTracker tests that rolling works and doesn't panic
func TestRollTransactionGroupCounterTracker(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	defer func() {
		if r := recover(); r != nil {
			a.False(true, "Something panicked during TestRollTransactionGroupCounterTracker")
		}
	}()

	grp1 := transactionGroupCounterTracker{
		{
			offset:        0,
			modulator:     0,
			groupCounters: [bloomFilterRetryCount]uint64{},
		},
	}

	grp1.roll(0, 0)
	grp1.roll(0, 2)

	grp2 := transactionGroupCounterTracker{
		{
			offset:        0,
			modulator:     0,
			groupCounters: [bloomFilterRetryCount]uint64{0, 1},
		},
	}

	grp2.roll(0, 0)
	grp2.roll(0, 2)
	a.True(grp2[0].groupCounters[0] == 0)
	a.True(grp2[0].groupCounters[1] == 1)

	grp3 := transactionGroupCounterTracker{
		{
			offset:        0,
			modulator:     0,
			groupCounters: [bloomFilterRetryCount]uint64{2, 1, 0},
		},
	}

	grp3.roll(0, 0)
	a.Equal(grp3[0].groupCounters, [bloomFilterRetryCount]uint64{1, 0, 2})
	grp3.roll(0, 1)

}

// TestGetNextScheduleOffset tests the state machine of getNextScheduleOffset
func TestGetNextScheduleOffset(t *testing.T) {
	partitiontest.PartitionTest(t)

	type args struct {
		isRelay        bool
		beta           time.Duration
		partialMessage bool
		currentTime    time.Duration
	}

	type results struct {
		offset time.Duration
		ops    peersOps
	}

	tests := []struct {
		fxn     func(p *Peer)
		arg     args
		result  results
		postFxn func(s peerState) bool
	}{
		{
			fxn:     func(p *Peer) { p.nextStateTimestamp = 2 * time.Millisecond },
			arg:     args{false, time.Millisecond, false, 1 * time.Millisecond},
			result:  results{1 * time.Millisecond, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn:     func(p *Peer) { p.nextStateTimestamp = 0 * time.Millisecond },
			arg:     args{false, 3 * time.Millisecond, false, 1 * time.Millisecond},
			result:  results{3 * time.Millisecond, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		// --

		{
			fxn:     func(p *Peer) { p.isOutgoing = false; p.nextStateTimestamp = 0 * time.Millisecond },
			arg:     args{true, 3 * time.Millisecond, false, 1 * time.Millisecond},
			result:  results{6 * time.Millisecond, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn:     func(p *Peer) { p.isOutgoing = false; p.nextStateTimestamp = 9 * time.Millisecond },
			arg:     args{true, 3 * time.Millisecond, false, 1 * time.Millisecond},
			result:  results{8 * time.Millisecond, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		// --

		{
			fxn:     func(p *Peer) { p.isOutgoing = true; p.state = peerStateLateBloom },
			arg:     args{true, 3 * time.Millisecond, false, 1 * time.Millisecond},
			result:  results{0 * time.Millisecond, 0},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn: func(p *Peer) {
				p.isOutgoing = true
				p.state = peerStateHoldsoff
				p.lastSentBloomFilter.containedTxnsRange.transactionsCount = 0
				p.nextStateTimestamp = 2 * messageTimeWindow
			},
			arg:     args{true, 3 * time.Millisecond, false, 1 * time.Millisecond},
			result:  results{messageTimeWindow - 1*time.Millisecond, peerOpsReschedule},
			postFxn: func(s peerState) bool { return s == peerStateLateBloom },
		},

		{
			fxn:     func(p *Peer) { p.nextStateTimestamp = 0 },
			arg:     args{false, 3 * time.Millisecond, true, 1 * time.Millisecond},
			result:  results{messageTimeWindow, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn:     func(p *Peer) { p.nextStateTimestamp = messageTimeWindow * 3 },
			arg:     args{false, 3 * time.Millisecond, true, 1 * time.Millisecond},
			result:  results{messageTimeWindow, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn:     func(p *Peer) { p.nextStateTimestamp = messageTimeWindow * 2 },
			arg:     args{false, 3 * time.Millisecond, true, 1 * time.Millisecond},
			result:  results{2*messageTimeWindow - 1*time.Millisecond, peerOpsReschedule | peerOpsClearInterruptible},
			postFxn: func(s peerState) bool { return s == peerStateHoldsoff },
		},

		// --

		{
			fxn:     func(p *Peer) { p.isOutgoing = true },
			arg:     args{true, 3 * time.Millisecond, true, 1 * time.Millisecond},
			result:  results{time.Duration(0), 0},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn:     func(p *Peer) { p.isOutgoing = true; p.state = peerStateHoldsoff },
			arg:     args{true, 3 * time.Millisecond, true, 1 * time.Millisecond},
			result:  results{messageTimeWindow, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn:     func(p *Peer) { p.isOutgoing = false; p.nextStateTimestamp = 0 },
			arg:     args{true, 3 * time.Millisecond, true, 1 * time.Millisecond},
			result:  results{messageTimeWindow, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},

		{
			fxn:     func(p *Peer) { p.isOutgoing = false; p.nextStateTimestamp = 9 * time.Millisecond },
			arg:     args{true, 3 * time.Millisecond, true, 1 * time.Millisecond},
			result:  results{8 * time.Millisecond, peerOpsReschedule},
			postFxn: func(s peerState) bool { return true },
		},
	}
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p := makePeer(nil, true, true, &config, log, 0)
			if test.fxn != nil {
				test.fxn(p)
			}

			offset, ops := p.getNextScheduleOffset(test.arg.isRelay, test.arg.beta, test.arg.partialMessage, test.arg.currentTime)

			r := results{offset, ops}

			if !test.postFxn(p.state) {
				t.Errorf("getNextScheduleOffset() state = %v", p.state)
			}

			if !reflect.DeepEqual(r, test.result) {
				t.Errorf("getNextScheduleOffset() = %v, want %v", r, test.result)
			}

		})
	}

}

// TestGetMessageConstructionOps tests the state machine of getMessageConstructionOps
func TestGetMessageConstructionOps(t *testing.T) {
	partitiontest.PartitionTest(t)

	type args struct {
		isRelay           bool
		fetchTransactions bool
	}

	peerStateLateBloomState := peerStateLateBloom
	peerStateHoldsoffState := peerStateHoldsoff

	tests := []struct {
		fxn    func(p *Peer)
		arg    args
		result messageConstructionOps
		state  *peerState
	}{
		{
			fxn:    func(p *Peer) {},
			arg:    args{false, false},
			result: messageConstTransactions,
			state:  nil,
		},
		{
			fxn:    func(p *Peer) { p.localTransactionsModulator = 0 },
			arg:    args{false, true},
			result: messageConstUpdateRequestParams | messageConstTransactions,
			state:  nil,
		},
		{
			fxn:    func(p *Peer) { p.localTransactionsModulator = 1; p.nextStateTimestamp = 1 },
			arg:    args{false, true},
			result: messageConstUpdateRequestParams | messageConstTransactions,
			state:  nil,
		},
		{
			fxn:    func(p *Peer) { p.localTransactionsModulator = 1; p.nextStateTimestamp = 0 },
			arg:    args{false, true},
			result: messageConstUpdateRequestParams | messageConstTransactions | messageConstBloomFilter,
			state:  nil,
		},
		{
			fxn:    func(p *Peer) { p.localTransactionsModulator = 1; p.nextStateTimestamp = 99 },
			arg:    args{false, true},
			result: messageConstUpdateRequestParams | messageConstTransactions,
			state:  nil,
		},
		// --

		{
			fxn:    func(p *Peer) { p.isOutgoing = false; p.requestedTransactionsModulator = 0; p.nextStateTimestamp = 0 },
			arg:    args{true, true},
			result: messageConstUpdateRequestParams | messageConstNextMinDelay,
			state:  nil,
		},
		{
			fxn:    func(p *Peer) { p.isOutgoing = false; p.requestedTransactionsModulator = 0; p.nextStateTimestamp = 1 },
			arg:    args{true, true},
			result: messageConstUpdateRequestParams,
			state:  nil,
		},

		{
			fxn: func(p *Peer) {
				p.isOutgoing = false
				p.localTransactionsModulator = 1
				p.requestedTransactionsModulator = 1
				p.nextStateTimestamp = 0
			},
			arg:    args{true, true},
			result: messageConstUpdateRequestParams | messageConstNextMinDelay | messageConstTransactions | messageConstBloomFilter,
			state:  nil,
		},
		{
			fxn:    func(p *Peer) { p.isOutgoing = false; p.requestedTransactionsModulator = 1; p.nextStateTimestamp = 1 },
			arg:    args{true, true},
			result: messageConstUpdateRequestParams | messageConstTransactions,
			state:  nil,
		},

		// --

		{
			fxn:    func(p *Peer) { p.isOutgoing = true; p.state = peerStateLateBloom; p.localTransactionsModulator = 0 },
			arg:    args{true, true},
			result: messageConstUpdateRequestParams,
			state:  &peerStateLateBloomState,
		},

		{
			fxn:    func(p *Peer) { p.isOutgoing = true; p.state = peerStateLateBloom; p.localTransactionsModulator = 1 },
			arg:    args{true, true},
			result: messageConstUpdateRequestParams | messageConstBloomFilter,
			state:  &peerStateLateBloomState,
		},

		{
			fxn:    func(p *Peer) { p.isOutgoing = true; p.state = peerStateHoldsoff; p.localTransactionsModulator = 1 },
			arg:    args{true, true},
			result: messageConstUpdateRequestParams | messageConstTransactions,
			state:  &peerStateHoldsoffState,
		},
	}
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p := makePeer(nil, true, true, &config, log, 0)
			if test.fxn != nil {
				test.fxn(p)
			}

			gotOps := p.getMessageConstructionOps(test.arg.isRelay, test.arg.fetchTransactions)

			if test.state != nil && p.state != *test.state {
				t.Errorf("getMessageConstructionOps() state = %v, want %v", p.state, test.state)
			}

			if gotOps != test.result {
				t.Errorf("getMessageConstructionOps() = %v, want %v", gotOps, test.result)
			}

		})
	}

}

// TestAdvancePeerState tests the state machine of advancePeerState
func TestAdvancePeerState(t *testing.T) {
	partitiontest.PartitionTest(t)

	type args struct {
		currentTime time.Duration
		isRelay     bool
	}

	tests := []struct {
		fxn    func(p *Peer)
		arg    args
		result peersOps
		state  peerState
	}{
		{
			fxn:    func(p *Peer) { p.state = peerStateStartup },
			arg:    args{time.Millisecond, false},
			result: peerOpsSendMessage,
			state:  peerStateHoldsoff,
		},
		{
			fxn:    func(p *Peer) { p.state = peerStateHoldsoff; p.nextStateTimestamp = 0 },
			arg:    args{time.Millisecond, false},
			result: peerOpsSetInterruptible | peerOpsReschedule,
			state:  peerStateInterrupt,
		},
		{
			fxn:    func(p *Peer) { p.state = peerStateHoldsoff; p.nextStateTimestamp = 1 },
			arg:    args{time.Millisecond, false},
			result: peerOpsSendMessage,
			state:  peerStateHoldsoff,
		},
		{
			fxn:    func(p *Peer) { p.state = peerStateInterrupt },
			arg:    args{time.Millisecond, false},
			result: peerOpsSendMessage | peerOpsClearInterruptible,
			state:  peerStateHoldsoff,
		},
		// --
		{
			fxn:    func(p *Peer) { p.isOutgoing = false; p.state = peerStateStartup },
			arg:    args{time.Millisecond, true},
			result: peerOpsSendMessage,
			state:  peerStateHoldsoff,
		},
		{
			fxn:    func(p *Peer) { p.isOutgoing = false; p.state = peerStateHoldsoff },
			arg:    args{time.Millisecond, true},
			result: peerOpsSendMessage,
			state:  peerStateHoldsoff,
		},
		// --

		{
			fxn: func(p *Peer) {
				p.isOutgoing = true
				p.state = peerStateStartup
				p.lastReceivedMessageNextMsgMinDelay = messageTimeWindow * 2
			},
			arg:    args{time.Millisecond, true},
			result: peerOpsSendMessage,
			state:  peerStateLateBloom,
		},
		{
			fxn: func(p *Peer) {
				p.isOutgoing = true
				p.state = peerStateStartup
				p.lastReceivedMessageNextMsgMinDelay = messageTimeWindow * 3
			},
			arg:    args{time.Millisecond, true},
			result: peerOpsSendMessage,
			state:  peerStateHoldsoff,
		},

		{
			fxn: func(p *Peer) {
				p.isOutgoing = true
				p.state = peerStateHoldsoff
				p.nextStateTimestamp = messageTimeWindow * 2
			},
			arg:    args{0 * time.Millisecond, true},
			result: peerOpsSendMessage,
			state:  peerStateLateBloom,
		},

		{
			fxn: func(p *Peer) {
				p.isOutgoing = true
				p.state = peerStateHoldsoff
				p.nextStateTimestamp = messageTimeWindow * 3
			},
			arg:    args{0 * time.Millisecond, true},
			result: peerOpsSendMessage,
			state:  peerStateHoldsoff,
		},

		{
			fxn:    func(p *Peer) { p.isOutgoing = true; p.state = peerStateLateBloom },
			arg:    args{time.Millisecond, true},
			result: peerOpsSendMessage,
			state:  peerStateLateBloom,
		},
	}
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	for i, test := range tests {
		t.Run(string(rune(i)), func(t *testing.T) {
			p := makePeer(nil, true, true, &config, log, 0)
			if test.fxn != nil {
				test.fxn(p)
			}

			gotOps := p.advancePeerState(test.arg.currentTime, test.arg.isRelay)

			if p.state != test.state {
				t.Errorf("advancePeerState() state = %v, want %v", p.state, test.state)
			}

			if gotOps != test.result {
				t.Errorf("advancePeerState() = %v, want %v", gotOps, test.result)
			}

		})
	}
}

// TestUpdateIncomingMessageTiming tests updating the incoming message timing
func TestUpdateIncomingMessageTiming(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)

	currentRound := basics.Round(1)
	currentTime := time.Millisecond * 123
	currentMessageSize := int(p.significantMessageThreshold)
	timing := timingParams{NextMsgMinDelay: 42}

	// Test direct assignment

	p.lastConfirmedMessageSeqReceived = p.lastSentMessageSequenceNumber + 1

	p.updateIncomingMessageTiming(timing, currentRound, currentTime, 0, time.Millisecond, currentMessageSize)

	a.Equal(p.lastReceivedMessageLocalRound, currentRound)
	a.Equal(p.lastReceivedMessageTimestamp, currentTime)
	a.Equal(p.lastReceivedMessageSize, currentMessageSize)
	a.Equal(p.lastReceivedMessageNextMsgMinDelay, time.Duration(timing.NextMsgMinDelay)*time.Nanosecond)

	// Test entering if statement

	p.lastConfirmedMessageSeqReceived = p.lastSentMessageSequenceNumber
	p.lastSentMessageRound = currentRound
	timing.ResponseElapsedTime = 1
	p.lastSentMessageTimestamp = 1 * time.Millisecond
	currentMessageSize = maxDataExchangeRateThreshold + 1
	p.updateIncomingMessageTiming(timing, currentRound, currentTime, 0, time.Millisecond, currentMessageSize)

	a.Equal(uint64(maxDataExchangeRateThreshold), p.dataExchangeRate)

	p.lastConfirmedMessageSeqReceived = p.lastSentMessageSequenceNumber
	p.lastSentMessageRound = currentRound
	timing.ResponseElapsedTime = 1
	p.lastSentMessageTimestamp = 1 * time.Millisecond
	p.lastSentMessageSize = 0
	currentMessageSize = int(p.significantMessageThreshold)
	currentTime = time.Millisecond * 1000
	p.updateIncomingMessageTiming(timing, currentRound, currentTime, 0, time.Millisecond, currentMessageSize)

	a.Equal(uint64(minDataExchangeRateThreshold), p.dataExchangeRate)

	p.lastConfirmedMessageSeqReceived = p.lastSentMessageSequenceNumber
	p.lastSentMessageRound = currentRound
	timing.ResponseElapsedTime = uint64(time.Millisecond)
	p.lastSentMessageTimestamp = 1 * time.Millisecond
	p.lastSentMessageSize = 0
	currentMessageSize = 100000
	currentTime = time.Millisecond * 123
	p.updateIncomingMessageTiming(timing, currentRound, currentTime, time.Millisecond, time.Millisecond*100, currentMessageSize)

	a.Equal(uint64(5000000), p.dataExchangeRate)
}

// TestUpdateIncomingTransactionGroups tests updating the incoming transaction groups
func TestUpdateIncomingTransactionGroups(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var txnGroups []pooldata.SignedTxGroup

	for i := 0; i < 10; i++ {

		tmp := pooldata.SignedTxGroup{
			Transactions: []transactions.SignedTxn{transactions.SignedTxn{
				Sig:      crypto.Signature{},
				Msig:     crypto.MultisigSig{},
				Lsig:     transactions.LogicSig{},
				Txn:      transactions.Transaction{},
				AuthAddr: basics.Address{},
			}},
			LocallyOriginated:  false,
			GroupCounter:       0,
			GroupTransactionID: transactions.Txid{byte(i)},
			EncodedLength:      0,
		}
		txnGroups = append(txnGroups, tmp)
	}

	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)

	p.recentSentTransactions.reset()

	for i := 0; i < 10; i++ {
		txid := transactions.Txid{byte(i)}
		a.False(p.recentSentTransactions.contained(txid))
	}

}

// TestUpdateRequestParams tests updating the request parameters
func TestUpdateRequestParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)
	oldModulator := p.requestedTransactionsModulator
	oldOffset := p.requestedTransactionsOffset

	p.updateRequestParams(oldModulator, oldOffset)
	a.Equal(p.requestedTransactionsModulator, oldModulator)
	a.Equal(p.requestedTransactionsOffset, oldOffset)

	p.updateRequestParams(oldModulator+1, oldOffset+1)
	a.Equal(p.requestedTransactionsModulator, oldModulator+1)
	a.Equal(p.requestedTransactionsOffset, oldOffset+1)

}

// bloom.GenericFilter
type nopFilter struct{}

func (nf *nopFilter) Set(x []byte) {}
func (nf *nopFilter) Test(x []byte) bool {
	return false
}
func (nf *nopFilter) MarshalBinary() ([]byte, error) {
	return nil, nil
}
func (nf *nopFilter) UnmarshalBinary(data []byte) error {
	return nil
}

// TestAddIncomingBloomFilter tests adding an incoming bloom filter
func TestAddIncomingBloomFilter(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)

	for i := 0; i < 2*maxIncomingBloomFilterHistory; i++ {
		bf := &testableBloomFilter{
			encodingParams: requestParams{
				_struct:   struct{}{},
				Offset:    byte(i),
				Modulator: 0,
			},
			filter: &nopFilter{},
		}
		p.addIncomingBloomFilter(basics.Round(i), bf, basics.Round(i))
	}

	// filters from current round, -1, and -2 are kept. => 3
	a.Equal(3, len(p.recentIncomingBloomFilters))

	for i := 0; i < 2*maxIncomingBloomFilterHistory; i++ {
		bf := &testableBloomFilter{
			encodingParams: requestParams{
				_struct:   struct{}{},
				Offset:    byte(i),
				Modulator: 0,
			},
			filter: &nopFilter{},
		}
		p.addIncomingBloomFilter(basics.Round(i), bf, 0)
	}

	a.Equal(maxIncomingBloomFilterHistory, len(p.recentIncomingBloomFilters))
}

// TestSelectPendingTransactions tests selectPendingTransactions
func TestSelectPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)

	type args struct {
		pendingTransactions []pooldata.SignedTxGroup
		sendWindow          time.Duration
		round               basics.Round
		bloomFilterSize     int
	}

	type results struct {
		selectedTxns           []pooldata.SignedTxGroup
		selectedTxnIDs         []transactions.Txid
		partialTransactionsSet bool
	}

	tests := []struct {
		name   string
		fxn    func(p *Peer)
		arg    args
		result results
	}{
		{"Case 1", func(p *Peer) { p.lastRound = 98 }, args{nil, time.Millisecond, 100, 0}, results{nil, nil, false}},
		{"Case 2", func(p *Peer) { p.lastRound = 101; p.requestedTransactionsModulator = 0 }, args{nil, time.Millisecond, 100, 0}, results{nil, nil, false}},
		{"Case 3", func(p *Peer) { p.lastRound = 200; p.messageSeriesPendingTransactions = nil }, args{[]pooldata.SignedTxGroup{}, time.Millisecond, 100, 0}, results{nil, nil, false}},
	}
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := makePeer(nil, true, true, &config, log, 0)
			if test.fxn != nil {
				test.fxn(p)
			}
			var r results
			r.selectedTxns, r.selectedTxnIDs, r.partialTransactionsSet = p.selectPendingTransactions(test.arg.pendingTransactions, test.arg.sendWindow, test.arg.round, test.arg.bloomFilterSize)
			if !reflect.DeepEqual(r, test.result) {
				t.Errorf("selectPendingTransactions() gotSelectedTxns = %v, want %v", r, test.result)
			}
		})
	}
}

// TestSelectedMessagesModulator tests the use of the modulator on the returned list
func TestSelectedMessagesModulator(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	peer := Peer{}

	peer.lastRound = 10
	peer.requestedTransactionsModulator = 2
	peer.requestedTransactionsOffset = 1
	peer.lastSelectedTransactionsCount = 1
	peer.dataExchangeRate = 1000
	peer.recentSentTransactions = makeTransactionCache(10, 10, 0)

	dig1 := crypto.Digest{0x1, 0, 0, 0, 0, 0, 0, 0, 0}
	dig2 := crypto.Digest{0x2, 0, 0, 0, 0, 0, 0, 0, 0}
	dig3 := crypto.Digest{0x3, 0, 0, 0, 0, 0, 0, 0, 0}
	dig4 := crypto.Digest{0x4, 0, 0, 0, 0, 0, 0, 0, 0}
	dig5 := crypto.Digest{0x5, 0, 0, 0, 0, 0, 0, 0, 0}
	dig6 := crypto.Digest{0x6, 0, 0, 0, 0, 0, 0, 0, 0}

	a.Equal(txidToUint64(transactions.Txid(dig1)), uint64(1))
	a.Equal(txidToUint64(transactions.Txid(dig2)), uint64(2))
	a.Equal(txidToUint64(transactions.Txid(dig3)), uint64(3))
	a.Equal(txidToUint64(transactions.Txid(dig4)), uint64(4))
	a.Equal(txidToUint64(transactions.Txid(dig5)), uint64(5))
	a.Equal(txidToUint64(transactions.Txid(dig6)), uint64(6))

	pendingTransations := []pooldata.SignedTxGroup{
		pooldata.SignedTxGroup{GroupCounter: 1, GroupTransactionID: transactions.Txid(dig1), EncodedLength: 1},
		pooldata.SignedTxGroup{GroupCounter: 2, GroupTransactionID: transactions.Txid(dig2), EncodedLength: 1},
		pooldata.SignedTxGroup{GroupCounter: 3, GroupTransactionID: transactions.Txid(dig3), EncodedLength: 1},
		pooldata.SignedTxGroup{GroupCounter: 4, GroupTransactionID: transactions.Txid(dig4), EncodedLength: 1},
		pooldata.SignedTxGroup{GroupCounter: 5, GroupTransactionID: transactions.Txid(dig5), EncodedLength: 1},
		pooldata.SignedTxGroup{GroupCounter: 6, GroupTransactionID: transactions.Txid(dig6), EncodedLength: 1},
	}

	selectedTxns, _, _ := peer.selectPendingTransactions(pendingTransations, time.Millisecond, 5, 0)

	a.Equal(len(selectedTxns), 2)
	a.Equal(selectedTxns[0].GroupCounter, uint64(1))
	a.Equal(selectedTxns[1].GroupCounter, uint64(3))

}

// TestGetAcceptedMessages tests get accepted messages
func TestGetAcceptedMessages(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)

	var testList []uint64
	chPtr := &p.transactionPoolAckCh

	for i := uint64(0); i < maxAcceptedMsgSeq; i++ {
		*chPtr <- i
		testList = append(testList, i)
	}

	a.Equal(len(*chPtr), 64)
	a.Equal(p.getAcceptedMessages(), testList)
	a.Equal(len(*chPtr), 0)
	a.Equal(len(p.transactionPoolAckMessages), 0)

}

// TestDequeuePendingTransactionPoolAckMessages tests dequeuePendingTransactionPoolAckMessages
func TestDequeuePendingTransactionPoolAckMessages(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)

	ch := p.transactionPoolAckCh
	var testList []uint64

	for i := uint64(0); i < maxAcceptedMsgSeq; i++ {
		ch <- i
		testList = append(testList, i)
	}

	p.dequeuePendingTransactionPoolAckMessages()

	a.Equal(p.transactionPoolAckMessages, testList)

	testList = testList[:0]

	ch = p.transactionPoolAckCh

	// Note the +1
	for i := uint64(0); i < (maxAcceptedMsgSeq + 1); i++ {
		if i >= maxAcceptedMsgSeq {
			// Channel is bounded at maxAcceptedMsgSeq so we need to flush it
			p.dequeuePendingTransactionPoolAckMessages()
			testList = append(testList[1:], i)
		} else {
			testList = append(testList, i)
		}

		ch <- i
	}

	p.dequeuePendingTransactionPoolAckMessages()

	a.Equal(p.transactionPoolAckMessages, testList)

}

// TestUpdateMessageSent Tests whether we can update the messages sent fields
func TestUpdateMessageSent(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)

	txMsg := &transactionBlockMessage{
		Version: txnBlockMessageVersion,
		Round:   42,
	}

	txnIds := []transactions.Txid{transactions.Txid(crypto.Hash([]byte{0x31, 0x32}))}
	timestamp := 10 * time.Second
	sequenceNumber := uint64(23)
	messageSize := 35
	bFilter := bloomFilter{}

	a.False(p.recentSentTransactions.contained(txnIds[0]))

	p.updateMessageSent(txMsg, txnIds, timestamp, sequenceNumber, messageSize)

	a.True(p.recentSentTransactions.contained(txnIds[0]))
	a.Equal(p.lastSentMessageSequenceNumber, sequenceNumber)
	a.Equal(p.lastSentMessageRound, txMsg.Round)
	a.Equal(p.lastSentMessageTimestamp, timestamp)
	a.Equal(p.lastSentMessageSize, messageSize)

	p.updateSentBoomFilter(bFilter, 0)

	a.Equal(p.lastSentBloomFilter, bFilter)

}

// TestIncomingPeersOnly Tests whether we can extract outgoing peers only
func TestIncomingPeersOnly(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p1 := makePeer(nil, true, true, &config, log, 0)
	p2 := makePeer(nil, true, false, &config, log, 0)
	p3 := makePeer(nil, false, true, &config, log, 0)
	p4 := makePeer(nil, false, false, &config, log, 0)

	peers := []*Peer{p1, p2, p3, p4}

	incomingPeers := incomingPeersOnly(peers)

	a.Equal(len(incomingPeers), 2)
	a.Equal(incomingPeers[0], p3)
	a.Equal(incomingPeers[1], p4)
}

// TestLocalRequestParams Tests setting and getting local request params
func TestLocalRequestParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(nil, true, true, &config, log, 0)

	p.setLocalRequestParams(256, 256)
	offset, modulator := p.getLocalRequestParams()
	a.Equal(offset, uint8(1))
	a.Equal(modulator, uint8(255))

	p.setLocalRequestParams(23, 256)
	offset, modulator = p.getLocalRequestParams()
	a.Equal(offset, uint8(23))
	a.Equal(modulator, uint8(255))

}

// TestSimpleGetters Tests the "simple" getters for the Peer Object
func TestSimpleGetters(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	var sentinelInterface interface{}
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p := makePeer(sentinelInterface, true, true, &config, log, 0)

	a.Equal(p.GetNetworkPeer(), sentinelInterface)
	a.Equal(p.GetTransactionPoolAckChannel(), p.transactionPoolAckCh)
}

// TestMakePeer Tests the Peer factory function
func TestMakePeer(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var sentinelInterface interface{}
	config := config.GetDefaultLocal()
	tlog := logging.TestingLog(t)
	log := wrapLogger(tlog, &config)
	p1 := makePeer(sentinelInterface, true, true, &config, log, 0)

	a.NotNil(p1)
	a.Equal(p1.networkPeer, sentinelInterface)
	a.Equal(p1.isOutgoing, true)
	a.Equal(p1.recentSentTransactions, makeTransactionCache(shortTermRecentTransactionsSentBufferLength, longTermRecentTransactionsSentBufferLength, pendingUnconfirmedRemoteMessages))
	a.Equal(p1.requestedTransactionsModulator, uint8(1))
	a.Equal(p1.dataExchangeRate, uint64(defaultRelayToRelayDataExchangeRate))

	// Check that we have different values if the local node relay is false
	p2 := makePeer(sentinelInterface, true, false, &config, log, 0)

	a.NotNil(p2)
	a.Equal(p1.networkPeer, sentinelInterface)
	a.Equal(p1.isOutgoing, true)
	a.Equal(p1.recentSentTransactions, makeTransactionCache(shortTermRecentTransactionsSentBufferLength, longTermRecentTransactionsSentBufferLength, pendingUnconfirmedRemoteMessages))
	a.Equal(p2.requestedTransactionsModulator, uint8(0))
	a.Equal(p2.dataExchangeRate, uint64(defaultDataExchangeRate))

}
