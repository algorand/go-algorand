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

package main

import (
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

type event struct {
	category telemetryspec.Category

	identifier telemetryspec.Event

	details telemetryspec.BlockStatsEventDetails
}

type MockEventSender struct {
	events []event
}

func (mes *MockEventSender) EventWithDetails(category telemetryspec.Category, identifier telemetryspec.Event, details interface{}) {
	mes.events = append(mes.events, event{category: category, identifier: identifier, details: details.(telemetryspec.BlockStatsEventDetails)})
}

// Helper method to create an EncodedBlockCert for the block handler.
func makeTestBlock(round uint64) rpcs.EncodedBlockCert {
	return rpcs.EncodedBlockCert{Block: bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: basics.Round(round)}}}
}

func TestConsecutiveBlocks(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sender := MockEventSender{}
	bs := blockstats{log: &sender}

	bs.onBlock(makeTestBlock(300))
	// first consecutive block
	bs.onBlock(makeTestBlock(301))
	// reset
	bs.onBlock(makeTestBlock(303))
	// second consecutive block
	bs.onBlock(makeTestBlock(304))

	require.Equal(t, 2, len(sender.events))
}

func TestEventWithDetails(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sender := MockEventSender{}
	bs := blockstats{log: &sender}

	// Create blocks with some senders in the payload.
	makeStxnWithAddr := func(addr basics.Address) transactions.SignedTxnInBlock {
		return transactions.SignedTxnInBlock{SignedTxnWithAD: transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: transactions.Transaction{Header: transactions.Header{Sender: addr}}}}}
	}
	addr := basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	otherAddr := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	// Check that only unique addrs are returned by ActiveUsers.
	stxn1 := makeStxnWithAddr(addr)
	stxn2 := makeStxnWithAddr(otherAddr)
	stxn3 := makeStxnWithAddr(addr)
	// Make block with some transactions.
	testBlock := makeTestBlock(300)
	testBlock.Block.Payset = transactions.Payset{stxn1, stxn2, stxn3}

	bs.onBlock(makeTestBlock(299))
	bs.onBlock(testBlock)
	bs.onBlock(makeTestBlock(301))

	testCases := []struct {
		round       uint64
		activeUsers uint64
		txns        uint64
	}{
		{uint64(300), uint64(2), uint64(3)},
		{uint64(301), uint64(0), uint64(0)},
	}

	require.Equal(t, 2, len(sender.events))
	for i, event := range sender.events {
		require.Equal(t, testCases[i].round, event.details.Round)
		require.Equal(t, testCases[i].activeUsers, event.details.ActiveUsers)
		require.Equal(t, testCases[i].txns, event.details.Transactions)
	}
}

func TestAgreementTime(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sleepTime := 50 * time.Millisecond
	testAttempts := 0
	const maxTestAttempts = 10
	for {
		sleepTimeHighWatermark := time.Duration(int64(sleepTime) * 105 / 100)

		sender := MockEventSender{}
		bs := blockstats{log: &sender}

		start := time.Now()
		bs.onBlock(makeTestBlock(300))
		time.Sleep(sleepTime)
		bs.onBlock(makeTestBlock(301))
		end := time.Now()

		require.Equal(t, 1, len(sender.events))
		details := sender.events[0].details

		// Test to see that the wait duration is at least the amount of time we slept
		require.True(t, int(details.AgreementDurationMs) >= int(sleepTime)/int(time.Millisecond))

		// we want to test that the time is roughly the sleeping-time ( sleepTime ), but slow machines might not reflect that accurately.
		// to address that, we calculate the envelope time of the two onBlock calls, which is always greater than the desired high watermark.
		// this would give us an indication that the local machine isn't performing that great, and we might want to repeat the
		// test with a different time constrains.
		if end.Sub(start) >= sleepTimeHighWatermark {
			// something else took CPU between the above two onBlock calls; repeat the test with a larget interval.
			sleepTime *= 2
			testAttempts++
			require.True(t, testAttempts < maxTestAttempts)
			continue
		}
		require.True(t, int(details.AgreementDurationMs) < int(sleepTimeHighWatermark))
		break
	}

}
