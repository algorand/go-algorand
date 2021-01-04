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

package main

import (
	"testing"
	"time"

	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/stretchr/testify/require"
)

type event struct {
	category telemetryspec.Category

	identifier telemetryspec.Event

	details interface{}
}

type MockEventSender struct {
	events []event
}

func (mes *MockEventSender) EventWithDetails(category telemetryspec.Category, identifier telemetryspec.Event, details interface{}) {
	mes.events = append(mes.events, event{category: category, identifier: identifier, details: details})
}

func TestConsecutiveBlocks(t *testing.T) {
	sender := MockEventSender{}
	bs := blockstats{log: &sender}

	bs.onBlock(v1.Block{Round: 300})
	// first consecutive block
	bs.onBlock(v1.Block{Round: 301})
	// reset
	bs.onBlock(v1.Block{Round: 303})
	// second consecutive block
	bs.onBlock(v1.Block{Round: 304})

	require.Equal(t, 2, len(sender.events))
}

func TestAgreementTime(t *testing.T) {
	sleepTime := 50 * time.Millisecond
	testAttempts := 0
	const maxTestAttempts = 10
	for {
		sleepTimeHighWatermark := time.Duration(int64(sleepTime) * 105 / 100)

		sender := MockEventSender{}
		bs := blockstats{log: &sender}

		start := time.Now()
		bs.onBlock(v1.Block{Round: 300})
		time.Sleep(sleepTime)
		bs.onBlock(v1.Block{Round: 301})
		end := time.Now()

		require.Equal(t, 1, len(sender.events))
		details := sender.events[0].details.(telemetryspec.BlockStatsEventDetails)

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
