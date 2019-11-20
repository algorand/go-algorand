// Copyright (C) 2019 Algorand, Inc.
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
	sender := MockEventSender{}
	bs := blockstats{log: &sender}

	bs.onBlock(v1.Block{Round: 300})
	time.Sleep(500 * time.Millisecond)
	bs.onBlock(v1.Block{Round: 301})

	require.Equal(t, 1, len(sender.events))
	details := sender.events[0].details.(telemetryspec.BlockStatsEventDetails)

	// Make sure the duration is close to 500ms
	require.True(t, int(details.AgreementDurationMs) < 600)
	require.True(t, int(details.AgreementDurationMs) > 400)
}
