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

package network

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/testPartitioning"
)

type eventsDetailsLogger struct {
	logging.Logger
	eventIdentifier telemetryspec.Event
	eventReceived   chan interface{}
}

func (dl eventsDetailsLogger) EventWithDetails(category telemetryspec.Category, identifier telemetryspec.Event, details interface{}) {
	if category == telemetryspec.Network && identifier == dl.eventIdentifier {
		dl.eventReceived <- details

	}
}

// for two node network, check that B can ping A and get a reply
func TestRequestLogger(t *testing.T) {
	testPartitioning.PartitionTest(t)

	log := logging.TestingLog(t)
	dl := eventsDetailsLogger{Logger: log, eventReceived: make(chan interface{}, 1), eventIdentifier: telemetryspec.HTTPRequestEvent}
	log.SetLevel(logging.Level(defaultConfig.BaseLoggerDebugLevel))
	netA := &WebsocketNetwork{
		log:       dl,
		config:    defaultConfig,
		phonebook: MakePhonebook(1, 1*time.Millisecond),
		GenesisID: "go-test-network-genesis",
		NetworkID: config.Devtestnet,
	}
	netA.config.EnableRequestLogger = true
	netA.setup()
	netA.eventualReadyDelay = time.Second

	netA.config.GossipFanout = 1
	netA.Start()
	defer func() { t.Log("stopping A"); netA.Stop(); t.Log("A done") }()
	netB := makeTestWebsocketNode(t)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook = MakePhonebook(1, 1*time.Millisecond)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", PhoneBookEntryRelayRole)
	netB.Start()
	defer func() { t.Log("stopping B"); netB.Stop(); t.Log("B done") }()

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	select {
	case <-time.After(10 * time.Second):
		// we failed to get the event within the time limits.
		t.Errorf("Event was not written to logger")
	case <-dl.eventReceived:
		// great, we got the desired event!
	}
}
