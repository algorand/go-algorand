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
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

func (ard *hostIncomingRequests) remove(trackedRequest *TrackerRequest) {
	for i := range ard.requests {
		if ard.requests[i] == trackedRequest {
			// remove entry.
			ard.requests = append(ard.requests[0:i], ard.requests[i+1:]...)
			return
		}
	}
}
func TestHostIncomingRequestsOrdering(t *testing.T) {
	if defaultConfig.ConnectionsRateLimitingCount == 0 || defaultConfig.ConnectionsRateLimitingWindowSeconds == 0 {
		t.Skip()
	}
	// add 100 items to the hostIncomingRequests object, and make sure they are sorted.
	hir := hostIncomingRequests{}
	now := time.Now()
	perm := rand.Perm(100)
	for i := 0; i < 100; i++ {
		trackedRequest := makeTrackerRequest("remoteaddr", "host", "port", now.Add(time.Duration(perm[i])*time.Minute), nil)
		hir.add(trackedRequest)
	}
	require.Equal(t, 100, len(hir.requests))

	// make sure the array ends up being ordered.
	for i := 1; i < 100; i++ {
		require.True(t, hir.requests[i].created.After(hir.requests[i-1].created))
	}

	// test the remove function.
	for len(hir.requests) > 0 {
		// select a random item.
		i := rand.Int() % len(hir.requests)
		o := hir.requests[i]
		hir.remove(o)
		// make sure the item isn't there anymore.
		for _, p := range hir.requests {
			require.False(t, p == o)
			require.Equal(t, hir.countConnections(now.Add(-time.Second)), uint(len(hir.requests)))
		}
	}
}

func TestRateLimiting(t *testing.T) {
	if defaultConfig.ConnectionsRateLimitingCount == 0 || defaultConfig.ConnectionsRateLimitingWindowSeconds == 0 {
		t.Skip()
	}
	log := logging.TestingLog(t)
	log.SetLevel(logging.Level(defaultConfig.BaseLoggerDebugLevel))
	wn := &WebsocketNetwork{
		log:       log,
		config:    defaultConfig,
		phonebook: MakePhonebook(1, 1),
		GenesisID: "go-test-network-genesis",
		NetworkID: config.Devtestnet,
	}

	// increase the IncomingConnectionsLimit/MaxConnectionsPerIP limits, since we don't want to test these.
	wn.config.IncomingConnectionsLimit = int(defaultConfig.ConnectionsRateLimitingCount) * 5
	wn.config.MaxConnectionsPerIP += int(defaultConfig.ConnectionsRateLimitingCount) * 5

	wn.setup()
	wn.eventualReadyDelay = time.Second

	netA := wn
	netA.config.GossipFanout = 1

	defer func() { t.Log("stopping A"); netA.Stop(); t.Log("A done") }()

	netA.Start()
	addrA, postListen := netA.Address()
	require.Truef(t, postListen, "Listening network failed to start")

	noAddressConfig := defaultConfig
	noAddressConfig.NetAddress = ""

	clientsCount := int(defaultConfig.ConnectionsRateLimitingCount + 5)

	networks := make([]*WebsocketNetwork, clientsCount)
	phonebooks := make([]Phonebook, clientsCount)
	for i := 0; i < clientsCount; i++ {
		networks[i] = makeTestWebsocketNodeWithConfig(t, noAddressConfig)
		networks[i].config.GossipFanout = 1
		phonebooks[i] = MakePhonebook(networks[i].config.ConnectionsRateLimitingCount,
			time.Duration(networks[i].config.ConnectionsRateLimitingWindowSeconds)*time.Second)
		phonebooks[i].ReplacePeerList([]string{addrA}, "default", PhoneBookEntryRelayRole)
		networks[i].phonebook = MakePhonebook(1, 1*time.Millisecond)
		networks[i].phonebook.ReplacePeerList([]string{addrA}, "default", PhoneBookEntryRelayRole)
		defer func(net *WebsocketNetwork, i int) {
			t.Logf("stopping network %d", i)
			net.Stop()
			t.Logf("network %d done", i)
		}(networks[i], i)
	}

	deadline := time.Now().Add(time.Duration(defaultConfig.ConnectionsRateLimitingWindowSeconds) * time.Second)

	for i := 0; i < clientsCount; i++ {
		networks[i].Start()
	}

	var connectedClients int
	timedOut := false
	for {
		if time.Now().After(deadline) {
			timedOut = true
			break
		}
		connectedClients = 0
		time.Sleep(100 * time.Millisecond)
		for i := 0; i < clientsCount; i++ {
			// check if the channel is ready.
			readyCh := networks[i].Ready()
			select {
			case <-readyCh:
				// it's closed, so this client got connected.
				connectedClients++
				phonebookLen := len(phonebooks[i].GetAddresses(1, PhoneBookEntryRelayRole))
				// if this channel is ready, than we should have an address, since it didn't get blocked.
				require.Equal(t, 1, phonebookLen)
			default:
				// not ready yet.
				// wait abit longer.
			}
		}
		if connectedClients >= int(defaultConfig.ConnectionsRateLimitingCount) {
			timedOut = time.Now().After(deadline)
			break
		}
	}
	if !timedOut {
		// test to see that at least some of the clients have seen 429
		require.Equal(t, int(defaultConfig.ConnectionsRateLimitingCount), connectedClients)
	}
}
