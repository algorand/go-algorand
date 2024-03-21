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

package network

import (
	"bytes"
	"math/rand"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
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
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	if defaultConfig.ConnectionsRateLimitingCount == 0 || defaultConfig.ConnectionsRateLimitingWindowSeconds == 0 {
		t.Skip()
	}
	log := logging.TestingLog(t)
	log.SetLevel(logging.Level(defaultConfig.BaseLoggerDebugLevel))
	testConfig := defaultConfig
	// This test is conducted locally, so we want to treat all hosts the same for counting incoming requests.
	testConfig.DisableLocalhostConnectionRateLimit = false
	wn := &WebsocketNetwork{
		log:       log,
		config:    testConfig,
		phonebook: MakePhonebook(1, 1),
		GenesisID: "go-test-network-genesis",
		NetworkID: config.Devtestnet,
	}

	// increase the IncomingConnectionsLimit/MaxConnectionsPerIP limits, since we don't want to test these.
	wn.config.IncomingConnectionsLimit = int(testConfig.ConnectionsRateLimitingCount) * 5
	wn.config.MaxConnectionsPerIP += int(testConfig.ConnectionsRateLimitingCount) * 5

	wn.setup()
	wn.eventualReadyDelay = time.Second

	netA := wn
	netA.config.GossipFanout = 1

	defer func() { t.Log("stopping A"); netA.Stop(); t.Log("A done") }()

	netA.Start()
	addrA, postListen := netA.Address()
	require.Truef(t, postListen, "Listening network failed to start")

	noAddressConfig := testConfig
	noAddressConfig.NetAddress = ""

	clientsCount := int(testConfig.ConnectionsRateLimitingCount + 5)

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

	deadline := time.Now().Add(time.Duration(testConfig.ConnectionsRateLimitingWindowSeconds) * time.Second)

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
		if connectedClients >= int(testConfig.ConnectionsRateLimitingCount) {
			timedOut = time.Now().After(deadline)
			break
		}
	}
	if !timedOut {
		// test to see that at least some of the clients have seen 429
		require.Equal(t, int(testConfig.ConnectionsRateLimitingCount), connectedClients)
	}
}

func TestRemoteAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tr := makeTrackerRequest("127.0.0.1:444", "", "", time.Now(), nil)
	require.Equal(t, "127.0.0.1:444", tr.remoteAddr)
	require.Equal(t, "127.0.0.1", tr.remoteHost)
	require.Equal(t, "444", tr.remotePort)

	require.Equal(t, "127.0.0.1:444", tr.remoteAddress())

	// remoteHost set to something else via X-Forwared-For HTTP headers
	tr.remoteHost = "10.0.0.1"
	require.Equal(t, "10.0.0.1", tr.remoteAddress())

	// otherPublicAddr is set via X-Algorand-Location HTTP header
	// and matches to the remoteHost
	tr.otherPublicAddr = "10.0.0.1:555"
	require.Equal(t, "10.0.0.1:555", tr.remoteAddress())

	// otherPublicAddr does not match remoteHost
	tr.remoteHost = "127.0.0.1"
	tr.otherPublicAddr = "127.0.0.99:555"
	require.Equal(t, "127.0.0.1:444", tr.remoteAddress())
}

func TestIsLocalHost(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.True(t, isLocalhost("localhost"))
	require.True(t, isLocalhost("127.0.0.1"))
	require.True(t, isLocalhost("[::1]"))
	require.True(t, isLocalhost("::1"))
	require.True(t, isLocalhost("[::]"))
	require.False(t, isLocalhost("192.168.0.1"))
	require.False(t, isLocalhost(""))
	require.False(t, isLocalhost("0.0.0.0"))
	require.False(t, isLocalhost("127.0.0.0"))
}

func TestGetForwardedConnectionAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var bufNewLogger bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&bufNewLogger)

	rt := RequestTracker{log: log}
	header := http.Header{}

	ip := rt.getForwardedConnectionAddress(header)
	require.Nil(t, ip)
	msgs := bufNewLogger.String()
	require.Empty(t, msgs)

	rt.config.UseXForwardedForAddressField = "X-Custom-Addr"
	ip = rt.getForwardedConnectionAddress(header)
	require.Nil(t, ip)
	msgs = bufNewLogger.String()
	require.NotEmpty(t, msgs)
	require.Contains(t, msgs, "UseForwardedForAddressField is configured as 'X-Custom-Addr'")

	// try again and ensure the message is not logged second time.
	bufNewLogger.Reset()
	ip = rt.getForwardedConnectionAddress(header)
	require.Nil(t, ip)
	msgs = bufNewLogger.String()
	require.Empty(t, msgs)

	// check a custom address can be parsed successfully.
	header.Set("X-Custom-Addr", "123.123.123.123")
	ip = rt.getForwardedConnectionAddress(header)
	require.NotNil(t, ip)
	require.Equal(t, "123.123.123.123", ip.String())
	msgs = bufNewLogger.String()
	require.Empty(t, msgs)

	// check a custom address in a form of a list can not be parsed,
	// this is the original behavior since the Release.
	header.Set("X-Custom-Addr", "123.123.123.123, 234.234.234.234")
	ip = rt.getForwardedConnectionAddress(header)
	require.Nil(t, ip)
	msgs = bufNewLogger.String()
	require.NotEmpty(t, msgs)
	require.Contains(t, msgs, "unable to parse origin address")

	// "X-Forwarded-For
	bufNewLogger.Reset()
	rt.misconfiguredUseForwardedForAddress.Store(false)
	rt.config.UseXForwardedForAddressField = "X-Forwarded-For"
	header = http.Header{}

	// check "X-Forwarded-For" empty value.
	ip = rt.getForwardedConnectionAddress(header)
	require.Nil(t, ip)
	msgs = bufNewLogger.String()
	require.NotEmpty(t, msgs)
	require.Contains(t, msgs, "UseForwardedForAddressField is configured as 'X-Forwarded-For'")
	bufNewLogger.Reset()

	// check "X-Forwarded-For" single value.
	header.Set("X-Forwarded-For", "123.123.123.123")
	ip = rt.getForwardedConnectionAddress(header)
	require.NotNil(t, ip)
	require.Equal(t, "123.123.123.123", ip.String())
	msgs = bufNewLogger.String()
	require.Empty(t, msgs)

	// check "X-Forwarded-For" list values - the last one is used,
	// this is a new behavior.
	bufNewLogger.Reset()
	rt.config.UseXForwardedForAddressField = "X-Forwarded-For"
	header.Set("X-Forwarded-For", "123.123.123.123, 234.234.234.234")
	ip = rt.getForwardedConnectionAddress(header)
	require.NotNil(t, ip)
	require.Equal(t, "234.234.234.234", ip.String())
	msgs = bufNewLogger.String()
	require.Empty(t, msgs)

	// check multile X-Forwarded-For headers - the last one should be used
	header.Set("X-Forwarded-For", "127.0.0.1")
	header.Add("X-Forwarded-For", "234.234.234.234")
	ip = rt.getForwardedConnectionAddress(header)
	require.NotNil(t, ip)
	require.Equal(t, "234.234.234.234", ip.String())
	msgs = bufNewLogger.String()
	require.Empty(t, msgs)

	header.Set("X-Forwarded-For", "127.0.0.1")
	header.Add("X-Forwarded-For", "123.123.123.123, 234.234.234.234")
	ip = rt.getForwardedConnectionAddress(header)
	require.NotNil(t, ip)
	require.Equal(t, "234.234.234.234", ip.String())
	msgs = bufNewLogger.String()
	require.Empty(t, msgs)
}
