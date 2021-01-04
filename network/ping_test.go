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
)

// for two node network, check that B can ping A and get a reply
func TestPing(t *testing.T) {
	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.config.PeerPingPeriodSeconds = 5
	netA.Start()
	defer func() { t.Log("stopping A"); netA.Stop(); t.Log("A done") }()
	netB := makeTestWebsocketNode(t)
	netB.config.GossipFanout = 1
	netB.config.PeerPingPeriodSeconds = 5
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook = MakePhonebook(1, 1*time.Millisecond)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default")
	netB.Start()
	defer func() { t.Log("stopping B"); netB.Stop(); t.Log("B done") }()

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	t.Log("a ready")
	waitReady(t, netB, readyTimeout.C)
	t.Log("b ready")

	bpeers := netB.GetPeers(PeersConnectedOut)
	require.Equal(t, 1, len(bpeers))

	peer := bpeers[0].(*wsPeer)
	prePing := time.Now()
	peer.sendPing()
	const waitStep = 10 * time.Millisecond
	for i := 1; i <= 100; i++ {
		time.Sleep(waitStep)
		_, lastPingRoundTripTime := peer.pingTimes()
		if lastPingRoundTripTime > 0 {
			postPing := time.Now()
			testTime := postPing.Sub(prePing)
			if lastPingRoundTripTime < testTime {
				// success
				return
			}
			t.Fatalf("ping came back with bogus time %s after %s test waiting", lastPingRoundTripTime, testTime)
		}
	}
	t.FailNow()
}
