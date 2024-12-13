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

package peerstore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPeerInfoFromAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testcases := []struct {
		name   string
		addr   string
		errMsg string
	}{
		{"invalid multiaddr string", "/ip4/", "failed to parse multiaddr"},
		{"invalid tcp port", "/ip4/1.2.3.4/tcp/AAAAAAA", "failed to parse port addr"},
		{"unknown protocol", "/ip4/1.2.3.4/tcp/443/AAAAAAA", "unknown protocol"},
		{"badprotocol", "/badprotocol/1.2.3.4/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb", "failed to parse multiaddr"},
		{"invalid peerID", "/ip4/1.2.3.4/tcp/4041/p2p/AAAAAAA", "failed to parse p2p addr"},
		{"invalid value for protocol", "/ip4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb", "invalid value \"ams-2.bootstrap.libp2p.io\" for protocol ip4"},
		{"dns4", "/dns4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb", ""},
		{"ipv4", "/ip4/147.75.83.83/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Na", ""},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("test %s", tc.name), func(t *testing.T) {
			t.Parallel()
			_, err := PeerInfoFromAddr(tc.addr)
			if tc.errMsg != "" {
				require.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPeerInfoFromAddrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	addrs := []string{
		"/ip4/1.2.3.4/tcp/4041/p2p/AAAAAAA",
		"/ip4/1.2.3.4/tcp/AAAAAAA",
		"/dns4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
		"/ip4/147.75.83.83/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Na",
	}
	peerInfos, malformedAddrs := PeerInfoFromAddrs(addrs)
	require.Len(t, peerInfos, 2)
	require.Len(t, malformedAddrs, 2)
	require.Contains(t, malformedAddrs["/ip4/1.2.3.4/tcp/4041/p2p/AAAAAAA"], "failed to parse multiaddr")
	require.Contains(t, malformedAddrs["/ip4/1.2.3.4/tcp/AAAAAAA"], "failed to parse port addr")
}
