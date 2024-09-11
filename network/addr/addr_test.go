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

package addr

import (
	"net/url"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

type urlCase struct {
	text string
	out  url.URL
}

func TestParseHostOrURL(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	urlTestCases := []urlCase{
		{"localhost:123", url.URL{Scheme: "http", Host: "localhost:123"}},
		{"http://localhost:123", url.URL{Scheme: "http", Host: "localhost:123"}},
		{"ws://localhost:9999", url.URL{Scheme: "ws", Host: "localhost:9999"}},
		{"wss://localhost:443", url.URL{Scheme: "wss", Host: "localhost:443"}},
		{"https://localhost:123", url.URL{Scheme: "https", Host: "localhost:123"}},
		{"https://somewhere.tld", url.URL{Scheme: "https", Host: "somewhere.tld"}},
		{"http://127.0.0.1:123", url.URL{Scheme: "http", Host: "127.0.0.1:123"}},
		{"//somewhere.tld", url.URL{Scheme: "", Host: "somewhere.tld"}},
		{"//somewhere.tld:4601", url.URL{Scheme: "", Host: "somewhere.tld:4601"}},
		{"http://[::]:123", url.URL{Scheme: "http", Host: "[::]:123"}},
		{"1.2.3.4:123", url.URL{Scheme: "http", Host: "1.2.3.4:123"}},
		{"[::]:123", url.URL{Scheme: "http", Host: "[::]:123"}},
		{"r2-devnet.devnet.algodev.network:4560", url.URL{Scheme: "http", Host: "r2-devnet.devnet.algodev.network:4560"}},
		{"::11.22.33.44:123", url.URL{Scheme: "http", Host: "::11.22.33.44:123"}},
	}
	badUrls := []string{
		"justahost",
		"localhost:WAT",
		"http://localhost:WAT",
		"https://localhost:WAT",
		"ws://localhost:WAT",
		"wss://localhost:WAT",
		"//localhost:WAT",
		"://badaddress", // See rpcs/blockService_test.go TestRedirectFallbackEndpoints
		"://localhost:1234",
		":xxx",
		":xxx:1234",
		"::11.22.33.44",
		":a:1",
		":a:",
		":1",
		":a",
		":",
		"",
	}
	for _, tc := range urlTestCases {
		t.Run(tc.text, func(t *testing.T) {
			v, err := ParseHostOrURL(tc.text)
			require.NoError(t, err)
			if tc.out != *v {
				t.Errorf("url wanted %#v, got %#v", tc.out, v)
				return
			}
		})
		t.Run(tc.text+"-multiaddr", func(t *testing.T) {
			v, err := ParseHostOrURLOrMultiaddr(tc.text)
			require.NoError(t, err)
			if tc.out.Host != v {
				t.Errorf("url wanted %#v, got %#v", tc.text, v)
				return
			}
		})
	}
	for _, addr := range badUrls {
		t.Run(addr, func(t *testing.T) {
			_, err := ParseHostOrURL(addr)
			require.Error(t, err, "url should fail", addr)
			require.False(t, IsMultiaddr(addr))
		})
		t.Run(addr+"-multiaddr", func(t *testing.T) {
			_, err := ParseHostOrURLOrMultiaddr(addr)
			require.Error(t, err, "url should fail", addr)
			require.False(t, IsMultiaddr(addr))
		})
	}

}

func TestParseHostURLOrMultiaddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	validMultiAddrs := []string{
		"/ip4/127.0.0.1/tcp/8080",
		"/ip6/::1/tcp/8080",
		"/ip4/192.168.1.1/udp/9999/quic",
		"/ip4/192.168.1.1/tcp/8180/p2p/Qmewz5ZHN1AAGTarRbMupNPbZRfg3p5jUGoJ3JYEatJVVk",
		"/ip4/192.255.2.8/tcp/8180/ws",
	}

	badMultiAddrs := []string{
		"/ip4/256.256.256.256/tcp/8080", // Invalid IPv4 address.
		"/ip4/127.0.0.1/abc/8080",       // abc is not a valid protocol.
		"/ip4/127.0.0.1/tcp/abc",        // Port is not a valid number.
		"/unix",                         // Unix protocol without a path is invalid.
		"/ip4/127.0.0.1/tcp",            // Missing a port after tcp
		"/p2p/invalidPeerID",            // Invalid peer ID after p2p.
		"ip4/127.0.0.1/tcp/8080",        // Missing starting /.
	}

	for _, addr := range validMultiAddrs {
		t.Run(addr, func(t *testing.T) {
			v, err := ParseHostOrURLOrMultiaddr(addr)
			require.NoError(t, err)
			require.Equal(t, addr, v)
			require.True(t, IsMultiaddr(addr))
		})
	}

	for _, addr := range badMultiAddrs {
		t.Run(addr, func(t *testing.T) {
			_, err := ParseHostOrURLOrMultiaddr(addr)
			require.Error(t, err)
			require.False(t, IsMultiaddr(addr))
		})
	}

}
