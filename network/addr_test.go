// Copyright (C) 2019-2023 Algorand, Inc.
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
	}
	for _, addr := range badUrls {
		t.Run(addr, func(t *testing.T) {
			_, err := ParseHostOrURL(addr)
			require.Error(t, err, "url should fail", addr)
		})
	}
}
