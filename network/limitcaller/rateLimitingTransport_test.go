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

package limitcaller

import (
	"net/http"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

type ctStore struct {
	t      *testing.T
	getCnt uint64
}

func (c *ctStore) GetConnectionWaitTime(addrOrPeerID string) (bool, time.Duration, time.Time) {
	require.NotEmpty(c.t, addrOrPeerID)
	c.getCnt++
	return false, 0, time.Time{}
}

func (c *ctStore) UpdateConnectionTime(addrOrPeerID string, provisionalTime time.Time) bool {
	require.NotEmpty(c.t, addrOrPeerID)
	return false
}

type emptyRoundTripper struct{}

func (e *emptyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

func TestRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ctStore := ctStore{t: t}
	rtt := MakeRateLimitingBoundTransportWithRoundTripper(&ctStore, 0, &emptyRoundTripper{}, "")
	req := &http.Request{}
	_, err := rtt.RoundTrip(req)
	require.ErrorContains(t, err, "target not set")
	require.Equal(t, uint64(0), ctStore.getCnt)

	rtt = MakeRateLimitingBoundTransportWithRoundTripper(&ctStore, 0, &emptyRoundTripper{}, "mytarget")
	req, err = http.NewRequest("GET", "https://example.com/test", nil)
	require.NoError(t, err)
	_, err = rtt.RoundTrip(req)
	require.ErrorContains(t, err, "URL host does not match the target")
	require.Equal(t, uint64(0), ctStore.getCnt)

	rtt = MakeRateLimitingBoundTransportWithRoundTripper(&ctStore, 0, &emptyRoundTripper{}, "mytarget")
	req, err = http.NewRequest("GET", "/test", nil)
	require.NoError(t, err)
	_, err = rtt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, uint64(1), ctStore.getCnt)
}
