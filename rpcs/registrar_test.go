// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package rpcs

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestServicePathsShareServeMux registers every service path on one
// http.ServeMux, as the networks do, and checks that each request reaches the
// right pattern with the expected path values. ServeMux panics on an invalid
// or conflicting pattern, so this also guards against both.
func TestServicePathsShareServeMux(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	mux := http.NewServeMux()
	for _, pattern := range []string{
		network.GossipNetworkPath,
		network.HealthServiceStatusPath,
		BlockServiceBlockPath,
		LedgerServiceLedgerPath,
		TxServiceHTTPPath,
	} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Pattern", r.Pattern)
			w.Header().Set("Genesis", r.PathValue("genesisID"))
			w.Header().Set("Round", r.PathValue("round"))
		})
	}

	tests := []struct {
		path    string
		pattern string
		genesis string
		round   string
	}{
		{"/v1/testnet-v1.0/gossip", network.GossipNetworkPath, "testnet-v1.0", ""},
		{"/status", network.HealthServiceStatusPath, "", ""},
		{"/v1/testnet-v1.0/block/1a", BlockServiceBlockPath, "testnet-v1.0", "1a"},
		{"/v1/testnet-v1.0/ledger/zz", LedgerServiceLedgerPath, "testnet-v1.0", "zz"},
		{"/v1/testnet-v1.0/txsync", TxServiceHTTPPath, "testnet-v1.0", ""},
		// Only version 1 is served
		{"/v2/testnet-v1.0/block/1a", "", "", ""},
		{"/v1/testnet-v1.0/block/", "", "", ""},
	}
	for _, tt := range tests {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", tt.path, nil))
		if tt.pattern == "" {
			a.Equal(http.StatusNotFound, rr.Code, tt.path)
			continue
		}
		a.Equal(http.StatusOK, rr.Code, tt.path)
		a.Equal(tt.pattern, rr.Header().Get("Pattern"), tt.path)
		a.Equal(tt.genesis, rr.Header().Get("Genesis"), tt.path)
		a.Equal(tt.round, rr.Header().Get("Round"), tt.path)
	}
}
