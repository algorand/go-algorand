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

package catchup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
)

type dummyLedgerFetcherReporter struct {
}

func (lf *dummyLedgerFetcherReporter) updateLedgerFetcherProgress(*ledger.CatchpointCatchupAccessorProgress) {
}

func TestNoPeersAvailable(t *testing.T) {
	lf := makeLedgerFetcher(&mocks.MockNetwork{}, &mocks.MockCatchpointCatchupAccessor{}, logging.TestingLog(t), &dummyLedgerFetcherReporter{}, config.GetDefaultLocal())
	err := lf.downloadLedger(context.Background(), basics.Round(0))
	require.Equal(t, errNoPeersAvailable, err)
	lf.peers = append(lf.peers, &lf) // The peer is an opaque interface.. we can add anything as a Peer.
	err = lf.downloadLedger(context.Background(), basics.Round(0))
	require.Equal(t, errNonHTTPPeer, err)
}

func TestNonParsableAddress(t *testing.T) {
	lf := makeLedgerFetcher(&mocks.MockNetwork{}, &mocks.MockCatchpointCatchupAccessor{}, logging.TestingLog(t), &dummyLedgerFetcherReporter{}, config.GetDefaultLocal())
	peer := testHTTPPeer(":def")
	err := lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
	require.Error(t, err)
}

func TestLedgerFetcherErrorResponseHandling(t *testing.T) {
	// create a dummy server.
	mux := http.NewServeMux()
	s := &http.Server{
		Handler: mux,
	}
	listener, err := net.Listen("tcp", "localhost:")

	require.NoError(t, err)
	go s.Serve(listener)
	defer s.Close()
	defer listener.Close()

	httpServerResponse := http.StatusNotFound
	contentTypes := make([]string, 0)
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		for _, contentType := range contentTypes {
			w.Header().Add("Content-Type", contentType)
		}
		w.WriteHeader(httpServerResponse)
	})

	lf := makeLedgerFetcher(&mocks.MockNetwork{}, &mocks.MockCatchpointCatchupAccessor{}, logging.TestingLog(t), &dummyLedgerFetcherReporter{}, config.GetDefaultLocal())
	peer := testHTTPPeer(listener.Addr().String())
	err = lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
	require.Equal(t, errNoLedgerForRound, err)

	httpServerResponse = http.StatusInternalServerError
	err = lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
	require.Equal(t, fmt.Errorf("getPeerLedger error response status code %d", httpServerResponse), err)

	httpServerResponse = http.StatusOK
	err = lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
	require.Equal(t, fmt.Errorf("getPeerLedger : http ledger fetcher invalid content type count %d", 0), err)

	contentTypes = []string{"applications/one", "applications/two"}
	err = lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
	require.Equal(t, fmt.Errorf("getPeerLedger : http ledger fetcher invalid content type count %d", len(contentTypes)), err)

	contentTypes = []string{"applications/one"}
	err = lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
	require.Equal(t, fmt.Errorf("getPeerLedger : http ledger fetcher response has an invalid content type : %s", contentTypes[0]), err)
}
