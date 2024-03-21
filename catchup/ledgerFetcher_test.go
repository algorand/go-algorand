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
	"github.com/algorand/go-algorand/test/partitiontest"
)

type dummyLedgerFetcherReporter struct {
}

func (lf *dummyLedgerFetcherReporter) updateLedgerFetcherProgress(*ledger.CatchpointCatchupAccessorProgress) {
}

func TestNoPeersAvailable(t *testing.T) {
	partitiontest.PartitionTest(t)

	lf := makeLedgerFetcher(&mocks.MockNetwork{}, &mocks.MockCatchpointCatchupAccessor{}, logging.TestingLog(t), &dummyLedgerFetcherReporter{}, config.GetDefaultLocal())
	peer := &lf // The peer is an opaque interface.. we can add anything as a Peer.
	err := lf.downloadLedger(context.Background(), peer, basics.Round(0))
	require.Equal(t, errNonHTTPPeer, err)
}

func TestNonParsableAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	lf := makeLedgerFetcher(&mocks.MockNetwork{}, &mocks.MockCatchpointCatchupAccessor{}, logging.TestingLog(t), &dummyLedgerFetcherReporter{}, config.GetDefaultLocal())
	peer := testHTTPPeer(":def")
	err := lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
	require.Error(t, err)
}

func TestLedgerFetcherErrorResponseHandling(t *testing.T) {
	partitiontest.PartitionTest(t)
	testcases := []struct {
		name               string
		httpServerResponse int
		contentTypes       []string
		err                error
	}{
		{
			name:               "getPeerLedger 400 Response",
			httpServerResponse: http.StatusNotFound,
			contentTypes:       make([]string, 0),
			err:                errNoLedgerForRound,
		},
		{
			name:               "getPeerLedger 500 Response",
			httpServerResponse: http.StatusInternalServerError,
			contentTypes:       make([]string, 0),
			err:                fmt.Errorf("getPeerLedger error response status code %d", http.StatusInternalServerError),
		},
		{
			name:               "getPeerLedger No Content Type",
			httpServerResponse: http.StatusOK,
			contentTypes:       make([]string, 0),
			err:                fmt.Errorf("getPeerLedger : http ledger fetcher invalid content type count %d", 0),
		},
		{
			name:               "getPeerLedger Too Many Content Types",
			httpServerResponse: http.StatusOK,
			contentTypes:       []string{"applications/one", "applications/two"},
			err:                fmt.Errorf("getPeerLedger : http ledger fetcher invalid content type count %d", 2),
		},
		{
			name:               "getPeerLedger Invalid Content Type",
			httpServerResponse: http.StatusOK,
			contentTypes:       []string{"applications/one"},
			err:                fmt.Errorf("getPeerLedger : http ledger fetcher response has an invalid content type : %s", "applications/one"),
		},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
			mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
				for _, contentType := range tc.contentTypes {
					w.Header().Add("Content-Type", contentType)
				}
				w.WriteHeader(tc.httpServerResponse)
			})
			lf := makeLedgerFetcher(&mocks.MockNetwork{}, &mocks.MockCatchpointCatchupAccessor{}, logging.TestingLog(t), &dummyLedgerFetcherReporter{}, config.GetDefaultLocal())
			peer := testHTTPPeer(listener.Addr().String())
			err = lf.getPeerLedger(context.Background(), &peer, basics.Round(0))
			require.Equal(t, tc.err, err)
		})
	}
}

func TestLedgerFetcherHeadLedger(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create a dummy server.
	mux := http.NewServeMux()
	s := &http.Server{
		Handler: mux,
	}
	listener, err := net.Listen("tcp", "localhost:")

	var httpServerResponse = 0
	var contentTypes = make([]string, 0)
	require.NoError(t, err)
	go s.Serve(listener)
	defer s.Close()
	defer listener.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		for _, contentType := range contentTypes {
			w.Header().Add("Content-Type", contentType)
		}
		w.WriteHeader(httpServerResponse)
	})
	successPeer := testHTTPPeer(listener.Addr().String())
	lf := makeLedgerFetcher(&mocks.MockNetwork{}, &mocks.MockCatchpointCatchupAccessor{}, logging.TestingLog(t), &dummyLedgerFetcherReporter{}, config.GetDefaultLocal())

	// headLedger non-http peer
	err = lf.headLedger(context.Background(), nil, basics.Round(0))
	require.Equal(t, errNonHTTPPeer, err)

	// headLedger parseURL failure
	parseFailurePeer := testHTTPPeer("foobar")
	err = lf.headLedger(context.Background(), &parseFailurePeer, basics.Round(0))
	require.Equal(t, fmt.Errorf("could not parse a host from url"), err)

	// headLedger 404 response
	httpServerResponse = http.StatusNotFound
	err = lf.headLedger(context.Background(), &successPeer, basics.Round(0))
	require.Equal(t, errNoLedgerForRound, err)

	// headLedger 200 response
	httpServerResponse = http.StatusOK
	err = lf.headLedger(context.Background(), &successPeer, basics.Round(0))
	require.NoError(t, err)

	// headLedger 500 response
	httpServerResponse = http.StatusInternalServerError
	err = lf.headLedger(context.Background(), &successPeer, basics.Round(0))
	require.Equal(t, fmt.Errorf("headLedger error response status code %d", http.StatusInternalServerError), err)
}
