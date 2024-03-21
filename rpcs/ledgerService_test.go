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

package rpcs

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type fakeNetwork struct {
	network.GossipNode
	router *mux.Router
	*mock.Mock
}

func (fnet *fakeNetwork) RegisterHTTPHandler(path string, handler http.Handler) {
	fnet.router.Handle(path, handler)
	fnet.Called(path, handler)
}

type fakeLedger struct {
	*mock.Mock
}

func (fledger *fakeLedger) GetCatchpointStream(round basics.Round) (ledger.ReadCloseSizer, error) {
	args := fledger.Called(round)
	return args.Get(0).(ledger.ReadCloseSizer), args.Error(1)
}

type readCloseSizer struct {
	io.ReadCloser
	*mock.Mock
}

func (r readCloseSizer) Size() (int64, error) {
	args := r.Called()
	return int64(args.Int(0)), args.Error(1)
}

func (r readCloseSizer) Close() error {
	return nil
}

func TestLedgerService(t *testing.T) {
	partitiontest.PartitionTest(t)
	genesisID := "testGenesisID"
	cfg := config.GetDefaultLocal()
	l := fakeLedger{Mock: &mock.Mock{}}
	fnet := fakeNetwork{router: mux.NewRouter(), Mock: &mock.Mock{}}

	// Test LedgerService not enabled
	cfg.EnableLedgerService = false
	ledgerService := MakeLedgerService(cfg, &l, &fnet, genesisID)
	fnet.AssertNotCalled(t, "RegisterHTTPHandler", LedgerServiceLedgerPath, ledgerService)
	ledgerService.Start()
	require.Equal(t, int32(0), ledgerService.running.Load())

	// Test GET 404
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)
	ledgerService.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)

	// Test LedgerService enabled
	cfg.EnableLedgerService = true
	fnet.On("RegisterHTTPHandler", LedgerServiceLedgerPath, mock.Anything).Return()
	ledgerService = MakeLedgerService(cfg, &l, &fnet, genesisID)
	fnet.AssertCalled(t, "RegisterHTTPHandler", LedgerServiceLedgerPath, ledgerService)
	ledgerService.Start()
	require.Equal(t, int32(1), ledgerService.running.Load())

	// Test GET 400 Bad Version String
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/v2/foobar/ledger/23", nil)
	require.NoError(t, err)
	fnet.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "unsupported version '2'")

	// Test Get 400 Bad Genesis ID
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/v1/foobar/ledger/23", nil)
	require.NoError(t, err)
	fnet.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "mismatching genesisID 'foobar'")

	// Test Get 400 No Path Vars
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "", nil)
	require.NoError(t, err)
	ledgerService.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "missing genesisID")

	// Not Testing non path var handling because I'm not convinced it's reachable given `LedgerServiceLedgerPath`

	// Test Get 400 round out of range
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", fmt.Sprintf("/v1/%s/ledger/zzzzzzzzzzzzzzzzzzzzzzz", genesisID), nil)
	require.NoError(t, err)
	fnet.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "specified round number could not be parsed using base 36 : ")

	// Test Get Catchpoint Not Found
	rr = httptest.NewRecorder()
	rnd := 1111
	b36Rnd, err := strconv.ParseUint(fmt.Sprintf("%d", rnd), 36, 64)
	require.NoError(t, err)
	req, err = http.NewRequest("GET", fmt.Sprintf("/v1/%s/ledger/%d", genesisID, rnd), nil)
	require.NoError(t, err)
	rcs := readCloseSizer{Mock: &mock.Mock{}}
	gcp := l.On("GetCatchpointStream", basics.Round(b36Rnd)).Return(&rcs, ledgercore.ErrNoEntry{Round: basics.Round(rnd)})
	fnet.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)
	require.Contains(t, rr.Body.String(), fmt.Sprintf("catchpoint file for round %d is not available", b36Rnd))

	// Test Get Catchpoint Unexpected Error
	rr = httptest.NewRecorder()
	require.NoError(t, err)
	req, err = http.NewRequest("GET", fmt.Sprintf("/v1/%s/ledger/%d", genesisID, rnd), nil)
	require.NoError(t, err)
	gcp.Unset()
	gcp = l.On("GetCatchpointStream", basics.Round(b36Rnd)).Return(&rcs, ledgercore.ErrNoSpace)
	fnet.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Contains(t, rr.Body.String(), fmt.Sprintf("catchpoint file for round %d could not be retrieved due to internal error : ", b36Rnd))

	// Test HEAD Catchpoint 200
	rr = httptest.NewRecorder()
	require.NoError(t, err)
	req, err = http.NewRequest("HEAD", fmt.Sprintf("/v1/%s/ledger/%d", genesisID, rnd), nil)
	require.NoError(t, err)
	gcp.Unset()
	gcp = l.On("GetCatchpointStream", basics.Round(b36Rnd)).Return(&rcs, nil)
	fnet.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, LedgerResponseContentType, rr.Header().Get("Content-Type"))

	// Test LedgerService Stopped
	ledgerService.Stop()
	require.Equal(t, int32(0), ledgerService.running.Load())
}
