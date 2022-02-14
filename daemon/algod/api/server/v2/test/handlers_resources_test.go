// Copyright (C) 2019-2022 Algorand, Inc.
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

package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

type mockLedger struct {
	accounts map[basics.Address]basics.AccountData
	latest   basics.Round
}

func (l *mockLedger) LookupAccount(round basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, basics.MicroAlgos, error) {
	ad, ok := l.accounts[addr]
	if !ok { // return empty / not found
		return ledgercore.AccountData{}, l.latest, basics.MicroAlgos{Raw: 0}, nil
	}
	return ledgercore.ToAccountData(ad), l.latest, basics.MicroAlgos{Raw: 0}, nil
}
func (l *mockLedger) LookupLatest(addr basics.Address) (basics.AccountData, basics.Round, basics.MicroAlgos, error) {
	ad, ok := l.accounts[addr]
	if !ok {
		return basics.AccountData{}, l.latest, basics.MicroAlgos{Raw: 0}, nil
	}
	return ad, l.latest, basics.MicroAlgos{Raw: 0}, nil
}

func (l *mockLedger) ConsensusParams(r basics.Round) (config.ConsensusParams, error) {
	return config.Consensus[protocol.ConsensusFuture], nil
}

func (l *mockLedger) Latest() basics.Round { return l.latest }

func (l *mockLedger) LookupResource(rnd basics.Round, addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ar ledgercore.AccountResource, err error) {
	panic("not implemented")
}
func (l *mockLedger) BlockCert(rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	panic("not implemented")
}
func (l *mockLedger) LatestTotals() (rnd basics.Round, at ledgercore.AccountTotals, err error) {
	panic("not implemented")
}
func (l *mockLedger) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	panic("not implemented")
}
func (l *mockLedger) Wait(r basics.Round) chan struct{} {
	panic("not implemented")
}
func (l *mockLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (c basics.Address, ok bool, err error) {
	panic("not implemented")
}
func (l *mockLedger) EncodedBlockCert(rnd basics.Round) (blk []byte, cert []byte, err error) {
	panic("not implemented")
}
func (l *mockLedger) Block(rnd basics.Round) (blk bookkeeping.Block, err error) {
	panic("not implemented")
}

func randomAccountWithResources(N int) basics.AccountData {
	a := ledgertesting.RandomAccountData(0)
	a.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
	a.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
	a.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
	a.AppParams = make(map[basics.AppIndex]basics.AppParams)
	for i := 0; i < N; i++ {
		switch i % 4 {
		case 0:
			a.Assets[basics.AssetIndex(i)] = ledgertesting.RandomAssetHolding(false)
		case 1:
			a.AssetParams[basics.AssetIndex(i)] = ledgertesting.RandomAssetParams()
		case 2:
			a.AppLocalStates[basics.AppIndex(i)] = ledgertesting.RandomAppLocalState()
		case 3:
			a.AppParams[basics.AppIndex(i)] = ledgertesting.RandomAppParams()
		}
	}
	return a
}

func setupTestForLargeResources(t *testing.T, acctSize, maxResults int) (handlers v2.Handlers, ctx echo.Context, rec *httptest.ResponseRecorder, fakeAddr basics.Address) {
	ml := mockLedger{
		accounts: make(map[basics.Address]basics.AccountData),
		latest:   basics.Round(10),
	}
	fakeAddr = ledgertesting.RandomAddress()

	ml.accounts[fakeAddr] = randomAccountWithResources(acctSize)

	mockNode := makeMockNode(&ml, t.Name(), nil)
	mockNode.config.MaxAccountsAPIResults = uint64(maxResults)
	dummyShutdownChan := make(chan struct{})
	handlers = v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)

	return
}

func accountInformationResourceLimitsTest(t *testing.T, acctSize, maxResults int, excludeAll bool, expectedCode int) {
	handlers, ctx, rec, addr := setupTestForLargeResources(t, acctSize, maxResults)
	params := generatedV2.AccountInformationParams{}
	if excludeAll {
		exclude := "all"
		params.Exclude = &exclude
	}
	err := handlers.AccountInformation(ctx, addr.String(), params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)

	var ret map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &ret)
	require.NoError(t, err)

	// totals should be present in both 200 and 400
	require.Equal(t, float64(acctSize), ret["total-apps-local-state"].(float64)+ret["total-assets"].(float64)+ret["total-created-apps"].(float64)+ret["total-created-assets"].(float64))

	// check totals
	switch rec.Code {
	case 400:
		require.Equal(t, float64(maxResults), ret["max-results"])
	case 200:
		if excludeAll {
			require.Nil(t, ret["apps-local-state"])
			require.Nil(t, ret["assets"])
			require.Nil(t, ret["created-apps"])
			require.Nil(t, ret["created-assets"])
		} else {
			require.Equal(t, acctSize, len(ret["apps-local-state"].([]interface{}))+
				len(ret["assets"].([]interface{}))+
				len(ret["created-apps"].([]interface{}))+
				len(ret["created-assets"].([]interface{})))
		}
	}
}

func TestAccountInformationResourceLimits(t *testing.T) {
	partitiontest.PartitionTest(t)

	accountInformationResourceLimitsTest(t, 99, 100, false, 200)  // under limit
	accountInformationResourceLimitsTest(t, 101, 100, false, 400) // over limit
	accountInformationResourceLimitsTest(t, 100, 100, false, 200) // at limit
	accountInformationResourceLimitsTest(t, 101, 100, true, 200)  // over limit with exclude=all
}
