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
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLedger struct {
	accounts map[basics.Address]basics.AccountData
	latest   basics.Round
	blocks   []bookkeeping.Block
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

func (l *mockLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ar ledgercore.AssetResource, err error) {
	ad, ok := l.accounts[addr]
	if !ok {
		return ledgercore.AssetResource{}, nil
	}
	if ap, ok := ad.AssetParams[basics.AssetIndex(aidx)]; ok {
		ar.AssetParams = &ap
	}
	if ah, ok := ad.Assets[basics.AssetIndex(aidx)]; ok {
		ar.AssetHolding = &ah
	}
	return ar, nil
}
func (l *mockLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ar ledgercore.AppResource, err error) {
	ad, ok := l.accounts[addr]
	if !ok {
		return ledgercore.AppResource{}, nil
	}
	if ap, ok := ad.AppParams[basics.AppIndex(aidx)]; ok {
		ar.AppParams = &ap
	}
	if ls, ok := ad.AppLocalStates[basics.AppIndex(aidx)]; ok {
		ar.AppLocalState = &ls
	}
	return ar, nil
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

func (l *mockLedger) AddressTxns(id basics.Address, r basics.Round) ([]transactions.SignedTxnWithAD, error) {
	blk := l.blocks[r]

	spec := transactions.SpecialAddresses{
		FeeSink:     blk.FeeSink,
		RewardsPool: blk.RewardsPool,
	}

	var res []transactions.SignedTxnWithAD

	for _, tx := range blk.Payset {
		if tx.Txn.MatchAddress(id, spec) {
			signedTxn := transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: tx.Txn}}
			res = append(res, signedTxn)
		}
	}
	return res, nil
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

func randomAccountWithAssets(N int) basics.AccountData {
	a := ledgertesting.RandomAccountData(0)
	a.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
	for i := 0; i < N; i++ {
		a.Assets[basics.AssetIndex(i*4)] = ledgertesting.RandomAssetHolding(false)
	}
	return a
}

func randomAccountWithAssetParams(N int) basics.AccountData {
	a := ledgertesting.RandomAccountData(0)
	a.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
	for i := 0; i < N; i++ {
		a.AssetParams[basics.AssetIndex(i*4+1)] = ledgertesting.RandomAssetParams()
	}
	return a
}

func randomAccountWithAppLocalState(N int) basics.AccountData {
	a := ledgertesting.RandomAccountData(0)
	a.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
	for i := 0; i < N; i++ {
		a.AppLocalStates[basics.AppIndex(i*4+2)] = ledgertesting.RandomAppLocalState()
	}
	return a
}

func randomAccountWithAppParams(N int) basics.AccountData {
	a := ledgertesting.RandomAccountData(0)
	a.AppParams = make(map[basics.AppIndex]basics.AppParams)
	for i := 0; i < N; i++ {
		a.AppParams[basics.AppIndex(i*4+3)] = ledgertesting.RandomAppParams()
	}
	return a
}

func setupTestForLargeResources(t *testing.T, acctSize, maxResults int, accountMaker func(int) basics.AccountData) (handlers v2.Handlers, fakeAddr basics.Address, acctData basics.AccountData) {
	ml := mockLedger{
		accounts: make(map[basics.Address]basics.AccountData),
		latest:   basics.Round(10),
	}
	fakeAddr = ledgertesting.RandomAddress()

	acctData = accountMaker(acctSize)
	ml.accounts[fakeAddr] = acctData

	mockNode := makeMockNode(&ml, t.Name(), nil)
	mockNode.config.MaxAPIResourcesPerAccount = uint64(maxResults)
	dummyShutdownChan := make(chan struct{})
	handlers = v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	return
}

func newReq(t *testing.T) (ctx echo.Context, rec *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	return
}

func accountInformationResourceLimitsTest(t *testing.T, accountMaker func(int) basics.AccountData, acctSize, maxResults int, exclude string, expectedCode int) {
	handlers, addr, acctData := setupTestForLargeResources(t, acctSize, maxResults, accountMaker)
	params := generatedV2.AccountInformationParams{}
	if exclude != "" {
		params.Exclude = &exclude
	}
	ctx, rec := newReq(t)
	err := handlers.AccountInformation(ctx, addr.String(), params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)

	var ret struct {
		TotalApps          int           `json:"total-apps-opted-in"`
		TotalAssets        int           `json:"total-assets-opted-in"`
		TotalCreatedApps   int           `json:"total-created-apps"`
		TotalCreatedAssets int           `json:"total-created-assets"`
		MaxResults         int           `json:"max-results"`
		Apps               []interface{} `json:"apps-local-state"`
		Assets             []interface{} `json:"assets"`
		CreatedApps        []interface{} `json:"createdApps"`
		CreatedAssets      []interface{} `json:"createdAssets"`
	}

	var errRet struct {
		Data struct {
			TotalApps          int `json:"total-apps-opted-in"`
			TotalAssets        int `json:"total-assets-opted-in"`
			TotalCreatedApps   int `json:"total-created-apps"`
			TotalCreatedAssets int `json:"total-created-assets"`
			MaxResults         int `json:"max-results"`
		} `json:"data,omitempty"`
	}

	// check totals
	switch rec.Code {
	case 400:
		err = json.Unmarshal(rec.Body.Bytes(), &errRet)
		require.NoError(t, err)
		require.Equal(t, maxResults, errRet.Data.MaxResults)
		// totals should be present in both 200 and 400
		require.Equal(t, acctSize, errRet.Data.TotalApps+errRet.Data.TotalAssets+errRet.Data.TotalCreatedApps+errRet.Data.TotalCreatedAssets, "totals incorrect: %+v", ret)
	case 200:
		err = json.Unmarshal(rec.Body.Bytes(), &ret)
		require.NoError(t, err)
		// totals should be present in both 200 and 400
		require.Equal(t, acctSize, ret.TotalApps+ret.TotalAssets+ret.TotalCreatedApps+ret.TotalCreatedAssets, "totals incorrect: %+v", ret)

		if exclude == "all" {
			require.Nil(t, ret.Apps)
			require.Nil(t, ret.Assets)
			require.Nil(t, ret.CreatedApps)
			require.Nil(t, ret.CreatedAssets)
		} else if exclude == "none" {
			require.Equal(t, acctSize, len(ret.Apps)+len(ret.Assets)+len(ret.CreatedApps)+len(ret.CreatedAssets))
		}
	}

	// check individual assets/apps
	for i := 0; i < ret.TotalAssets; i++ {
		ctx, rec = newReq(t)
		aidx := basics.AssetIndex(i * 4)
		err = handlers.AccountAssetInformation(ctx, addr.String(), uint64(aidx), generatedV2.AccountAssetInformationParams{})
		require.NoError(t, err)
		require.Equal(t, 200, rec.Code)
		var ret generatedV2.AccountAssetResponse
		err = json.Unmarshal(rec.Body.Bytes(), &ret)
		require.NoError(t, err)
		assert.Nil(t, ret.CreatedAsset)
		assert.Equal(t, ret.AssetHolding, &generatedV2.AssetHolding{
			Amount:   acctData.Assets[aidx].Amount,
			AssetId:  uint64(aidx),
			IsFrozen: acctData.Assets[aidx].Frozen,
		})
	}
	for i := 0; i < ret.TotalCreatedAssets; i++ {
		ctx, rec = newReq(t)
		aidx := basics.AssetIndex(i*4 + 1)
		err = handlers.AccountAssetInformation(ctx, addr.String(), uint64(aidx), generatedV2.AccountAssetInformationParams{})
		require.NoError(t, err)
		require.Equal(t, 200, rec.Code)
		var ret generatedV2.AccountAssetResponse
		err = json.Unmarshal(rec.Body.Bytes(), &ret)
		require.NoError(t, err)
		assert.Nil(t, ret.AssetHolding)
		ap := acctData.AssetParams[aidx]
		assetParams := v2.AssetParamsToAsset(addr.String(), aidx, &ap)
		assert.Equal(t, ret.CreatedAsset, &assetParams.Params)
	}
	for i := 0; i < ret.TotalApps; i++ {
		ctx, rec = newReq(t)
		aidx := basics.AppIndex(i*4 + 2)
		err = handlers.AccountApplicationInformation(ctx, addr.String(), uint64(aidx), generatedV2.AccountApplicationInformationParams{})
		require.NoError(t, err)
		require.Equal(t, 200, rec.Code)
		var ret generatedV2.AccountApplicationResponse
		err = json.Unmarshal(rec.Body.Bytes(), &ret)
		require.NoError(t, err)
		assert.Nil(t, ret.CreatedApp)
		require.NotNil(t, ret.AppLocalState)
		assert.Equal(t, uint64(aidx), ret.AppLocalState.Id)
		ls := acctData.AppLocalStates[aidx]
		assert.Equal(t, ls.Schema.NumByteSlice, ret.AppLocalState.Schema.NumByteSlice)
		assert.Equal(t, ls.Schema.NumUint, ret.AppLocalState.Schema.NumUint)
	}
	for i := 0; i < ret.TotalCreatedApps; i++ {
		ctx, rec = newReq(t)
		aidx := basics.AppIndex(i*4 + 3)
		err = handlers.AccountApplicationInformation(ctx, addr.String(), uint64(aidx), generatedV2.AccountApplicationInformationParams{})
		require.NoError(t, err)
		require.Equal(t, 200, rec.Code)
		var ret generatedV2.AccountApplicationResponse
		err = json.Unmarshal(rec.Body.Bytes(), &ret)
		require.NoError(t, err)
		assert.Nil(t, ret.AppLocalState)
		ap := acctData.AppParams[aidx]
		expAp := v2.AppParamsToApplication(addr.String(), aidx, &ap)
		assert.EqualValues(t, expAp.Params.ApprovalProgram, ret.CreatedApp.ApprovalProgram)
		assert.EqualValues(t, expAp.Params.ClearStateProgram, ret.CreatedApp.ClearStateProgram)
		assert.EqualValues(t, expAp.Params.Creator, ret.CreatedApp.Creator)
	}
}

func TestAccountInformationResourceLimits(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, tc := range []struct {
		name         string
		accountMaker func(int) basics.AccountData
	}{
		{name: "all", accountMaker: randomAccountWithResources},
		{name: "assets", accountMaker: randomAccountWithAssets},
		{name: "applocal", accountMaker: randomAccountWithAppLocalState},
		{name: "assetparams", accountMaker: randomAccountWithAssetParams},
		{name: "appparams", accountMaker: randomAccountWithAppParams},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accountInformationResourceLimitsTest(t, tc.accountMaker, 99, 100, "", 200)      // under limit
			accountInformationResourceLimitsTest(t, tc.accountMaker, 101, 100, "", 400)     // over limit
			accountInformationResourceLimitsTest(t, tc.accountMaker, 100, 100, "", 200)     // at limit
			accountInformationResourceLimitsTest(t, tc.accountMaker, 101, 100, "all", 200)  // over limit with exclude=all
			accountInformationResourceLimitsTest(t, tc.accountMaker, 101, 100, "none", 400) // over limit with exclude=none
		})
	}
}
