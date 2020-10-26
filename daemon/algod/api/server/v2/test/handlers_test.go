// Copyright (C) 2019-2020 Algorand, Inc.
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
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

func setupTestForMethodGet(t *testing.T) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, []account.Root, []transactions.SignedTxn, func()) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, rootkeys, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	mockNode := makeMockNode(mockLedger, t.Name(), nil)
	dummyShutdownChan := make(chan struct{})
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	return handler, c, rec, rootkeys, stxns, releasefunc
}

func TestSimpleMockBuilding(t *testing.T) {
	t.Parallel()

	handler, _, _, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	require.Equal(t, t.Name(), handler.Node.GenesisID())
}

func accountInformationTest(t *testing.T, address string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.AccountInformation(c, address, generatedV2.AccountInformationParams{})
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
	if address == poolAddr.String() {
		expectedResponse := poolAddrResponseGolden
		actualResponse := generatedV2.AccountResponse{}
		err = protocol.DecodeJSON(rec.Body.Bytes(), &actualResponse)
		require.NoError(t, err)
		require.Equal(t, expectedResponse, actualResponse)
	}
}

func TestAccountInformation(t *testing.T) {
	t.Parallel()

	accountInformationTest(t, poolAddr.String(), 200)
	accountInformationTest(t, "bad account", 400)
}

func getBlockTest(t *testing.T, blockNum uint64, format string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.GetBlock(c, blockNum, generatedV2.GetBlockParams{Format: &format})
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestGetBlock(t *testing.T) {
	t.Parallel()

	getBlockTest(t, 0, "json", 200)
	getBlockTest(t, 0, "msgpack", 200)
	getBlockTest(t, 1, "json", 500)
	getBlockTest(t, 0, "bad format", 400)
}

func TestGetSupply(t *testing.T) {
	t.Parallel()

	handler, c, _, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.GetSupply(c)
	require.NoError(t, err)
}

func TestGetStatus(t *testing.T) {
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.GetStatus(c)
	require.NoError(t, err)
	stat := cannedStatusReportGolden
	expectedResult := generatedV2.NodeStatusResponse{
		LastRound:                   uint64(stat.LastRound),
		LastVersion:                 string(stat.LastVersion),
		NextVersion:                 string(stat.NextVersion),
		NextVersionRound:            uint64(stat.NextVersionRound),
		NextVersionSupported:        stat.NextVersionSupported,
		TimeSinceLastRound:          uint64(stat.TimeSinceLastRound().Nanoseconds()),
		CatchupTime:                 uint64(stat.CatchupTime.Nanoseconds()),
		StoppedAtUnsupportedRound:   stat.StoppedAtUnsupportedRound,
		LastCatchpoint:              &stat.LastCatchpoint,
		Catchpoint:                  &stat.Catchpoint,
		CatchpointTotalAccounts:     &stat.CatchpointCatchupTotalAccounts,
		CatchpointProcessedAccounts: &stat.CatchpointCatchupProcessedAccounts,
		CatchpointTotalBlocks:       &stat.CatchpointCatchupTotalBlocks,
		CatchpointAcquiredBlocks:    &stat.CatchpointCatchupAcquiredBlocks,
	}
	actualResult := generatedV2.NodeStatusResponse{}
	err = protocol.DecodeJSON(rec.Body.Bytes(), &actualResult)
	require.NoError(t, err)
	require.Equal(t, expectedResult, actualResult)
}

func TestGetStatusAfterBlock(t *testing.T) {
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.WaitForBlock(c, 0)
	require.NoError(t, err)
	// Expect 400 - the test ledger will always cause "errRequestedRoundInUnsupportedRound",
	// as it has not participated in agreement to build blockheaders
	require.Equal(t, 400, rec.Code)
}

func TestGetTransactionParams(t *testing.T) {
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.TransactionParams(c)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
}

func pendingTransactionInformationTest(t *testing.T, txidToUse int, format string, expectedCode int) {
	handler, c, rec, _, stxns, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	txid := "bad txid"
	if txidToUse >= 0 {
		txid = stxns[txidToUse].ID().String()
	}
	params := generatedV2.PendingTransactionInformationParams{Format: &format}
	err := handler.PendingTransactionInformation(c, txid, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactionInformation(t *testing.T) {
	t.Parallel()

	pendingTransactionInformationTest(t, 0, "json", 200)
	pendingTransactionInformationTest(t, 0, "msgpack", 200)
	pendingTransactionInformationTest(t, -1, "json", 400)
	pendingTransactionInformationTest(t, 0, "bad format", 400)
}

func getPendingTransactionsTest(t *testing.T, format string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	params := generatedV2.GetPendingTransactionsParams{Format: &format}
	err := handler.GetPendingTransactions(c, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactions(t *testing.T) {
	t.Parallel()

	getPendingTransactionsTest(t, "json", 200)
	getPendingTransactionsTest(t, "msgpack", 200)
	getPendingTransactionsTest(t, "bad format", 400)
}

func pendingTransactionsByAddressTest(t *testing.T, rootkeyToUse int, format string, expectedCode int) {
	handler, c, rec, rootkeys, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	address := "bad address"
	if rootkeyToUse >= 0 {
		address = rootkeys[rootkeyToUse].Address().String()
	}
	params := generatedV2.GetPendingTransactionsByAddressParams{Format: &format}
	err := handler.GetPendingTransactionsByAddress(c, address, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactionsByAddress(t *testing.T) {
	t.Parallel()

	pendingTransactionsByAddressTest(t, 0, "json", 200)
	pendingTransactionsByAddressTest(t, 0, "msgpack", 200)
	pendingTransactionsByAddressTest(t, 0, "bad format", 400)
	pendingTransactionsByAddressTest(t, -1, "json", 400)
}

func postTransactionTest(t *testing.T, txnToUse, expectedCode int) {
	numAccounts := 5
	numTransactions := 5
	offlineAccounts := true
	mockLedger, _, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil)
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	var body io.Reader
	if txnToUse >= 0 {
		stxn := stxns[txnToUse]
		bodyBytes := protocol.Encode(&stxn)
		body = bytes.NewReader(bodyBytes)
	}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.RawTransaction(c)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPostTransaction(t *testing.T) {
	t.Parallel()

	postTransactionTest(t, -1, 400)
	postTransactionTest(t, 0, 200)
}

func startCatchupTest(t *testing.T, catchpoint string, nodeError error, expectedCode int) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nodeError)
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.StartCatchup(c, catchpoint)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestStartCatchup(t *testing.T) {
	t.Parallel()

	goodCatchPoint := "5894690#DVFRZUYHEFKRLK5N6DNJRR4IABEVN2D6H76F3ZSEPIE6MKXMQWQA"
	startCatchupTest(t, goodCatchPoint, nil, 201)

	inProgressError := node.MakeCatchpointAlreadyInProgressError("catchpoint")
	startCatchupTest(t, goodCatchPoint, inProgressError, 200)

	unableToStartError := node.MakeCatchpointUnableToStartError("running", "requested")
	startCatchupTest(t, goodCatchPoint, unableToStartError, 400)

	startCatchupTest(t, goodCatchPoint, errors.New("anothing else is internal"), 500)

	badCatchPoint := "bad catchpoint"
	startCatchupTest(t, badCatchPoint, nil, 400)
}

func abortCatchupTest(t *testing.T, catchpoint string, expectedCode int) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil)
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.AbortCatchup(c, catchpoint)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestAbortCatchup(t *testing.T) {
	t.Parallel()

	goodCatchPoint := "5894690#DVFRZUYHEFKRLK5N6DNJRR4IABEVN2D6H76F3ZSEPIE6MKXMQWQA"
	abortCatchupTest(t, goodCatchPoint, 200)
	badCatchPoint := "bad catchpoint"
	abortCatchupTest(t, badCatchPoint, 400)
}

func tealCompileTest(t *testing.T, bytesToUse []byte, expectedCode int, enableDeveloperAPI bool) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil)
	mockNode.config.EnableDeveloperAPI = enableDeveloperAPI
	handler := v2.Handlers{
		Node:     &mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytesToUse))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.TealCompile(c)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestTealCompile(t *testing.T) {
	t.Parallel()

	tealCompileTest(t, nil, 200, true) // nil program should work
	goodProgram := `int 1`
	goodProgramBytes := []byte(goodProgram)
	tealCompileTest(t, goodProgramBytes, 200, true)
	tealCompileTest(t, goodProgramBytes, 404, false)
	badProgram := "bad program"
	badProgramBytes := []byte(badProgram)
	tealCompileTest(t, badProgramBytes, 400, true)
}

func tealDryrunTest(
	t *testing.T, obj *generatedV2.DryrunRequest, format string,
	expCode int, expResult string, enableDeveloperAPI bool,
) (response generatedV2.DryrunResponse) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil)
	mockNode.config.EnableDeveloperAPI = enableDeveloperAPI
	handler := v2.Handlers{
		Node:     &mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}

	var data []byte
	if format == "json" {
		data = protocol.EncodeJSON(obj)
	} else {
		obj2, err := v2.DryrunRequestFromGenerated(obj)
		require.NoError(t, err)
		data = protocol.EncodeReflect(&obj2)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.TealDryrun(c)
	require.NoError(t, err)
	require.Equal(t, expCode, rec.Code)
	if rec.Code == 200 {
		data = rec.Body.Bytes()
		err = protocol.DecodeJSON(data, &response)
		require.NoError(t, err, string(data))

		require.GreaterOrEqual(t, len(response.Txns), 1)
		require.NotNil(t, response.Txns[0].AppCallMessages)
		messages := *response.Txns[0].AppCallMessages
		require.GreaterOrEqual(t, len(messages), 1)
		require.Equal(t, expResult, messages[len(messages)-1])
	}
	return
}

func TestTealDryrun(t *testing.T) {
	t.Parallel()

	var gdr generated.DryrunRequest
	txns := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:   1,
					ApprovalProgram: []byte{1, 2, 3},
					ApplicationArgs: [][]byte{
						[]byte("check"),
						[]byte("bar"),
					},
				},
			},
		},
	}
	for i := range txns {
		enc := protocol.EncodeJSON(&txns[i])
		gdr.Txns = append(gdr.Txns, enc)
	}

	sucProgram, err := logic.AssembleStringV2("int 1")
	require.NoError(t, err)

	failProgram, err := logic.AssembleStringV2("int 0")
	require.NoError(t, err)

	gdr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: sucProgram,
			},
		},
	}
	localv := make(generated.TealKeyValueStore, 1)
	localv[0] = generated.TealKeyValue{
		Key:   "foo",
		Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: "bar"},
	}

	gdr.Accounts = []generated.Account{
		{
			Address: basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalState{{
				Id:       1,
				KeyValue: &localv,
			}},
		},
	}

	gdr.ProtocolVersion = string(protocol.ConsensusFuture)
	tealDryrunTest(t, &gdr, "json", 200, "PASS", true)
	tealDryrunTest(t, &gdr, "msgp", 200, "PASS", true)
	tealDryrunTest(t, &gdr, "msgp", 404, "", false)

	gdr.ProtocolVersion = "unk"
	tealDryrunTest(t, &gdr, "json", 400, "", true)
	gdr.ProtocolVersion = ""

	// TODO(after applications) uncomment these two lines. The current
	// protocol version does not support TEAL v2, which is required for
	// application support.
	// ddr := tealDryrunTest(t, &gdr, "json", 200, "PASS", true)
	// require.Equal(t, string(protocol.ConsensusCurrentVersion), ddr.ProtocolVersion)
	gdr.ProtocolVersion = string(protocol.ConsensusFuture)
	ddr := tealDryrunTest(t, &gdr, "json", 200, "PASS", true)
	require.Equal(t, string(protocol.ConsensusFuture), ddr.ProtocolVersion)

	gdr.Apps[0].Params.ApprovalProgram = failProgram
	tealDryrunTest(t, &gdr, "json", 200, "REJECT", true)
	tealDryrunTest(t, &gdr, "msgp", 200, "REJECT", true)
	tealDryrunTest(t, &gdr, "json", 404, "", false)
}
