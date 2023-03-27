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

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

const stateProofIntervalForHandlerTests = uint64(256)

func setupTestForMethodGet(t *testing.T, consensusUpgrade bool) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, []account.Root, []transactions.SignedTxn, func()) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, rootkeys, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	mockNode := makeMockNode(mockLedger, t.Name(), nil, consensusUpgrade)
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

func numOrNil(n uint64) *uint64 {
	if n == 0 {
		return nil
	}
	return &n
}

func TestSimpleMockBuilding(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, _, _, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	require.Equal(t, t.Name(), handler.Node.GenesisID())
}

func accountInformationTest(t *testing.T, address string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	err := handler.AccountInformation(c, address, model.AccountInformationParams{})
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
	if address == poolAddr.String() {
		expectedResponse := poolAddrResponseGolden
		actualResponse := model.AccountResponse{}
		err = protocol.DecodeJSON(rec.Body.Bytes(), &actualResponse)
		require.NoError(t, err)
		require.Equal(t, expectedResponse, actualResponse)
	}
}

func TestAccountInformation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	accountInformationTest(t, poolAddr.String(), 200)
	accountInformationTest(t, "bad account", 400)
}

func getBlockTest(t *testing.T, blockNum uint64, format string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	err := handler.GetBlock(c, blockNum, model.GetBlockParams{Format: (*model.GetBlockParamsFormat)(&format)})
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestGetBlock(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	getBlockTest(t, 0, "json", 200)
	getBlockTest(t, 0, "msgpack", 200)
	getBlockTest(t, 1, "json", 404)
	getBlockTest(t, 1, "msgpack", 404)
	getBlockTest(t, 0, "bad format", 400)
}

func testGetLedgerStateDelta(t *testing.T, round uint64, format string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	insertRounds(require.New(t), handler, 3)
	err := handler.GetLedgerStateDelta(c, round, model.GetLedgerStateDeltaParams{Format: (*model.GetLedgerStateDeltaParamsFormat)(&format)})
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestGetLedgerStateDelta(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Run("json-200", func(t *testing.T) {
		t.Parallel()
		testGetLedgerStateDelta(t, 1, "json", 200)
	})
	t.Run("msgpack-200", func(t *testing.T) {
		t.Parallel()
		testGetLedgerStateDelta(t, 2, "msgpack", 200)
	})
	t.Run("msgp-200", func(t *testing.T) {
		t.Parallel()
		testGetLedgerStateDelta(t, 3, "msgp", 200)
	})
	t.Run("json-404", func(t *testing.T) {
		t.Parallel()
		testGetLedgerStateDelta(t, 0, "json", 404)
	})
	t.Run("msgpack-404", func(t *testing.T) {
		t.Parallel()
		testGetLedgerStateDelta(t, 9999, "msgpack", 404)
	})
	t.Run("format-400", func(t *testing.T) {
		t.Parallel()
		testGetLedgerStateDelta(t, 1, "bad format", 400)
	})

}

func TestSyncRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
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

	defer releasefunc()

	// TestSetSyncRound 200
	mockCall := mockNode.On("SetSyncRound", mock.Anything).Return(nil)
	err := handler.SetSyncRound(c, 0)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	mockCall.Unset()
	c, rec = newReq(t)
	// TestSetSyncRound 400 SyncRoundInvalid
	mockCall = mockNode.On("SetSyncRound", mock.Anything).Return(catchup.ErrSyncRoundInvalid)
	err = handler.SetSyncRound(c, 0)
	require.NoError(t, err)
	require.Equal(t, 400, rec.Code)
	mockCall.Unset()
	c, rec = newReq(t)
	// TestSetSyncRound 500 InternalError
	mockCall = mockNode.On("SetSyncRound", mock.Anything).Return(fmt.Errorf("unknown error"))
	err = handler.SetSyncRound(c, 0)
	require.NoError(t, err)
	require.Equal(t, 500, rec.Code)
	c, rec = newReq(t)

	// TestGetSyncRound 200
	mockCall = mockNode.On("GetSyncRound").Return(2)
	err = handler.GetSyncRound(c)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	mockCall.Unset()
	c, rec = newReq(t)
	// TestGetSyncRound 404 NotFound
	mockCall = mockNode.On("GetSyncRound").Return(0)
	err = handler.GetSyncRound(c)
	require.NoError(t, err)
	require.Equal(t, 404, rec.Code)
	c, rec = newReq(t)

	// TestUnsetSyncRound 200
	mockCall = mockNode.On("UnsetSyncRound").Return()
	err = handler.UnsetSyncRound(c)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	mockCall.Unset()
	c, rec = newReq(t)

	mock.AssertExpectationsForObjects(t, mockNode)
}

func addBlockHelper(t *testing.T) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, transactions.SignedTxn, func()) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)

	l := handler.Node.LedgerForAPI()

	genBlk, err := l.Block(0)
	require.NoError(t, err)

	// make an app call txn with eval delta
	lsig := transactions.LogicSig{Logic: retOneProgram} // int 1
	program := logic.Program(lsig.Logic)
	lhash := crypto.HashObj(&program)
	var sender basics.Address
	copy(sender[:], lhash[:])
	stx := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         basics.MicroAlgos{Raw: 1000},
				GenesisID:   genBlk.GenesisID(),
				GenesisHash: genBlk.GenesisHash(),
				FirstValid:  1,
				LastValid:   10,
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: 1,
				OnCompletion:  transactions.ClearStateOC,
			},
		},
		Lsig: lsig,
	}
	ad := transactions.ApplyData{
		EvalDelta: transactions.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{
				1: {"key": basics.ValueDelta{Action: 1}},
			},
		},
	}

	// put it into a block
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	totalsRound, totals, err := l.LatestTotals()
	require.NoError(t, err)
	require.Equal(t, l.Latest(), totalsRound)
	totalRewardUnits := totals.RewardUnits()
	poolBal, _, _, err := l.LookupLatest(poolAddr)
	require.NoError(t, err)

	var blk bookkeeping.Block
	blk.BlockHeader = bookkeeping.BlockHeader{
		GenesisID:    genBlk.GenesisID(),
		GenesisHash:  genBlk.GenesisHash(),
		Round:        l.Latest() + 1,
		Branch:       genBlk.Hash(),
		TimeStamp:    0,
		RewardsState: genBlk.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits, logging.Base()),
		UpgradeState: genBlk.UpgradeState,
	}

	blk.BlockHeader.TxnCounter = genBlk.TxnCounter

	blk.RewardsPool = genBlk.RewardsPool
	blk.FeeSink = genBlk.FeeSink
	blk.CurrentProtocol = genBlk.CurrentProtocol
	blk.TimeStamp = genBlk.TimeStamp + 1

	txib, err := blk.EncodeSignedTxn(stx, ad)
	blk.Payset = append(blk.Payset, txib)
	blk.BlockHeader.TxnCounter++
	blk.TxnCommitments, err = blk.PaysetCommit()
	require.NoError(t, err)

	err = l.(*data.Ledger).AddBlock(blk, agreement.Certificate{})
	require.NoError(t, err)

	return handler, c, rec, stx, releasefunc
}

func TestGetBlockHash(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	err := handler.GetBlockHash(c, 0)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)

	c, rec = newReq(t)
	err = handler.GetBlockHash(c, 1)
	require.NoError(t, err)
	require.Equal(t, 404, rec.Code)
}

func TestGetBlockGetBlockHash(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	insertRounds(a, handler, 2)

	type blockResponse struct {
		Block bookkeeping.Block `codec:"block"`
	}

	var block1, block2 blockResponse
	var block1Hash model.BlockHashResponse
	format := "json"

	// Get block 1
	err := handler.GetBlock(c, 1, model.GetBlockParams{Format: (*model.GetBlockParamsFormat)(&format)})
	a.NoError(err)
	a.Equal(200, rec.Code)
	err = protocol.DecodeJSON(rec.Body.Bytes(), &block1)
	a.NoError(err)

	// Get block 2
	c, rec = newReq(t)
	err = handler.GetBlock(c, 2, model.GetBlockParams{Format: (*model.GetBlockParamsFormat)(&format)})
	a.NoError(err)
	a.Equal(200, rec.Code)
	err = protocol.DecodeJSON(rec.Body.Bytes(), &block2)
	a.NoError(err)

	// Get block 1 hash
	c, rec = newReq(t)
	err = handler.GetBlockHash(c, 1)
	a.NoError(err)
	a.Equal(200, rec.Code)
	err = protocol.DecodeJSON(rec.Body.Bytes(), &block1Hash)
	a.NoError(err)

	// Validate that the block returned from GetBlock(1) has the same hash that is returned via GetBlockHash(1)
	a.Equal(crypto.HashObj(block1.Block.BlockHeader).String(), block1Hash.BlockHash)

	// Validate that the block returned from GetBlock(2) has the same prev-hash that is returned via GetBlockHash(1)
	hash := block2.Block.Branch.String()
	a.Equal(fmt.Sprintf("blk-%s", block1Hash.BlockHash), hash)

	// Sanity check that the hashes are not equal (i.e. they are not the default values)
	a.NotEqual(block1.Block.Branch, block2.Block.Branch)
}

func TestGetBlockJsonEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, releasefunc := addBlockHelper(t)
	defer releasefunc()

	// fetch the block and ensure it can be properly decoded with the standard JSON decoder
	format := "json"
	err := handler.GetBlock(c, 1, model.GetBlockParams{Format: (*model.GetBlockParamsFormat)(&format)})
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	body := rec.Body.Bytes()

	response := struct {
		Block bookkeeping.Block `codec:"block"`
	}{}

	err = json.Unmarshal(body, &response)
	require.NoError(t, err)
}

func TestGetSupply(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, _, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	err := handler.GetSupply(c)
	require.NoError(t, err)
}

func TestGetStatus(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	err := handler.GetStatus(c)
	require.NoError(t, err)
	stat := cannedStatusReportGolden
	expectedResult := model.NodeStatusResponse{
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
		CatchpointVerifiedAccounts:  &stat.CatchpointCatchupVerifiedAccounts,
		CatchpointTotalBlocks:       &stat.CatchpointCatchupTotalBlocks,
		CatchpointAcquiredBlocks:    &stat.CatchpointCatchupAcquiredBlocks,
		CatchpointTotalKvs:          &stat.CatchpointCatchupTotalKVs,
		CatchpointProcessedKvs:      &stat.CatchpointCatchupProcessedKVs,
		CatchpointVerifiedKvs:       &stat.CatchpointCatchupVerifiedKVs,
	}
	actualResult := model.NodeStatusResponse{}
	err = protocol.DecodeJSON(rec.Body.Bytes(), &actualResult)
	require.NoError(t, err)
	require.Equal(t, expectedResult, actualResult)
}

func TestGetStatusConsensusUpgrade(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, true)
	defer releasefunc()
	err := handler.GetStatus(c)
	require.NoError(t, err)
	stat := cannedStatusReportConsensusUpgradeGolden
	consensus := config.Consensus[protocol.ConsensusCurrentVersion]
	votesToGo := uint64(stat.NextProtocolVoteBefore) - uint64(stat.LastRound)
	nextProtocolVoteBefore := uint64(stat.NextProtocolVoteBefore)
	votes := uint64(consensus.UpgradeVoteRounds) - votesToGo
	votesNo := votes - stat.NextProtocolApprovals

	expectedResult := model.NodeStatusResponse{
		LastRound:                     uint64(stat.LastRound),
		LastVersion:                   string(stat.LastVersion),
		NextVersion:                   string(stat.NextVersion),
		NextVersionRound:              uint64(stat.NextVersionRound),
		NextVersionSupported:          stat.NextVersionSupported,
		TimeSinceLastRound:            uint64(stat.TimeSinceLastRound().Nanoseconds()),
		CatchupTime:                   uint64(stat.CatchupTime.Nanoseconds()),
		StoppedAtUnsupportedRound:     stat.StoppedAtUnsupportedRound,
		LastCatchpoint:                &stat.LastCatchpoint,
		Catchpoint:                    &stat.Catchpoint,
		CatchpointTotalAccounts:       &stat.CatchpointCatchupTotalAccounts,
		CatchpointProcessedAccounts:   &stat.CatchpointCatchupProcessedAccounts,
		CatchpointVerifiedAccounts:    &stat.CatchpointCatchupVerifiedAccounts,
		CatchpointTotalBlocks:         &stat.CatchpointCatchupTotalBlocks,
		CatchpointAcquiredBlocks:      &stat.CatchpointCatchupAcquiredBlocks,
		CatchpointTotalKvs:            &stat.CatchpointCatchupTotalKVs,
		CatchpointProcessedKvs:        &stat.CatchpointCatchupProcessedKVs,
		CatchpointVerifiedKvs:         &stat.CatchpointCatchupVerifiedKVs,
		UpgradeVotesRequired:          &consensus.UpgradeThreshold,
		UpgradeNodeVote:               &stat.UpgradeApprove,
		UpgradeDelay:                  &stat.UpgradeDelay,
		UpgradeNoVotes:                &votesNo,
		UpgradeYesVotes:               &stat.NextProtocolApprovals,
		UpgradeVoteRounds:             &consensus.UpgradeVoteRounds,
		UpgradeNextProtocolVoteBefore: &nextProtocolVoteBefore,
		UpgradeVotes:                  &votes,
	}
	actualResult := model.NodeStatusResponse{}
	err = protocol.DecodeJSON(rec.Body.Bytes(), &actualResult)
	require.NoError(t, err)
	require.Equal(t, expectedResult, actualResult)
}

func TestGetStatusAfterBlock(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	err := handler.WaitForBlock(c, 0)
	require.NoError(t, err)
	// Expect 400 - the test ledger will always cause "errRequestedRoundInUnsupportedRound",
	// as it has not participated in agreement to build blockheaders
	require.Equal(t, 400, rec.Code)
}

func TestGetTransactionParams(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	err := handler.TransactionParams(c)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
}

func pendingTransactionInformationTest(t *testing.T, txidToUse int, format string, expectedCode int) {
	handler, c, rec, _, stxns, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	txid := "bad txid"
	if txidToUse >= 0 {
		txid = stxns[txidToUse].ID().String()
	}
	params := model.PendingTransactionInformationParams{Format: (*model.PendingTransactionInformationParamsFormat)(&format)}
	err := handler.PendingTransactionInformation(c, txid, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactionInformation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	pendingTransactionInformationTest(t, 0, "json", 200)
	pendingTransactionInformationTest(t, 0, "msgpack", 200)
	pendingTransactionInformationTest(t, -1, "json", 400)
	pendingTransactionInformationTest(t, 0, "bad format", 400)
}

func getPendingTransactionsTest(t *testing.T, format string, max uint64, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	params := model.GetPendingTransactionsParams{Format: (*model.GetPendingTransactionsParamsFormat)(&format), Max: &max}
	err := handler.GetPendingTransactions(c, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
	if format == "json" && rec.Code == 200 {
		var response model.PendingTransactionsResponse

		data := rec.Body.Bytes()
		err = protocol.DecodeJSON(data, &response)
		require.NoError(t, err, string(data))

		if max == 0 || max >= uint64(len(txnPoolGolden)) {
			// all pending txns should be returned
			require.Equal(t, uint64(len(response.TopTransactions)), uint64(len(txnPoolGolden)))
		} else {
			// only max txns should be returned
			require.Equal(t, uint64(len(response.TopTransactions)), max)
		}

		require.Equal(t, response.TotalTransactions, uint64(len(txnPoolGolden)))
		require.GreaterOrEqual(t, response.TotalTransactions, uint64(len(response.TopTransactions)))
	}
}

func TestPendingTransactionLogsEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	response := model.PendingTransactionResponse{
		Logs: &[][]byte{
			{},
			[]byte(string("a")),
			[]byte(string("test")),
			{0},
			{0, 1, 2},
		},
	}

	// log messages should be base64 encoded
	expected := `{
  "logs": [
    "",
    "YQ==",
    "dGVzdA==",
    "AA==",
    "AAEC"
  ],
  "pool-error": "",
  "txn": null
}`

	for _, handle := range []codec.Handle{protocol.JSONHandle, protocol.JSONStrictHandle} {
		var output []byte
		enc := codec.NewEncoderBytes(&output, handle)

		err := enc.Encode(response)
		require.NoError(t, err)

		require.Equal(t, expected, string(output))
	}
}

func TestPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	getPendingTransactionsTest(t, "json", 0, 200)
	getPendingTransactionsTest(t, "json", 1, 200)
	getPendingTransactionsTest(t, "json", 2, 200)
	getPendingTransactionsTest(t, "json", 3, 200)
	getPendingTransactionsTest(t, "msgpack", 0, 200)
	getPendingTransactionsTest(t, "msgpack", 1, 200)
	getPendingTransactionsTest(t, "msgpack", 2, 200)
	getPendingTransactionsTest(t, "msgpack", 3, 200)
	getPendingTransactionsTest(t, "bad format", 0, 400)
}

func pendingTransactionsByAddressTest(t *testing.T, rootkeyToUse int, format string, expectedCode int) {
	handler, c, rec, rootkeys, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()
	address := "bad address"
	if rootkeyToUse >= 0 {
		address = rootkeys[rootkeyToUse].Address().String()
	}
	params := model.GetPendingTransactionsByAddressParams{Format: (*model.GetPendingTransactionsByAddressParamsFormat)(&format)}
	err := handler.GetPendingTransactionsByAddress(c, address, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactionsByAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	pendingTransactionsByAddressTest(t, 0, "json", 200)
	pendingTransactionsByAddressTest(t, 0, "msgpack", 200)
	pendingTransactionsByAddressTest(t, 0, "bad format", 400)
	pendingTransactionsByAddressTest(t, -1, "json", 400)
}

func prepareTransactionTest(t *testing.T, txnToUse, expectedCode int) (handler v2.Handlers, c echo.Context, rec *httptest.ResponseRecorder, releasefunc func()) {
	numAccounts := 5
	numTransactions := 5
	offlineAccounts := true
	mockLedger, _, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
	handler = v2.Handlers{

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
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	return
}

func postTransactionTest(t *testing.T, txnToUse, expectedCode int) {
	handler, c, rec, releasefunc := prepareTransactionTest(t, txnToUse, expectedCode)
	defer releasefunc()
	err := handler.RawTransaction(c)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPostTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	postTransactionTest(t, -1, 400)
	postTransactionTest(t, 0, 200)
}

func simulateTransactionTest(t *testing.T, txnToUse int, format string, expectedCode int) {
	handler, c, rec, releasefunc := prepareTransactionTest(t, txnToUse, expectedCode)
	defer releasefunc()
	err := handler.SimulateTransaction(c, model.SimulateTransactionParams{Format: (*model.SimulateTransactionParamsFormat)(&format)})
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPostSimulateTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		txnIndex       int
		format         string
		expectedStatus int
	}{
		{
			txnIndex:       -1,
			format:         "json",
			expectedStatus: 400,
		},
		{
			txnIndex:       0,
			format:         "json",
			expectedStatus: 200,
		},
		{
			txnIndex:       0,
			format:         "msgpack",
			expectedStatus: 200,
		},
		{
			txnIndex:       0,
			format:         "bad format",
			expectedStatus: 400,
		},
	}

	for i, testCase := range testCases {
		testCase := testCase
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			t.Parallel()
			simulateTransactionTest(t, testCase.txnIndex, testCase.format, testCase.expectedStatus)
		})
	}
}

func copyInnerTxnGroupIDs(t *testing.T, dst, src *model.PendingTransactionResponse) {
	t.Helper()

	// msgpack decodes to map[interface{}]interface{} while JSON decodes to map[string]interface{}
	txn := dst.Txn["txn"]
	switch dstTxnMap := txn.(type) {
	case map[string]interface{}:
		srcTxnMap := src.Txn["txn"].(map[string]interface{})
		groupID, hasGroupID := srcTxnMap["grp"]
		if hasGroupID {
			dstTxnMap["grp"] = groupID
		}
	case map[interface{}]interface{}:
		srcTxnMap := src.Txn["txn"].(map[interface{}]interface{})
		groupID, hasGroupID := srcTxnMap["grp"]
		if hasGroupID {
			dstTxnMap["grp"] = groupID
		}
	}

	if dst.InnerTxns == nil || src.InnerTxns == nil {
		return
	}

	assert.Equal(t, len(*dst.InnerTxns), len(*src.InnerTxns))

	for innerIndex := range *dst.InnerTxns {
		if innerIndex == len(*src.InnerTxns) {
			break
		}
		dstInner := &(*dst.InnerTxns)[innerIndex]
		srcInner := &(*src.InnerTxns)[innerIndex]
		copyInnerTxnGroupIDs(t, dstInner, srcInner)
	}
}

func assertSimulationResultsEqual(t *testing.T, expectedError string, expected, actual model.SimulateResponse) {
	t.Helper()

	if len(expectedError) != 0 {
		require.NotNil(t, actual.TxnGroups[0].FailureMessage)
		require.Contains(t, *actual.TxnGroups[0].FailureMessage, expectedError)
		require.False(t, expected.WouldSucceed, "Test case WouldSucceed value is not consistent with expected failure")
		// if it matched the expected error, copy the actual one so it will pass the equality check below
		expected.TxnGroups[0].FailureMessage = actual.TxnGroups[0].FailureMessage
	}

	// Copy inner txn groups IDs, since the mocktracer scenarios don't populate them
	assert.Equal(t, len(expected.TxnGroups), len(actual.TxnGroups))
	for groupIndex := range expected.TxnGroups {
		if groupIndex == len(actual.TxnGroups) {
			break
		}
		expectedGroup := &expected.TxnGroups[groupIndex]
		actualGroup := &actual.TxnGroups[groupIndex]
		assert.Equal(t, len(expectedGroup.TxnResults), len(actualGroup.TxnResults))
		for txnIndex := range expectedGroup.TxnResults {
			if txnIndex == len(actualGroup.TxnResults) {
				break
			}
			expectedTxn := &expectedGroup.TxnResults[txnIndex]
			actualTxn := &actualGroup.TxnResults[txnIndex]
			if expectedTxn.TxnResult.InnerTxns == nil || actualTxn.TxnResult.InnerTxns == nil {
				continue
			}
			assert.Equal(t, len(*expectedTxn.TxnResult.InnerTxns), len(*actualTxn.TxnResult.InnerTxns))
			for innerIndex := range *expectedTxn.TxnResult.InnerTxns {
				if innerIndex == len(*actualTxn.TxnResult.InnerTxns) {
					break
				}
				expectedInner := &(*expectedTxn.TxnResult.InnerTxns)[innerIndex]
				actualInner := &(*actualTxn.TxnResult.InnerTxns)[innerIndex]
				copyInnerTxnGroupIDs(t, expectedInner, actualInner)
			}
		}
	}

	require.Equal(t, expected, actual)
}

func makePendingTxnResponse(t *testing.T, txn transactions.SignedTxnWithAD, handle codec.Handle) model.PendingTransactionResponse {
	t.Helper()
	preEncoded := v2.ConvertInnerTxn(&txn)

	// encode to bytes
	var encodedBytes []byte
	encoder := codec.NewEncoderBytes(&encodedBytes, handle)
	err := encoder.Encode(&preEncoded)
	require.NoError(t, err)

	// decode to model.PendingTransactionResponse
	var response model.PendingTransactionResponse
	decoder := codec.NewDecoderBytes(encodedBytes, handle)
	err = decoder.Decode(&response)
	require.NoError(t, err)

	return response
}

func TestSimulateTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// prepare node and handler
	numAccounts := 5
	offlineAccounts := true
	mockLedger, roots, _, _, releasefunc := testingenvWithBalances(t, 999_998, 999_999, numAccounts, 1, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}

	hdr, err := mockLedger.BlockHdr(mockLedger.Latest())
	require.NoError(t, err)
	txnInfo := simulationtesting.TxnInfo{LatestHeader: hdr}

	scenarios := mocktracer.GetTestScenarios()

	for name, scenarioFn := range scenarios {
		t.Run(name, func(t *testing.T) { //nolint:paralleltest // Uses shared testing env
			sender := roots[0]
			futureAppID := basics.AppIndex(2)

			payTxn := txnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   sender.Address(),
				Receiver: futureAppID.Address(),
				Amount:   700_000,
			})
			appCallTxn := txnInfo.NewTxn(txntest.Txn{
				Type:   protocol.ApplicationCallTx,
				Sender: sender.Address(),
				ClearStateProgram: `#pragma version 6
int 1`,
			})
			scenario := scenarioFn(mocktracer.TestScenarioInfo{
				CallingTxn:   appCallTxn.Txn(),
				MinFee:       basics.MicroAlgos{Raw: txnInfo.CurrentProtocolParams().MinTxnFee},
				CreatedAppID: futureAppID,
			})
			appCallTxn.ApprovalProgram = scenario.Program

			txntest.Group(&payTxn, &appCallTxn)

			stxns := []transactions.SignedTxn{
				payTxn.Txn().Sign(sender.Secrets()),
				appCallTxn.Txn().Sign(sender.Secrets()),
			}

			// build request body
			var body io.Reader
			var bodyBytes []byte
			for _, stxn := range stxns {
				bodyBytes = append(bodyBytes, protocol.Encode(&stxn)...)
			}

			msgpackFormat := model.SimulateTransactionParamsFormatMsgpack
			jsonFormat := model.SimulateTransactionParamsFormatJson
			responseFormats := []struct {
				name   string
				params model.SimulateTransactionParams
				handle codec.Handle
			}{
				{
					name: "msgpack",
					params: model.SimulateTransactionParams{
						Format: &msgpackFormat,
					},
					handle: protocol.CodecHandle,
				},
				{
					name: "json",
					params: model.SimulateTransactionParams{
						Format: &jsonFormat,
					},
					handle: protocol.JSONStrictHandle,
				},
				{
					name: "default",
					params: model.SimulateTransactionParams{
						Format: nil, // should default to JSON
					},
					handle: protocol.JSONStrictHandle,
				},
			}

			for _, responseFormat := range responseFormats {
				t.Run(string(responseFormat.name), func(t *testing.T) { //nolint:paralleltest // Uses shared testing env
					body = bytes.NewReader(bodyBytes)
					req := httptest.NewRequest(http.MethodPost, "/", body)
					rec := httptest.NewRecorder()

					e := echo.New()
					c := e.NewContext(req, rec)

					// simulate transaction
					err := handler.SimulateTransaction(c, responseFormat.params)
					require.NoError(t, err)
					require.Equal(t, 200, rec.Code, rec.Body.String())

					// decode actual response
					var actualBody model.SimulateResponse
					decoder := codec.NewDecoderBytes(rec.Body.Bytes(), responseFormat.handle)
					err = decoder.Decode(&actualBody)
					require.NoError(t, err)

					var expectedFailedAt *[]uint64
					if len(scenario.FailedAt) != 0 {
						clone := make([]uint64, len(scenario.FailedAt))
						copy(clone, scenario.FailedAt)
						clone[0]++
						expectedFailedAt = &clone
					}

					var txnAppBudgetUsed []*uint64
					appBudgetAdded := numOrNil(scenario.AppBudgetAdded)
					appBudgetConsumed := numOrNil(scenario.AppBudgetConsumed)
					for i := range scenario.TxnAppBudgetConsumed {
						txnAppBudgetUsed = append(txnAppBudgetUsed, numOrNil(scenario.TxnAppBudgetConsumed[i]))
					}
					expectedBody := model.SimulateResponse{
						Version: 1,
						TxnGroups: []model.SimulateTransactionGroupResult{
							{
								AppBudgetAdded:    appBudgetAdded,
								AppBudgetConsumed: appBudgetConsumed,
								FailedAt:          expectedFailedAt,
								TxnResults: []model.SimulateTransactionResult{
									{
										TxnResult: makePendingTxnResponse(t, transactions.SignedTxnWithAD{
											SignedTxn: stxns[0],
											// expect no ApplyData info
										}, responseFormat.handle),
										AppBudgetConsumed: txnAppBudgetUsed[0],
									},
									{
										TxnResult: makePendingTxnResponse(t, transactions.SignedTxnWithAD{
											SignedTxn: stxns[1],
											ApplyData: scenario.ExpectedSimulationAD,
										}, responseFormat.handle),
										AppBudgetConsumed: txnAppBudgetUsed[1],
									},
								},
							},
						},
						WouldSucceed: scenario.Outcome == mocktracer.ApprovalOutcome,
					}
					assertSimulationResultsEqual(t, scenario.ExpectedError, expectedBody, actualBody)
				})
			}
		})
	}
}

func TestSimulateTransactionVerificationFailure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// prepare node and handler
	numAccounts := 5
	offlineAccounts := true
	mockLedger, roots, _, _, releasefunc := testingenv(t, numAccounts, 1, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}

	hdr, err := mockLedger.BlockHdr(mockLedger.Latest())
	require.NoError(t, err)
	txnInfo := simulationtesting.TxnInfo{LatestHeader: hdr}

	sender := roots[0]
	receiver := roots[1]

	txn := txnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Address(),
		Receiver: receiver.Address(),
		Amount:   0,
	})

	stxn := txn.Txn().Sign(sender.Secrets())
	// make signature invalid
	stxn.Sig[0] += byte(1) // will wrap if > 255

	// build request body
	bodyBytes := protocol.Encode(&stxn)
	body := bytes.NewReader(bodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	rec := httptest.NewRecorder()

	e := echo.New()
	c := e.NewContext(req, rec)

	// simulate transaction
	err = handler.SimulateTransaction(c, model.SimulateTransactionParams{})
	require.NoError(t, err)
	require.Equal(t, 400, rec.Code, rec.Body.String())
}

func startCatchupTest(t *testing.T, catchpoint string, nodeError error, expectedCode int) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nodeError, false)
	handler := v2.Handlers{Node: mockNode, Log: logging.Base(), Shutdown: dummyShutdownChan}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.StartCatchup(c, catchpoint)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestStartCatchup(t *testing.T) {
	partitiontest.PartitionTest(t)
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

	// Test that a catchup fails w/ 400 when the catchpoint round is > syncRound (while syncRound is set)
	syncRoundError := node.MakeCatchpointSyncRoundFailure(goodCatchPoint, 1)
	startCatchupTest(t, goodCatchPoint, syncRoundError, 400)
}

func abortCatchupTest(t *testing.T, catchpoint string, expectedCode int) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
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
	partitiontest.PartitionTest(t)
	t.Parallel()

	goodCatchPoint := "5894690#DVFRZUYHEFKRLK5N6DNJRR4IABEVN2D6H76F3ZSEPIE6MKXMQWQA"
	abortCatchupTest(t, goodCatchPoint, 200)
	badCatchPoint := "bad catchpoint"
	abortCatchupTest(t, badCatchPoint, 400)
}

func tealCompileTest(t *testing.T, bytesToUse []byte, expectedCode int,
	enableDeveloperAPI bool, params model.TealCompileParams,
	expectedSourcemap *logic.SourceMap,
) (response v2.CompileResponseWithSourceMap) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
	mockNode.config.EnableDeveloperAPI = enableDeveloperAPI
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytesToUse))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.TealCompile(c, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)

	// Check compiled response.
	if rec.Code == 200 {
		data := rec.Body.Bytes()
		err = protocol.DecodeJSON(data, &response)
		require.NoError(t, err, string(data))
		if expectedSourcemap != nil {
			require.Equal(t, *expectedSourcemap, *response.Sourcemap)
		} else {
			require.Nil(t, response.Sourcemap)
		}
	}
	return
}

func TestTealCompile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	params := model.TealCompileParams{}
	tealCompileTest(t, nil, 400, true, params, nil) // nil program should NOT work

	goodProgram := fmt.Sprintf(`#pragma version %d
int 1
assert
int 1`, logic.AssemblerMaxVersion)
	ops, _ := logic.AssembleString(goodProgram)
	expectedSourcemap := logic.GetSourceMap([]string{}, ops.OffsetToLine)
	goodProgramBytes := []byte(goodProgram)

	// Test good program with params
	tealCompileTest(t, goodProgramBytes, 200, true, params, nil)
	paramValue := true
	params = model.TealCompileParams{Sourcemap: &paramValue}
	tealCompileTest(t, goodProgramBytes, 200, true, params, &expectedSourcemap)
	paramValue = false
	params = model.TealCompileParams{Sourcemap: &paramValue}
	tealCompileTest(t, goodProgramBytes, 200, true, params, nil)

	// Test a program without the developer API flag.
	tealCompileTest(t, goodProgramBytes, 404, false, params, nil)

	// Test bad program.
	badProgram := "bad program"
	badProgramBytes := []byte(badProgram)
	tealCompileTest(t, badProgramBytes, 400, true, params, nil)
}

func tealDisassembleTest(t *testing.T, program []byte, expectedCode int,
	expectedString string, enableDeveloperAPI bool,
) (response model.DisassembleResponse) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
	mockNode.config.EnableDeveloperAPI = enableDeveloperAPI
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(program))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.TealDisassemble(c)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)

	if rec.Code == 200 {
		data := rec.Body.Bytes()
		err = protocol.DecodeJSON(data, &response)
		require.NoError(t, err, string(data))
		require.Equal(t, expectedString, response.Result)
	} else if rec.Code == 400 {
		var response model.ErrorResponse
		data := rec.Body.Bytes()
		err = protocol.DecodeJSON(data, &response)
		require.NoError(t, err, string(data))
		require.Contains(t, response.Message, expectedString)
	}
	return
}

func TestTealDisassemble(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// nil program works, but results in invalid version text.
	testProgram := []byte{}
	tealDisassembleTest(t, testProgram, 200, "// invalid version\n", true)

	// Test a valid program.
	for ver := 1; ver <= logic.AssemblerMaxVersion; ver++ {
		goodProgram := `int 1`
		ops, _ := logic.AssembleStringWithVersion(goodProgram, uint64(ver))
		disassembledProgram, _ := logic.Disassemble(ops.Program)
		tealDisassembleTest(t, ops.Program, 200, disassembledProgram, true)
	}
	// Test a nil program without the developer API flag.
	tealDisassembleTest(t, testProgram, 404, "", false)

	// Test bad program.
	badProgram := []byte{1, 99}
	tealDisassembleTest(t, badProgram, 400, "invalid opcode", true)
}

func tealDryrunTest(
	t *testing.T, obj *model.DryrunRequest, format string,
	expCode int, expResult string, enableDeveloperAPI bool,
) (response model.DryrunResponse) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
	mockNode.config.EnableDeveloperAPI = enableDeveloperAPI
	handler := v2.Handlers{
		Node:     mockNode,
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
	partitiontest.PartitionTest(t)
	t.Parallel()

	var gdr model.DryrunRequest
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

	sucOps, err := logic.AssembleStringWithVersion("int 1", 2)
	require.NoError(t, err)

	failOps, err := logic.AssembleStringWithVersion("int 0", 2)
	require.NoError(t, err)

	gdr.Apps = []model.Application{
		{
			Id: 1,
			Params: model.ApplicationParams{
				ApprovalProgram: sucOps.Program,
			},
		},
	}
	localv := make(model.TealKeyValueStore, 1)
	localv[0] = model.TealKeyValue{
		Key:   "foo",
		Value: model.TealValue{Type: uint64(basics.TealBytesType), Bytes: "bar"},
	}

	gdr.Accounts = []model.Account{
		{
			Address: basics.Address{}.String(),
			AppsLocalState: &[]model.ApplicationLocalState{{
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

	ddr := tealDryrunTest(t, &gdr, "json", 200, "PASS", true)
	require.Equal(t, string(protocol.ConsensusCurrentVersion), ddr.ProtocolVersion)
	gdr.ProtocolVersion = string(protocol.ConsensusFuture)
	ddr = tealDryrunTest(t, &gdr, "json", 200, "PASS", true)
	require.Equal(t, string(protocol.ConsensusFuture), ddr.ProtocolVersion)

	gdr.Apps[0].Params.ApprovalProgram = failOps.Program
	tealDryrunTest(t, &gdr, "json", 200, "REJECT", true)
	tealDryrunTest(t, &gdr, "msgp", 200, "REJECT", true)
	tealDryrunTest(t, &gdr, "json", 404, "", false)
}

func TestAppendParticipationKeys(t *testing.T) {
	partitiontest.PartitionTest(t)

	mockLedger, _, _, _, releasefunc := testingenv(t, 1, 1, true)
	defer releasefunc()
	mockNode := makeMockNode(mockLedger, t.Name(), nil, false)
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: make(chan struct{}),
	}

	id := account.ParticipationID{}
	id[0] = 10

	t.Run("Happy path", func(t *testing.T) {
		// Create test object to append.
		keys := make(account.StateProofKeys, 2)
		testKey1 := crypto.FalconSigner{}
		testKey1.PrivateKey[0] = 100

		testKey2 := crypto.FalconSigner{}
		testKey2.PrivateKey[0] = 101

		keys[0] = merklesignature.KeyRoundPair{Round: 100, Key: &testKey1}
		keys[1] = merklesignature.KeyRoundPair{Round: 101, Key: &testKey2}
		keyBytes := protocol.Encode(keys)

		// Put keys in the body.
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(keyBytes))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Call handler with request.
		err := handler.AppendKeys(c, id.String())

		// Verify that request was properly received and deserialized.
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, id, mockNode.id)
		require.Len(t, mockNode.keys, 2)
		require.Equal(t, mockNode.keys[0].Round, keys[0].Round)
		require.Equal(t, mockNode.keys[0].Key, keys[0].Key)

		require.Equal(t, mockNode.keys[1].Round, keys[1].Round)
		require.Equal(t, mockNode.keys[1].Key, keys[1].Key)

	})

	t.Run("Invalid body", func(t *testing.T) {
		// Create request with bogus bytes in the body
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte{0x99, 0x88, 0x77}))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Call handler with request.
		err := handler.AppendKeys(c, id.String())

		// Verify that request was properly received and deserialized.
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "unable to parse keys from body: msgpack decode error")
	})

	t.Run("Empty body", func(t *testing.T) {
		// Create test object with no keys to append.
		keys := make(account.StateProofKeys, 0)
		keyBytes := protocol.Encode(keys)

		// Put keys in the body.
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(keyBytes))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Call handler with request.
		err := handler.AppendKeys(c, id.String())

		// Verify that request was properly received and deserialized.
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "empty request, please attach keys to request body")
	})

	t.Run("Internal error", func(t *testing.T) {
		// Create mock node with an error.
		expectedErr := errors.New("expected error")
		mockNode := makeMockNode(mockLedger, t.Name(), expectedErr, false)
		handler := v2.Handlers{
			Node:     mockNode,
			Log:      logging.Base(),
			Shutdown: make(chan struct{}),
		}

		keys := make(account.StateProofKeys, 2)
		testKey1 := crypto.FalconSigner{}
		testKey1.PrivateKey[0] = 100

		testKey2 := crypto.FalconSigner{}
		testKey2.PrivateKey[0] = 101

		keys[0] = merklesignature.KeyRoundPair{Round: 100, Key: &testKey1}
		keys[1] = merklesignature.KeyRoundPair{Round: 101, Key: &testKey2}
		keyBytes := protocol.Encode(keys)

		// Put keys in the body.
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(keyBytes))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Call handler with request.
		err := handler.AppendKeys(c, id.String())

		// Verify that request was properly received and deserialized.
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Contains(t, rec.Body.String(), expectedErr.Error())
	})
}

// TxnMerkleElemRaw this struct helps creates a hashable struct from the bytes
type TxnMerkleElemRaw struct {
	Txn  crypto.Digest // txn id
	Stib crypto.Digest // hash value of transactions.SignedTxnInBlock
}

func txnMerkleToRaw(txid [crypto.DigestSize]byte, stib [crypto.DigestSize]byte) (buf []byte) {
	buf = make([]byte, 2*crypto.DigestSize)
	copy(buf[:], txid[:])
	copy(buf[crypto.DigestSize:], stib[:])
	return
}

// ToBeHashed implements the crypto.Hashable interface.
func (tme *TxnMerkleElemRaw) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TxnMerkleLeaf, txnMerkleToRaw(tme.Txn, tme.Stib)
}

func TestGetProofDefault(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)

	handler, c, rec, stx, releasefunc := addBlockHelper(t)
	defer releasefunc()

	txid := stx.ID()
	err := handler.GetTransactionProof(c, 1, txid.String(), model.GetTransactionProofParams{})
	a.NoError(err)

	var resp model.TransactionProofResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	a.NoError(err)
	a.Equal(model.TransactionProofResponseHashtypeSha512256, resp.Hashtype)

	l := handler.Node.LedgerForAPI()
	blkHdr, err := l.BlockHdr(1)
	a.NoError(err)

	singleLeafProof, err := merklearray.ProofDataToSingleLeafProof(string(resp.Hashtype), resp.Treedepth, resp.Proof)
	a.NoError(err)

	element := TxnMerkleElemRaw{Txn: crypto.Digest(txid)}
	copy(element.Stib[:], resp.Stibhash[:])
	elems := make(map[uint64]crypto.Hashable)
	elems[0] = &element

	// Verifies that the default proof is using SHA512_256
	err = merklearray.Verify(blkHdr.TxnCommitments.NativeSha512_256Commitment.ToSlice(), elems, singleLeafProof.ToProof())
	a.NoError(err)
}

func newEmptyBlock(a *require.Assertions, lastBlock bookkeeping.Block, genBlk bookkeeping.Block, l v2.LedgerForAPI) bookkeeping.Block {
	totalsRound, totals, err := l.LatestTotals()
	a.NoError(err)
	a.Equal(l.Latest(), totalsRound)

	totalRewardUnits := totals.RewardUnits()
	poolBal, _, _, err := l.LookupLatest(poolAddr)
	a.NoError(err)

	latestBlock := lastBlock

	var blk bookkeeping.Block
	blk.BlockHeader = bookkeeping.BlockHeader{
		GenesisID:    genBlk.GenesisID(),
		GenesisHash:  genBlk.GenesisHash(),
		Round:        l.Latest() + 1,
		Branch:       latestBlock.Hash(),
		RewardsState: latestBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits, logging.Base()),
		UpgradeState: latestBlock.UpgradeState,
	}

	blk.BlockHeader.TxnCounter = latestBlock.TxnCounter

	blk.RewardsPool = latestBlock.RewardsPool
	blk.FeeSink = latestBlock.FeeSink
	blk.CurrentProtocol = latestBlock.CurrentProtocol
	blk.TimeStamp = latestBlock.TimeStamp + 1

	blk.BlockHeader.TxnCounter++
	blk.TxnCommitments, err = blk.PaysetCommit()
	a.NoError(err)

	return blk
}

func addStateProofIfNeeded(blk bookkeeping.Block) bookkeeping.Block {
	round := uint64(blk.Round())
	if round%stateProofIntervalForHandlerTests == (stateProofIntervalForHandlerTests/2+18) && round > stateProofIntervalForHandlerTests*2 {
		return blk
	}
	stateProofRound := (round - round%stateProofIntervalForHandlerTests) - stateProofIntervalForHandlerTests
	tx := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type:   protocol.StateProofTx,
			Header: transactions.Header{Sender: transactions.StateProofSender},
			StateProofTxnFields: transactions.StateProofTxnFields{
				StateProofType: 0,
				Message: stateproofmsg.Message{
					BlockHeadersCommitment: []byte{0x0, 0x1, 0x2},
					FirstAttestedRound:     stateProofRound + 1,
					LastAttestedRound:      stateProofRound + stateProofIntervalForHandlerTests,
				},
			},
		},
	}
	txnib := transactions.SignedTxnInBlock{SignedTxnWithAD: transactions.SignedTxnWithAD{SignedTxn: tx}}
	blk.Payset = append(blk.Payset, txnib)

	return blk
}

func insertRounds(a *require.Assertions, h v2.Handlers, numRounds int) {
	ledger := h.Node.LedgerForAPI()

	genBlk, err := ledger.Block(0)
	a.NoError(err)

	lastBlk := genBlk
	for i := 0; i < numRounds; i++ {
		blk := newEmptyBlock(a, lastBlk, genBlk, ledger)
		blk = addStateProofIfNeeded(blk)
		blk.BlockHeader.CurrentProtocol = protocol.ConsensusCurrentVersion
		a.NoError(ledger.(*data.Ledger).AddBlock(blk, agreement.Certificate{}))
		lastBlk = blk
	}
}

func TestStateProofNotFound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	insertRounds(a, handler, 700)

	a.NoError(handler.GetStateProof(ctx, 650))
	a.Equal(404, responseRecorder.Code)
}

func TestStateProofHigherRoundThanLatest(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	a.NoError(handler.GetStateProof(ctx, 2))
	a.Equal(500, responseRecorder.Code)
}

func TestStateProof200(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	insertRounds(a, handler, 1000)

	a.NoError(handler.GetStateProof(ctx, stateProofIntervalForHandlerTests+1))
	a.Equal(200, responseRecorder.Code)

	stprfResp := model.StateProofResponse{}
	a.NoError(json.Unmarshal(responseRecorder.Body.Bytes(), &stprfResp))

	a.Equal([]byte{0x0, 0x1, 0x2}, stprfResp.Message.BlockHeadersCommitment)
}

func TestHeaderProofRoundTooHigh(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	a.NoError(handler.GetLightBlockHeaderProof(ctx, 2))
	a.Equal(500, responseRecorder.Code)
}

func TestHeaderProofStateProofNotFound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	insertRounds(a, handler, 700)

	a.NoError(handler.GetLightBlockHeaderProof(ctx, 650))
	a.Equal(404, responseRecorder.Code)
}

func TestGetBlockProof200(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	insertRounds(a, handler, 1000)

	a.NoError(handler.GetLightBlockHeaderProof(ctx, stateProofIntervalForHandlerTests*2+2))
	a.Equal(200, responseRecorder.Code)

	blkHdrArr, err := stateproof.FetchLightHeaders(handler.Node.LedgerForAPI(), stateProofIntervalForHandlerTests, basics.Round(stateProofIntervalForHandlerTests*3))
	a.NoError(err)

	leafproof, err := stateproof.GenerateProofOfLightBlockHeaders(stateProofIntervalForHandlerTests, blkHdrArr, 1)
	a.NoError(err)

	proofResp := model.LightBlockHeaderProofResponse{}
	a.NoError(json.Unmarshal(responseRecorder.Body.Bytes(), &proofResp))
	a.Equal(proofResp.Proof, leafproof.GetConcatenatedProof())
	a.Equal(proofResp.Treedepth, uint64(leafproof.TreeDepth))
}

func TestStateproofTransactionForRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ledger := mockLedger{blocks: make([]bookkeeping.Block, 0, 1000)}
	for i := 0; i <= 1000; i++ {
		var blk bookkeeping.Block
		blk.BlockHeader = bookkeeping.BlockHeader{
			Round: basics.Round(i),
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
		}
		blk = addStateProofIfNeeded(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}

	ctx, cncl := context.WithTimeout(context.Background(), time.Minute*2)
	defer cncl()
	txn, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofIntervalForHandlerTests*2+1), 1000, nil)
	a.NoError(err)
	a.Equal(2*stateProofIntervalForHandlerTests+1, txn.Message.FirstAttestedRound)
	a.Equal(3*stateProofIntervalForHandlerTests, txn.Message.LastAttestedRound)
	a.Equal([]byte{0x0, 0x1, 0x2}, txn.Message.BlockHeadersCommitment)

	txn, err = v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(2*stateProofIntervalForHandlerTests), 1000, nil)
	a.NoError(err)
	a.Equal(stateProofIntervalForHandlerTests+1, txn.Message.FirstAttestedRound)
	a.Equal(2*stateProofIntervalForHandlerTests, txn.Message.LastAttestedRound)

	txn, err = v2.GetStateProofTransactionForRound(ctx, &ledger, 999, 1000, nil)
	a.ErrorIs(err, v2.ErrNoStateProofForRound)

	txn, err = v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(2*stateProofIntervalForHandlerTests), basics.Round(2*stateProofIntervalForHandlerTests), nil)
	a.ErrorIs(err, v2.ErrNoStateProofForRound)
}

func TestStateproofTransactionForRoundWithoutStateproofs(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ledger := mockLedger{blocks: make([]bookkeeping.Block, 0, 1000)}
	for i := 0; i <= 1000; i++ {
		var blk bookkeeping.Block
		blk.BlockHeader = bookkeeping.BlockHeader{
			Round: basics.Round(i),
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusV30, // should have StateProofInterval == 0 .
			},
		}
		blk = addStateProofIfNeeded(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}
	ctx, cncl := context.WithTimeout(context.Background(), time.Minute)
	defer cncl()
	_, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofIntervalForHandlerTests*2+1), 1000, nil)
	a.ErrorIs(err, v2.ErrNoStateProofForRound)
}

func TestStateproofTransactionForRoundTimeouts(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ledger := mockLedger{blocks: make([]bookkeeping.Block, 0, 1000)}
	for i := 0; i <= 1000; i++ {
		var blk bookkeeping.Block
		blk.BlockHeader = bookkeeping.BlockHeader{
			Round: basics.Round(i),
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion, // should have StateProofInterval != 0 .
			},
		}
		blk = addStateProofIfNeeded(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}

	ctx, cncl := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cncl()
	_, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofIntervalForHandlerTests*2+1), 1000, nil)
	a.ErrorIs(err, v2.ErrTimeout)
}

func TestStateproofTransactionForRoundShutsDown(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ledger := mockLedger{blocks: make([]bookkeeping.Block, 0, 1000)}
	for i := 0; i <= 1000; i++ {
		var blk bookkeeping.Block
		blk.BlockHeader = bookkeeping.BlockHeader{
			Round: basics.Round(i),
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion, // should have StateProofInterval != 0 .
			},
		}
		blk = addStateProofIfNeeded(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}

	stoppedChan := make(chan struct{})
	close(stoppedChan)
	ctx, cncl := context.WithTimeout(context.Background(), time.Minute)
	defer cncl()
	_, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofIntervalForHandlerTests*2+1), 1000, stoppedChan)
	a.ErrorIs(err, v2.ErrShutdown)
}

func TestExperimentalCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, false)
	defer releasefunc()

	// Since we are invoking the method directly, it doesn't matter if EnableExperimentalAPI is true.
	// When this is false, the router never even registers this endpoint.
	err := handler.ExperimentalCheck(c)
	require.NoError(t, err)

	require.Equal(t, 200, rec.Code)
	require.Equal(t, "true\n", string(rec.Body.Bytes()))
}
