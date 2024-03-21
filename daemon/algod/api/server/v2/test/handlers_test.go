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

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/algorand/go-algorand/daemon/algod/api/server"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"golang.org/x/exp/slices"

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

const stateProofInterval = uint64(256)

func setupMockNodeForMethodGet(t *testing.T, status node.StatusReport, devmode bool) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, []account.Root, []transactions.SignedTxn, func()) {
	return setupMockNodeForMethodGetWithShutdown(t, status, devmode, make(chan struct{}))
}

func setupMockNodeForMethodGetWithShutdown(t *testing.T, status node.StatusReport, devmode bool, shutdown chan struct{}) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, []account.Root, []transactions.SignedTxn, func()) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, rootkeys, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	mockNode := makeMockNode(mockLedger, t.Name(), nil, status, devmode)
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: shutdown,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	return handler, c, rec, rootkeys, stxns, releasefunc
}

func setupTestForMethodGet(t *testing.T, status node.StatusReport) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, []account.Root, []transactions.SignedTxn, func()) {
	return setupMockNodeForMethodGet(t, status, false)
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

	handler, _, _, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()
	require.Equal(t, t.Name(), handler.Node.GenesisID())
}

func accountInformationTest(t *testing.T, address string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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

	mock.AssertExpectationsForObjects(t, mockNode)
}

func addBlockHelper(t *testing.T) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, transactions.SignedTxn, func()) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)

	l := handler.Node.LedgerForAPI()

	genBlk, err := l.Block(0)
	require.NoError(t, err)

	// make an app call txn with eval delta
	lsig := transactions.LogicSig{Logic: retOneProgram} // int 1
	lhash := logic.HashProgram(lsig.Logic)
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

func TestGetBlockTxids(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, stx, releasefunc := addBlockHelper(t)
	defer releasefunc()

	var response model.BlockTxidsResponse
	err := handler.GetBlockTxids(c, 0)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	data := rec.Body.Bytes()
	err = protocol.DecodeJSON(data, &response)
	require.NoError(t, err)
	require.Equal(t, 0, len(response.BlockTxids))

	c, rec = newReq(t)
	err = handler.GetBlockTxids(c, 2)
	require.NoError(t, err)
	require.Equal(t, 404, rec.Code)

	c, rec = newReq(t)
	err = handler.GetBlockTxids(c, 1)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	data = rec.Body.Bytes()
	err = protocol.DecodeJSON(data, &response)
	require.NoError(t, err)
	require.Equal(t, 1, len(response.BlockTxids))
	require.Equal(t, stx.ID().String(), response.BlockTxids[0])
}

func TestGetBlockHash(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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

	handler, c, _, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()
	err := handler.GetSupply(c)
	require.NoError(t, err)
}

func TestGetStatus(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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

func TestGetStatusConsensusUpgradeUnderflow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Setup status report with unanimous YES votes.
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	currentRound := basics.Round(1000000)
	stat := node.StatusReport{
		LastRound:              currentRound - 1,
		LastVersion:            protocol.ConsensusCurrentVersion,
		NextVersion:            protocol.ConsensusCurrentVersion,
		UpgradePropose:         "upgradePropose",
		NextProtocolVoteBefore: currentRound,
		NextProtocolApprovals:  proto.UpgradeVoteRounds,
	}

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, stat)
	defer releasefunc()
	err := handler.GetStatus(c)
	require.NoError(t, err)
	actualResult := model.NodeStatusResponse{}
	err = protocol.DecodeJSON(rec.Body.Bytes(), &actualResult)
	require.NoError(t, err)

	// Make sure the votes are all yes, and 0 no.
	require.Equal(t, uint64(0), *actualResult.UpgradeNoVotes)
	require.Equal(t, proto.UpgradeVoteRounds, *actualResult.UpgradeYesVotes)
	require.Equal(t, proto.UpgradeVoteRounds, *actualResult.UpgradeVotes)
	require.Equal(t, proto.UpgradeThreshold, *actualResult.UpgradeVotesRequired)
}

func TestGetStatusConsensusUpgrade(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cannedStatusReportConsensusUpgradeGolden := node.StatusReport{
		LastRound:                          basics.Round(97000),
		LastVersion:                        protocol.ConsensusCurrentVersion,
		NextVersion:                        protocol.ConsensusCurrentVersion,
		NextVersionRound:                   200000,
		NextVersionSupported:               true,
		StoppedAtUnsupportedRound:          true,
		Catchpoint:                         "",
		CatchpointCatchupAcquiredBlocks:    0,
		CatchpointCatchupProcessedAccounts: 0,
		CatchpointCatchupVerifiedAccounts:  0,
		CatchpointCatchupTotalAccounts:     0,
		CatchpointCatchupTotalKVs:          0,
		CatchpointCatchupProcessedKVs:      0,
		CatchpointCatchupVerifiedKVs:       0,
		CatchpointCatchupTotalBlocks:       0,
		LastCatchpoint:                     "",
		UpgradePropose:                     "upgradePropose",
		UpgradeApprove:                     false,
		UpgradeDelay:                       0,
		NextProtocolVoteBefore:             100000,
		NextProtocolApprovals:              5000,
	}

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportConsensusUpgradeGolden)
	defer releasefunc()
	err := handler.GetStatus(c)
	require.NoError(t, err)
	stat := cannedStatusReportConsensusUpgradeGolden
	consensus := config.Consensus[protocol.ConsensusCurrentVersion]
	votesToGo := uint64(stat.NextProtocolVoteBefore) - uint64(stat.LastRound) - 1
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

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()
	err := handler.WaitForBlock(c, 0)
	require.NoError(t, err)

	require.Equal(t, 400, rec.Code)
	msg, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	require.Contains(t, string(msg), "requested round would reach only after the protocol upgrade which isn't supported")
}

func TestGetStatusAfterBlockShutdown(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	catchup := cannedStatusReportGolden
	catchup.StoppedAtUnsupportedRound = false
	shutdownChan := make(chan struct{})
	handler, c, rec, _, _, releasefunc := setupMockNodeForMethodGetWithShutdown(t, catchup, false, shutdownChan)
	defer releasefunc()

	close(shutdownChan)
	err := handler.WaitForBlock(c, 0)
	require.NoError(t, err)

	require.Equal(t, 500, rec.Code)
	msg, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	require.Contains(t, string(msg), "operation aborted as server is shutting down")
}

func TestGetStatusAfterBlockDuringCatchup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	catchup := cannedStatusReportGolden
	catchup.StoppedAtUnsupportedRound = false
	catchup.Catchpoint = "catchpoint"
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, catchup)
	defer releasefunc()

	err := handler.WaitForBlock(c, 0)
	require.NoError(t, err)

	require.Equal(t, 503, rec.Code)
	msg, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	require.Contains(t, string(msg), "operation not available during catchup")
}

func TestGetStatusAfterBlockTimeout(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	supported := cannedStatusReportGolden
	supported.StoppedAtUnsupportedRound = false
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, supported)
	defer releasefunc()

	before := v2.WaitForBlockTimeout
	defer func() { v2.WaitForBlockTimeout = before }()
	v2.WaitForBlockTimeout = 1 * time.Millisecond
	err := handler.WaitForBlock(c, 1000)
	require.NoError(t, err)

	require.Equal(t, 200, rec.Code)
	dec := json.NewDecoder(rec.Body)
	var resp model.NodeStatusResponse
	err = dec.Decode(&resp)
	require.NoError(t, err)
	require.Equal(t, uint64(1), resp.LastRound)
}

func TestGetTransactionParams(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()
	err := handler.TransactionParams(c)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
}

func pendingTransactionInformationTest(t *testing.T, txidToUse int, format string, expectedCode int) {
	handler, c, rec, _, stxns, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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
	handler, c, rec, rootkeys, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
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

func prepareTransactionTest(t *testing.T, txnToUse int, txnPrep func(transactions.SignedTxn) []byte, cfg config.Local) (handler v2.Handlers, c echo.Context, rec *httptest.ResponseRecorder, releasefunc func()) {
	numAccounts := 5
	numTransactions := 5
	offlineAccounts := true
	mockLedger, _, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNodeWithConfig(mockLedger, t.Name(), nil, cannedStatusReportGolden, false, cfg)
	handler = v2.Handlers{

		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	var body io.Reader
	if txnToUse >= 0 {
		stxn := stxns[txnToUse]
		bodyBytes := txnPrep(stxn)
		body = bytes.NewReader(bodyBytes)
	}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	return
}

func postTransactionTest(t *testing.T, txnToUse int, expectedCode int, method string, enableExperimental bool) {
	txnPrep := func(stxn transactions.SignedTxn) []byte {
		return protocol.Encode(&stxn)
	}
	cfg := config.GetDefaultLocal()
	cfg.EnableExperimentalAPI = enableExperimental
	handler, c, rec, releasefunc := prepareTransactionTest(t, txnToUse, txnPrep, cfg)
	defer releasefunc()
	results := reflect.ValueOf(&handler).MethodByName(method).Call([]reflect.Value{reflect.ValueOf(c)})
	require.Equal(t, 1, len(results))
	// if the method returns nil, the cast would fail so use type assertion test
	err, _ := results[0].Interface().(error)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPostTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	postTransactionTest(t, -1, 400, "RawTransaction", false)
	postTransactionTest(t, 0, 200, "RawTransaction", false)
}

func TestPostTransactionAsync(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	postTransactionTest(t, -1, 404, "RawTransactionAsync", false)
	postTransactionTest(t, 0, 404, "RawTransactionAsync", false)
	postTransactionTest(t, -1, 400, "RawTransactionAsync", true)
	postTransactionTest(t, 0, 200, "RawTransactionAsync", true)
}

func simulateTransactionTest(t *testing.T, txnToUse int, format string, expectedCode int) {
	txnPrep := func(stxn transactions.SignedTxn) []byte {
		request := v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
				{
					Txns: []transactions.SignedTxn{stxn},
				},
			},
		}
		return protocol.EncodeReflect(&request)
	}
	handler, c, rec, releasefunc := prepareTransactionTest(t, txnToUse, txnPrep, config.GetDefaultLocal())
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

func copyInnerTxnGroupIDs(t *testing.T, dst, src *v2.PreEncodedTxInfo) {
	t.Helper()

	if !src.Txn.Txn.Group.IsZero() {
		dst.Txn.Txn.Group = src.Txn.Txn.Group
	}

	if dst.Inners == nil || src.Inners == nil {
		return
	}

	assert.Equal(t, len(*dst.Inners), len(*src.Inners))

	for innerIndex := range *dst.Inners {
		if innerIndex == len(*src.Inners) {
			break
		}
		dstInner := &(*dst.Inners)[innerIndex]
		srcInner := &(*src.Inners)[innerIndex]
		copyInnerTxnGroupIDs(t, dstInner, srcInner)
	}
}

func assertSimulationResultsEqual(t *testing.T, expectedError string, expected, actual v2.PreEncodedSimulateResponse) {
	t.Helper()

	if len(expectedError) != 0 {
		require.NotNil(t, actual.TxnGroups[0].FailureMessage)
		require.Contains(t, *actual.TxnGroups[0].FailureMessage, expectedError)
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
		assert.Equal(t, len(expectedGroup.Txns), len(actualGroup.Txns))
		for txnIndex := range expectedGroup.Txns {
			if txnIndex == len(actualGroup.Txns) {
				break
			}
			expectedTxn := &expectedGroup.Txns[txnIndex]
			actualTxn := &actualGroup.Txns[txnIndex]
			if expectedTxn.Txn.Inners == nil || actualTxn.Txn.Inners == nil {
				continue
			}
			assert.Equal(t, len(*expectedTxn.Txn.Inners), len(*actualTxn.Txn.Inners))
			for innerIndex := range *expectedTxn.Txn.Inners {
				if innerIndex == len(*actualTxn.Txn.Inners) {
					break
				}
				expectedInner := &(*expectedTxn.Txn.Inners)[innerIndex]
				actualInner := &(*actualTxn.Txn.Inners)[innerIndex]
				copyInnerTxnGroupIDs(t, expectedInner, actualInner)
			}
		}
	}

	require.Equal(t, expected, actual)
}

func makePendingTxnResponse(t *testing.T, txn transactions.SignedTxnWithAD) v2.PreEncodedTxInfo {
	t.Helper()
	preEncoded := v2.ConvertInnerTxn(&txn)

	// In theory we could return preEncoded directly, but there appears to be some subtle differences
	// once you encode and decode the object, such as *uint64 fields turning from 0 to nil. So to be
	// safe, let's encode and decode the object.

	// Encode to bytes
	encodedBytes := protocol.EncodeReflect(&preEncoded)

	// Decode to v2.PreEncodedTxInfo
	var response v2.PreEncodedTxInfo
	err := protocol.DecodeReflect(encodedBytes, &response)
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
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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
			futureAppID := basics.AppIndex(1002)

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
			request := v2.PreEncodedSimulateRequest{
				TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
					{
						Txns: stxns,
					},
				},
			}
			bodyBytes := protocol.EncodeReflect(&request)

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
					var actualBody v2.PreEncodedSimulateResponse
					decoder := codec.NewDecoderBytes(rec.Body.Bytes(), responseFormat.handle)
					err = decoder.Decode(&actualBody)
					require.NoError(t, err)

					var expectedFailedAt *[]uint64
					if len(scenario.FailedAt) != 0 {
						clone := slices.Clone(scenario.FailedAt)
						clone[0]++
						expectedFailedAt = &clone
					}

					var txnAppBudgetUsed []*uint64
					appBudgetAdded := numOrNil(scenario.AppBudgetAdded)
					appBudgetConsumed := numOrNil(scenario.AppBudgetConsumed)
					for i := range scenario.TxnAppBudgetConsumed {
						txnAppBudgetUsed = append(txnAppBudgetUsed, numOrNil(scenario.TxnAppBudgetConsumed[i]))
					}
					expectedBody := v2.PreEncodedSimulateResponse{
						Version: 2,
						TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
							{
								AppBudgetAdded:    appBudgetAdded,
								AppBudgetConsumed: appBudgetConsumed,
								FailedAt:          expectedFailedAt,
								Txns: []v2.PreEncodedSimulateTxnResult{
									{
										Txn: makePendingTxnResponse(t, transactions.SignedTxnWithAD{
											SignedTxn: stxns[0],
											// expect no ApplyData info
										}),
										AppBudgetConsumed: txnAppBudgetUsed[0],
									},
									{
										Txn: makePendingTxnResponse(t, transactions.SignedTxnWithAD{
											SignedTxn: stxns[1],
											ApplyData: scenario.ExpectedSimulationAD,
										}),
										AppBudgetConsumed: txnAppBudgetUsed[1],
									},
								},
							},
						},
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
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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

func TestSimulateTransactionMultipleGroups(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// prepare node and handler
	numAccounts := 5
	offlineAccounts := true
	mockLedger, roots, _, _, releasefunc := testingenv(t, numAccounts, 1, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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

	txn1 := txnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Address(),
		Receiver: receiver.Address(),
		Amount:   1,
	})
	txn2 := txnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Address(),
		Receiver: receiver.Address(),
		Amount:   2,
	})

	stxn1 := txn1.Txn().Sign(sender.Secrets())
	stxn2 := txn2.Txn().Sign(sender.Secrets())

	// build request body
	request := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{stxn1},
			},
			{
				Txns: []transactions.SignedTxn{stxn2},
			},
		},
	}
	bodyBytes := protocol.EncodeReflect(&request)
	body := bytes.NewReader(bodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	rec := httptest.NewRecorder()

	e := echo.New()
	c := e.NewContext(req, rec)

	// simulate transaction
	err = handler.SimulateTransaction(c, model.SimulateTransactionParams{})
	require.NoError(t, err)
	bodyString := rec.Body.String()
	require.Equal(t, 400, rec.Code, bodyString)
	require.Contains(t, bodyString, "expected 1 transaction group, got 2")
}

func startCatchupTest(t *testing.T, catchpoint string, nodeError error, expectedCode int) {
	startCatchupTestFull(t, catchpoint, nodeError, expectedCode, 0, "")
}

func startCatchupTestFull(t *testing.T, catchpoint string, nodeError error, expectedCode int, minRounds uint64, response string) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nodeError, cannedStatusReportGolden, false)
	handler := v2.Handlers{Node: mockNode, Log: logging.Base(), Shutdown: dummyShutdownChan}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	var err error
	if minRounds != 0 {
		err = handler.StartCatchup(c, catchpoint, model.StartCatchupParams{Min: &minRounds})
	} else {
		err = handler.StartCatchup(c, catchpoint, model.StartCatchupParams{})
	}
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
	if response != "" {
		require.Contains(t, rec.Body.String(), response)
	}
}

func TestStartCatchupInit(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	minRoundsToInitialize := uint64(1_000_000)

	tooSmallCatchpoint := fmt.Sprintf("%d#DVFRZUYHEFKRLK5N6DNJRR4IABEVN2D6H76F3ZSEPIE6MKXMQWQA", minRoundsToInitialize-1)
	startCatchupTestFull(t, tooSmallCatchpoint, nil, 200, minRoundsToInitialize, "the node has already been initialized")

	catchpointOK := fmt.Sprintf("%d#DVFRZUYHEFKRLK5N6DNJRR4IABEVN2D6H76F3ZSEPIE6MKXMQWQA", minRoundsToInitialize)
	startCatchupTestFull(t, catchpointOK, nil, 201, minRoundsToInitialize, catchpointOK)
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
}

func abortCatchupTest(t *testing.T, catchpoint string, expectedCode int) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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
	expectedSourcemap := logic.GetSourceMap([]string{"<body>"}, ops.OffsetToSource)
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
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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

	// Create a program with MaxTealSourceBytes+1 bytes
	// This should fail inside the handler when reading the bytes from the request body.
	largeProgram := []byte(strings.Repeat("a", v2.MaxTealSourceBytes+1))
	tealDisassembleTest(t, largeProgram, 400, "http: request body too large", true)
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
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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
	} else if rec.Code == 400 {
		var response model.ErrorResponse
		data := rec.Body.Bytes()
		err = protocol.DecodeJSON(data, &response)
		require.NoError(t, err, string(data))
		require.Contains(t, response.Message, expResult)
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
	tealDryrunTest(t, &gdr, "json", 400, "unsupported protocol version", true)
	gdr.ProtocolVersion = ""

	ddr := tealDryrunTest(t, &gdr, "json", 200, "PASS", true)
	require.Equal(t, string(protocol.ConsensusFuture), ddr.ProtocolVersion)
	gdr.ProtocolVersion = string(protocol.ConsensusFuture)
	ddr = tealDryrunTest(t, &gdr, "json", 200, "PASS", true)
	require.Equal(t, string(protocol.ConsensusFuture), ddr.ProtocolVersion)

	gdr.Apps[0].Params.ApprovalProgram = failOps.Program
	tealDryrunTest(t, &gdr, "json", 200, "REJECT", true)
	tealDryrunTest(t, &gdr, "msgp", 200, "REJECT", true)
	tealDryrunTest(t, &gdr, "json", 404, "", false)

	// This should fail inside the handler when reading the bytes from the request body.
	gdr.ProtocolVersion = strings.Repeat("a", v2.MaxTealDryrunBytes+1)
	tealDryrunTest(t, &gdr, "json", 400, "http: request body too large", true)
}

func TestAppendParticipationKeys(t *testing.T) {
	partitiontest.PartitionTest(t)

	mockLedger, _, _, _, releasefunc := testingenv(t, 1, 1, true)
	defer releasefunc()
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
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
		mockNode := makeMockNode(mockLedger, t.Name(), expectedErr, cannedStatusReportGolden, false)
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

	singleLeafProof, err := merklearray.ProofDataToSingleLeafProof(string(resp.Hashtype), resp.Proof)
	a.NoError(err)

	a.Equal(uint64(singleLeafProof.TreeDepth), resp.Treedepth)

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
		GenesisID:          genBlk.GenesisID(),
		GenesisHash:        genBlk.GenesisHash(),
		Round:              l.Latest() + 1,
		Branch:             latestBlock.Hash(),
		RewardsState:       latestBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits, logging.Base()),
		UpgradeState:       latestBlock.UpgradeState,
		StateProofTracking: latestBlock.StateProofTracking,
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

func addStateProof(blk bookkeeping.Block) bookkeeping.Block {
	round := uint64(blk.Round())
	stateProofRound := (round/stateProofInterval - 1) * stateProofInterval
	tx := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type:   protocol.StateProofTx,
			Header: transactions.Header{Sender: transactions.StateProofSender, FirstValid: blk.Round()},
			StateProofTxnFields: transactions.StateProofTxnFields{
				StateProofType: 0,
				Message: stateproofmsg.Message{
					BlockHeadersCommitment: []byte{0x0, 0x1, 0x2},
					FirstAttestedRound:     stateProofRound + 1,
					LastAttestedRound:      stateProofRound + stateProofInterval,
				},
			},
		},
	}
	txnib := transactions.SignedTxnInBlock{SignedTxnWithAD: transactions.SignedTxnWithAD{SignedTxn: tx}}
	blk.Payset = append(blk.Payset, txnib)

	updatedStateProofTracking := bookkeeping.StateProofTrackingData{
		StateProofVotersCommitment:  blk.BlockHeader.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		StateProofOnlineTotalWeight: blk.BlockHeader.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		StateProofNextRound:         blk.BlockHeader.StateProofTracking[protocol.StateProofBasic].StateProofNextRound + basics.Round(stateProofInterval),
	}
	blk.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	blk.BlockHeader.StateProofTracking[protocol.StateProofBasic] = updatedStateProofTracking

	return blk
}

func insertRounds(a *require.Assertions, h v2.Handlers, numRounds int) {
	ledger := h.Node.LedgerForAPI()

	firstStateProof := basics.Round(stateProofInterval * 2)
	genBlk, err := ledger.Block(0)
	a.NoError(err)
	genBlk.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	genBlk.BlockHeader.StateProofTracking[protocol.StateProofBasic] = bookkeeping.StateProofTrackingData{
		StateProofVotersCommitment:  nil,
		StateProofOnlineTotalWeight: basics.MicroAlgos{},
		StateProofNextRound:         firstStateProof,
	}

	lastBlk := genBlk
	for i := 0; i < numRounds; i++ {
		blk := newEmptyBlock(a, lastBlk, genBlk, ledger)
		round := uint64(blk.Round())
		// Add a StateProof transaction after half of the interval has passed (128 rounds) and add another 18 round for good measure
		// First StateProof should be 2*Interval, since the first commitment cannot be in genesis
		if blk.Round() > firstStateProof && (round%stateProofInterval == (stateProofInterval/2 + 18)) {
			blk = addStateProof(blk)
		}
		blk.BlockHeader.CurrentProtocol = protocol.ConsensusCurrentVersion
		a.NoError(ledger.(*data.Ledger).AddBlock(blk, agreement.Certificate{}))
		lastBlk = blk
	}
}

func TestStateProofNotFound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	insertRounds(a, handler, 700)

	a.NoError(handler.GetStateProof(ctx, 650))
	a.Equal(404, responseRecorder.Code)
}

func TestStateProofHigherRoundThanLatest(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	a.NoError(handler.GetStateProof(ctx, 2))
	a.Equal(500, responseRecorder.Code)
}

func TestStateProof200(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	insertRounds(a, handler, 1000)

	a.NoError(handler.GetStateProof(ctx, stateProofInterval+1))
	a.Equal(200, responseRecorder.Code)

	stprfResp := model.StateProofResponse{}
	a.NoError(json.Unmarshal(responseRecorder.Body.Bytes(), &stprfResp))

	a.Equal([]byte{0x0, 0x1, 0x2}, stprfResp.Message.BlockHeadersCommitment)
}

func TestHeaderProofRoundTooHigh(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	a.NoError(handler.GetLightBlockHeaderProof(ctx, 2))
	a.Equal(500, responseRecorder.Code)
}

func TestHeaderProofStateProofNotFound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	insertRounds(a, handler, 700)

	a.NoError(handler.GetLightBlockHeaderProof(ctx, 650))
	a.Equal(404, responseRecorder.Code)
}

func TestGetBlockProof200(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	handler, ctx, responseRecorder, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	insertRounds(a, handler, 1000)

	a.NoError(handler.GetLightBlockHeaderProof(ctx, stateProofInterval*2+2))
	a.Equal(200, responseRecorder.Code)

	blkHdrArr, err := stateproof.FetchLightHeaders(handler.Node.LedgerForAPI(), stateProofInterval, basics.Round(stateProofInterval*3))
	a.NoError(err)

	leafproof, err := stateproof.GenerateProofOfLightBlockHeaders(stateProofInterval, blkHdrArr, 1)
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
		blk = addStateProof(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}

	ctx, cncl := context.WithTimeout(context.Background(), time.Minute*2)
	defer cncl()
	txn, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofInterval*2+1), 1000, nil)
	a.NoError(err)
	a.Equal(2*stateProofInterval+1, txn.Message.FirstAttestedRound)
	a.Equal(3*stateProofInterval, txn.Message.LastAttestedRound)
	a.Equal([]byte{0x0, 0x1, 0x2}, txn.Message.BlockHeadersCommitment)

	txn, err = v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(2*stateProofInterval), 1000, nil)
	a.NoError(err)
	a.Equal(stateProofInterval+1, txn.Message.FirstAttestedRound)
	a.Equal(2*stateProofInterval, txn.Message.LastAttestedRound)

	txn, err = v2.GetStateProofTransactionForRound(ctx, &ledger, 999, 1000, nil)
	a.ErrorIs(err, v2.ErrNoStateProofForRound)

	txn, err = v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(2*stateProofInterval), basics.Round(2*stateProofInterval), nil)
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
		blk = addStateProof(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}
	ctx, cncl := context.WithTimeout(context.Background(), time.Minute)
	defer cncl()
	_, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofInterval*2+1), 1000, nil)
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
		blk = addStateProof(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}

	ctx, cncl := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cncl()
	_, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofInterval*2+1), 1000, nil)
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
		blk = addStateProof(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}

	stoppedChan := make(chan struct{})
	close(stoppedChan)
	ctx, cncl := context.WithTimeout(context.Background(), time.Minute)
	defer cncl()
	_, err := v2.GetStateProofTransactionForRound(ctx, &ledger, basics.Round(stateProofInterval*2+1), 1000, stoppedChan)
	a.ErrorIs(err, v2.ErrShutdown)
}

func TestExperimentalCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	// Since we are invoking the method directly, it doesn't matter if EnableExperimentalAPI is true.
	// When this is false, the router never even registers this endpoint.
	err := handler.ExperimentalCheck(c)
	require.NoError(t, err)

	require.Equal(t, 200, rec.Code)
	require.Equal(t, "true\n", string(rec.Body.Bytes()))
}

func TestTimestampOffsetNotInDevMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t, cannedStatusReportGolden)
	defer releasefunc()

	// TestGetBlockTimeStampOffset 400 - offset is not set and mock node is
	// not in dev mode
	err := handler.GetBlockTimeStampOffset(c)
	require.NoError(t, err)
	require.Equal(t, 400, rec.Code)
	require.Equal(t, "{\"message\":\"failed retrieving timestamp offset from node: cannot get block timestamp offset because we are not in dev mode\"}\n", rec.Body.String())
	c, rec = newReq(t)

	// TestSetBlockTimeStampOffset 400 - cannot set timestamp offset when not
	// in dev mode
	err = handler.SetBlockTimeStampOffset(c, 1)
	require.NoError(t, err)
	require.Equal(t, 400, rec.Code)
	require.Equal(t, "{\"message\":\"failed to set timestamp offset on the node: cannot set block timestamp when not in dev mode\"}\n", rec.Body.String())
}

func TestTimestampOffsetInDevMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler, c, rec, _, _, releasefunc := setupMockNodeForMethodGet(t, cannedStatusReportGolden, true)
	defer releasefunc()

	// TestGetBlockTimeStampOffset 404
	err := handler.GetBlockTimeStampOffset(c)
	require.NoError(t, err)
	require.Equal(t, 404, rec.Code)
	require.Equal(t, "{\"message\":\"failed retrieving timestamp offset from node: block timestamp offset was never set, using real clock for timestamps\"}\n", rec.Body.String())
	c, rec = newReq(t)

	// TestSetBlockTimeStampOffset 200
	err = handler.SetBlockTimeStampOffset(c, 1)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	c, rec = newReq(t)

	// TestGetBlockTimeStampOffset 200
	err = handler.GetBlockTimeStampOffset(c)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
	c, rec = newReq(t)

	// TestSetBlockTimeStampOffset 400
	err = handler.SetBlockTimeStampOffset(c, math.MaxUint64)
	require.NoError(t, err)
	require.Equal(t, 400, rec.Code)
	require.Equal(t, "{\"message\":\"failed to set timestamp offset on the node: block timestamp offset cannot be larger than max int64 value\"}\n", rec.Body.String())
}

func TestDeltasForTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	blk1 := bookkeeping.BlockHeader{Round: 1}
	blk2 := bookkeeping.BlockHeader{Round: 2}
	delta1 := ledgercore.StateDelta{Hdr: &blk1}
	delta2 := ledgercore.StateDelta{Hdr: &blk2, KvMods: map[string]ledgercore.KvValueDelta{"bx1": {Data: []byte("foobar")}}}
	txn1 := transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: transactions.Transaction{Type: protocol.PaymentTx}}}
	groupID1, err := crypto.DigestFromString(crypto.Hash([]byte("hello")).String())
	require.NoError(t, err)
	txn2 := transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: transactions.Transaction{
		Type:   protocol.AssetTransferTx,
		Header: transactions.Header{Group: groupID1}},
	}}

	tracer := eval.MakeTxnGroupDeltaTracer(2)
	handlers := v2.Handlers{
		Node: &mockNode{
			ledger: &mockLedger{
				tracer: tracer,
			},
		},
		Log: logging.Base(),
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// Add blocks to tracer
	tracer.BeforeBlock(&blk1)
	tracer.AfterTxnGroup(&logic.EvalParams{TxnGroup: []transactions.SignedTxnWithAD{txn1}}, &delta1, nil)
	tracer.BeforeBlock(&blk2)
	tracer.AfterTxnGroup(&logic.EvalParams{TxnGroup: []transactions.SignedTxnWithAD{txn2}}, &delta2, nil)

	// Test /v2/deltas/{round}/txn/group
	jsonFormatForRound := model.GetTransactionGroupLedgerStateDeltasForRoundParamsFormatJson
	err = handlers.GetTransactionGroupLedgerStateDeltasForRound(
		c,
		uint64(1),
		model.GetTransactionGroupLedgerStateDeltasForRoundParams{Format: &jsonFormatForRound},
	)
	require.NoError(t, err)

	var roundResponse model.TransactionGroupLedgerStateDeltasForRoundResponse
	err = json.Unmarshal(rec.Body.Bytes(), &roundResponse)
	require.NoError(t, err)
	require.Equal(t, 1, len(roundResponse.Deltas))
	require.Equal(t, []string{txn1.ID().String()}, roundResponse.Deltas[0].Ids)
	hdr, ok := roundResponse.Deltas[0].Delta["Hdr"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, delta1.Hdr.Round, basics.Round(hdr["rnd"].(float64)))

	// Test invalid round parameter
	c, rec = newReq(t)
	err = handlers.GetTransactionGroupLedgerStateDeltasForRound(
		c,
		uint64(4),
		model.GetTransactionGroupLedgerStateDeltasForRoundParams{Format: &jsonFormatForRound},
	)
	require.NoError(t, err)
	require.Equal(t, 404, rec.Code)

	// Test /v2/deltas/txn/group/{id}
	jsonFormatForTxn := model.GetLedgerStateDeltaForTransactionGroupParamsFormatJson
	c, rec = newReq(t)
	// Use TxID
	err = handlers.GetLedgerStateDeltaForTransactionGroup(
		c,
		txn2.Txn.ID().String(),
		model.GetLedgerStateDeltaForTransactionGroupParams{Format: &jsonFormatForTxn},
	)
	require.NoError(t, err)
	var groupResponse model.LedgerStateDeltaForTransactionGroupResponse
	err = json.Unmarshal(rec.Body.Bytes(), &groupResponse)
	require.NoError(t, err)
	groupHdr, ok := groupResponse["Hdr"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, delta2.Hdr.Round, basics.Round(groupHdr["rnd"].(float64)))

	// Use Group ID
	c, rec = newReq(t)
	err = handlers.GetLedgerStateDeltaForTransactionGroup(
		c,
		groupID1.String(),
		model.GetLedgerStateDeltaForTransactionGroupParams{Format: &jsonFormatForTxn},
	)
	require.NoError(t, err)
	err = json.Unmarshal(rec.Body.Bytes(), &groupResponse)
	require.NoError(t, err)
	require.NotNil(t, groupResponse["KvMods"])
	groupHdr, ok = groupResponse["Hdr"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, delta2.Hdr.Round, basics.Round(groupHdr["rnd"].(float64)))

	// Test invalid ID
	c, rec = newReq(t)
	badID := crypto.Hash([]byte("invalidID")).String()
	err = handlers.GetLedgerStateDeltaForTransactionGroup(
		c,
		badID,
		model.GetLedgerStateDeltaForTransactionGroupParams{Format: &jsonFormatForTxn},
	)
	require.NoError(t, err)
	require.Equal(t, 404, rec.Code)

	// Test nil Tracer
	nilTracerHandler := v2.Handlers{
		Node: &mockNode{
			ledger: &mockLedger{
				tracer: nil,
			},
		},
		Log: logging.Base(),
	}
	c, rec = newReq(t)
	err = nilTracerHandler.GetLedgerStateDeltaForTransactionGroup(
		c,
		groupID1.String(),
		model.GetLedgerStateDeltaForTransactionGroupParams{Format: &jsonFormatForTxn},
	)
	require.NoError(t, err)
	require.Equal(t, 501, rec.Code)

	c, rec = newReq(t)
	err = nilTracerHandler.GetTransactionGroupLedgerStateDeltasForRound(
		c,
		0,
		model.GetTransactionGroupLedgerStateDeltasForRoundParams{Format: &jsonFormatForRound},
	)
	require.NoError(t, err)
	require.Equal(t, 501, rec.Code)
}

func TestRouterRequestBody(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	mockLedger, _, _, _, _ := testingenv(t, 1, 1, true)
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
	dummyShutdownChan := make(chan struct{})
	l, err := net.Listen("tcp", ":0") // create listener so requests are buffered
	e := server.NewRouter(logging.TestingLog(t), mockNode, dummyShutdownChan, "", "", l, 1000)
	go e.Start(":0")
	defer e.Close()

	// Admin API call greater than max body bytes should succeed
	assert.Equal(t, "10MB", server.MaxRequestBodyBytes)
	stringReader := strings.NewReader(strings.Repeat("a", 50_000_000))
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/v2/participation", e.Listener.Addr().String()), stringReader)
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Public API call greater than max body bytes fails
	assert.Equal(t, "10MB", server.MaxRequestBodyBytes)
	stringReader = strings.NewReader(strings.Repeat("a", 50_000_000))
	req, err = http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/v2/transactions", e.Listener.Addr().String()), stringReader)
	assert.NoError(t, err)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestGeneratePartkeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
	handler := v2.Handlers{
		Node:          mockNode,
		Log:           logging.Base(),
		Shutdown:      dummyShutdownChan,
		KeygenLimiter: semaphore.NewWeighted(1),
	}
	e := echo.New()

	var addr basics.Address
	addr[0] = 1

	{
		require.Len(t, mockNode.PartKeyBinary, 0)
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.GenerateParticipationKeys(c, addr.String(), model.GenerateParticipationKeysParams{
			First: 1000,
			Last:  2000,
		})

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Wait for keygen to complete
		err = handler.KeygenLimiter.Acquire(context.Background(), 1)
		require.NoError(t, err)
		require.Greater(t, len(mockNode.PartKeyBinary), 0)
		handler.KeygenLimiter.Release(1)
	}

	{
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		// Simulate a blocked keygen process (and block until the previous keygen is complete)
		err := handler.KeygenLimiter.Acquire(context.Background(), 1)
		require.NoError(t, err)
		err = handler.GenerateParticipationKeys(c, addr.String(), model.GenerateParticipationKeysParams{
			First: 1000,
			Last:  2000,
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	}

}
