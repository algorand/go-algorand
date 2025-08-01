// Copyright (C) 2019-2025 Algorand, Inc.
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type catchpointCatchupLedger struct {
}

func (l *catchpointCatchupLedger) BlockCert(rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	blk = bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
		},
	}
	cert = agreement.Certificate{}
	commitments, err := blk.PaysetCommit()
	if err != nil {
		return blk, cert, err
	}
	blk.TxnCommitments = commitments

	return blk, cert, nil
}

func (l *catchpointCatchupLedger) GenesisHash() (d crypto.Digest) {
	return
}

func (l *catchpointCatchupLedger) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	return
}

func (l *catchpointCatchupLedger) Latest() (rnd basics.Round) {
	return
}

type catchpointCatchupAccessorMock struct {
	mocks.MockCatchpointCatchupAccessor
	l *catchpointCatchupLedger
}

func (m *catchpointCatchupAccessorMock) GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error) {
	return 1, nil
}

func (m *catchpointCatchupAccessorMock) Ledger() (l ledger.CatchupAccessorClientLedger) {
	return m.l
}

// GetVerifyData returns the balances hash, spver hash and totals used by VerifyCatchpoint
func (m *catchpointCatchupAccessorMock) GetVerifyData(ctx context.Context) (balancesHash, spverHash, onlineAccountsHash, onlineRoundParamsHash crypto.Digest, totals ledgercore.AccountTotals, err error) {
	return crypto.Digest{}, crypto.Digest{}, crypto.Digest{}, crypto.Digest{}, ledgercore.AccountTotals{}, nil
}

// TestCatchpointServicePeerRank ensures CatchpointService does not crash when a block fetched
// from the local ledger and not from network when ranking a peer
func TestCatchpointServicePeerRank(t *testing.T) {
	partitiontest.PartitionTest(t)

	l := catchpointCatchupLedger{}
	a := catchpointCatchupAccessorMock{l: &l}
	cs := CatchpointCatchupService{ledgerAccessor: &a, ledger: &l}
	cs.initDownloadPeerSelector()

	err := cs.processStageLatestBlockDownload()
	require.NoError(t, err)
}

type catchpointAccessorMock struct {
	mocks.MockCatchpointCatchupAccessor
	t      *testing.T
	topBlk bookkeeping.Block
}

func (m *catchpointAccessorMock) EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error) {
	return m.topBlk, nil
}

func (m *catchpointAccessorMock) StoreBlock(ctx context.Context, blk *bookkeeping.Block, cert *agreement.Certificate) (err error) {
	require.NotNil(m.t, blk)
	require.NotNil(m.t, cert)
	return nil
}

type catchpointCatchupLedger2 struct {
	catchpointCatchupLedger
	blk bookkeeping.Block
}

func (l *catchpointCatchupLedger2) BlockCert(rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	return l.blk, agreement.Certificate{}, nil
}

// TestProcessStageBlocksDownloadNilCert ensures StoreBlock does not receive a nil certificate when ledger has already had a block.
// It uses two mocks catchpointAccessorMock and catchpointCatchupLedger2 and pre-crafted blocks to make a single iteration of processStageBlocksDownload.
func TestProcessStageBlocksDownloadNilCert(t *testing.T) {
	partitiontest.PartitionTest(t)

	var err error
	blk1 := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round: 1,
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
		},
	}
	blk1.TxnCommitments, err = blk1.PaysetCommit()
	require.NoError(t, err)

	blk2 := blk1
	blk2.BlockHeader.Round = 2
	blk2.BlockHeader.Branch = blk1.Hash()
	blk2.BlockHeader.Branch512 = blk1.Hash512()
	blk2.TxnCommitments, err = blk2.PaysetCommit()
	require.NoError(t, err)

	ctx, cf := context.WithCancel(context.Background())
	cs := CatchpointCatchupService{
		ctx:            ctx,
		cancelCtxFunc:  cf,
		ledgerAccessor: &catchpointAccessorMock{topBlk: blk2, t: t},
		ledger:         &catchpointCatchupLedger2{blk: blk1},
		log:            logging.TestingLog(t),
	}

	err = cs.processStageBlocksDownload()
	require.NoError(t, err)
}
