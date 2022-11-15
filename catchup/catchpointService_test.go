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

package catchup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type catchpointCatchupLedger struct {
}

func (l *catchpointCatchupLedger) Block(rnd basics.Round) (blk bookkeeping.Block, err error) {
	blk = bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
		},
	}
	commitments, err := blk.PaysetCommit()
	if err != nil {
		return blk, err
	}
	blk.TxnCommitments = commitments

	return blk, nil
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
