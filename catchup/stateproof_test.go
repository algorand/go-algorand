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

package catchup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestServiceStateProofFetcherRenaissance(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Make Ledgers
	remote, _, blk, spdata, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, spdata, 1000)

	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	ls.RegisterHandlers(&nodeA)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: -1}, nil, nil, nil)
	syncer.testStart()

	provenWeight, overflowed := basics.Muldiv(spdata.TotalWeight.ToUint64(), uint64(spdata.Params.StateProofWeightThreshold), 1<<32)
	require.False(t, overflowed)

	lnProvenWt, err := stateproof.LnIntApproximation(provenWeight)
	require.NoError(t, err)

	syncer.SetRenaissance(StateProofVerificationContext{
		LastRound:        256,
		LnProvenWeight:   lnProvenWt,
		VotersCommitment: spdata.Tree.Root(),
		Proto:            blk.CurrentProtocol,
	})

	ctx := context.Background()
	syncer.startStateProofFetcher(ctx)

	ch := syncer.stateProofWait(500)
	<-ch

	msg := syncer.getStateProof(500)
	require.NotNil(t, msg)

	ch = syncer.stateProofWait(5000)
	<-ch

	msg = syncer.getStateProof(5000)
	require.Nil(t, msg)
}

func TestServiceStateProofSync(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Make Ledgers
	var blk0 bookkeeping.Block
	blk0.CurrentProtocol = protocol.ConsensusFuture
	remote, _, blk, spdata, err := buildTestLedger(t, blk0)
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, spdata, 1000)

	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	ls.RegisterHandlers(&nodeA)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: -1}, nil, nil, nil)
	syncer.testStart()

	provenWeight, overflowed := basics.Muldiv(spdata.TotalWeight.ToUint64(), uint64(spdata.Params.StateProofWeightThreshold), 1<<32)
	require.False(t, overflowed)

	lnProvenWt, err := stateproof.LnIntApproximation(provenWeight)
	require.NoError(t, err)

	syncer.SetRenaissance(StateProofVerificationContext{
		LastRound:        256,
		LnProvenWeight:   lnProvenWt,
		VotersCommitment: spdata.Tree.Root(),
		Proto:            blk.CurrentProtocol,
	})

	syncer.sync()

	rr, lr := remote.LastRound(), local.LastRound()
	require.Equal(t, rr, lr)

	// Block 500 should have been fetched using state proofs, which means
	// we should have no cert in the local ledger.
	_, cert, err := local.BlockCert(500)
	require.NoError(t, err)
	require.True(t, cert.MsgIsZero())

	// Block 900 should have been fetched using certs, which means
	// we should have a valid cert for it in the ledger.
	_, cert, err = local.BlockCert(900)
	require.NoError(t, err)
	require.Equal(t, cert.Round, basics.Round(900))

	// Now try to sync again, which should flush all of the state proofs already
	// covered by the local ledger (which is ahead of the state proofs now).
	syncer.sync()

	// Now extend the remote ledger, and make sure that the local ledger can sync
	// using state proofs starting from the most recent ledger-generated state
	// proof verification context.
	addBlocks(t, remote, spdata.TemplateBlock, spdata, 1000)
	syncer.sync()

	_, cert, err = local.BlockCert(1500)
	require.NoError(t, err)
	require.True(t, cert.MsgIsZero())

	_, cert, err = local.BlockCert(1900)
	require.NoError(t, err)
	require.Equal(t, cert.Round, basics.Round(1900))
}
