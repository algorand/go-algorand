// Copyright (C) 2019-2021 Algorand, Inc.
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

package txnsync

import (
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/timers"
)

type mockLogger struct {
	logging.Logger
}

type mockNodeConnector struct {
	NodeConnector
	calledEvents        *bool
	peerInfo            PeerInfo
	updatingPeers       bool
	transactionPoolSize int
}

func makeMockNodeConnector(calledEvents *bool) mockNodeConnector {
	return mockNodeConnector{calledEvents: calledEvents}
}

func (fn *mockNodeConnector) Events() <-chan Event {
	*fn.calledEvents = true
	return nil
}

func (fn *mockNodeConnector) GetCurrentRoundSettings() (out RoundSettings) { return }

func (fn *mockNodeConnector) Clock() (out timers.WallClock) {
	return timers.MakeMonotonicClock(time.Now())
}

func (fn *mockNodeConnector) Random(rng uint64) uint64 {
	var xb [8]byte
	rand.Read(xb[:])
	rv := binary.LittleEndian.Uint64(xb[:])
	return rv % rng
}

func (fn *mockNodeConnector) GetPeers() []PeerInfo { return nil }

func (fn *mockNodeConnector) GetPeer(interface{}) (out PeerInfo) {
	return fn.peerInfo
}

func (fn *mockNodeConnector) UpdatePeers(txsyncPeers []*Peer, netPeers []interface{}, peersAverageDataExchangeRate uint64) {
	fn.updatingPeers = true
}
func (fn *mockNodeConnector) SendPeerMessage(netPeer interface{}, msg []byte, callback SendMessageCallback) {
}
func (fn *mockNodeConnector) GetPendingTransactionGroups() (txGroups []transactions.SignedTxGroup, latestLocallyOriginatedGroupCounter uint64) {
	return
}
func (fn *mockNodeConnector) IncomingTransactionGroups(peer *Peer, messageSeq uint64, txGroups []transactions.SignedTxGroup) (transactionPoolSize int) {
	return fn.transactionPoolSize
}
func (fn *mockNodeConnector) NotifyMonitor() chan struct{} { return nil }

func (fn *mockNodeConnector) RelayProposal(proposalBytes []byte, txnSlices []transactions.SignedTxnSlice) {}

func (fn *mockNodeConnector) HandleProposalMessage(proposalDataBytes []byte, txGroups []transactions.SignedTxGroup, peer *Peer) {}

type mockThreadPool struct {
	execpool.BacklogPool
}

// TestStartStopTransactionSyncService test that we can start and stop the transaction sync service
func TestStartStopTransactionSyncService(t *testing.T) {

	calledEventsInNodeConnector := false

	a := require.New(t)

	mLogger := mockLogger{}
	mNodeConnector := makeMockNodeConnector(&calledEventsInNodeConnector)
	cfg := config.GetDefaultLocal()
	mThreadPool := mockThreadPool{}

	hashDigest := crypto.Hash([]byte{0x41, 0x6b, 0x69, 0x6b, 0x69})

	service := MakeTransactionSyncService(mLogger, &mNodeConnector, true, "GENID", hashDigest, cfg, mThreadPool)

	a.NotNil(service)

	service.Start()
	service.Stop()

	a.True(calledEventsInNodeConnector)

	a.Nil(service.cancelCtx)
	a.Nil(service.ctx)

}

// TestMakeTransactionSyncService tests that an appropriate transaction sync service was made
func TestMakeTransactionSyncService(t *testing.T) {

	a := require.New(t)

	mLogger := mockLogger{}
	mNodeConnector := &mockNodeConnector{}
	cfg := config.GetDefaultLocal()
	mThreadPool := mockThreadPool{}

	hashDigest := crypto.Hash([]byte{0x41, 0x6b, 0x69, 0x6b, 0x69})

	service1 := MakeTransactionSyncService(mLogger, mNodeConnector, true, "GENID", hashDigest, cfg, mThreadPool)

	a.NotNil(service1)

	a.Equal(service1.state.node, mNodeConnector)
	a.Equal(service1.state.log, wrapLogger(mLogger, &cfg))
	a.Equal(service1.state.isRelay, true)
	a.Equal(service1.state.genesisID, "GENID")
	a.Equal(service1.state.genesisHash, hashDigest)
	a.Equal(service1.state.config, cfg)
	a.Equal(service1.state.threadpool, mThreadPool)
	a.Equal(service1.state.service, service1)
	a.Equal(service1.state.xorBuilder.MaxIterations, 10)

	service2 := MakeTransactionSyncService(mLogger, mNodeConnector, false, "GENID2", hashDigest, cfg, mThreadPool)

	a.NotNil(service1)

	a.Equal(service2.state.node, mNodeConnector)
	a.Equal(service2.state.log, wrapLogger(mLogger, &cfg))
	a.Equal(service2.state.isRelay, false)
	a.Equal(service2.state.genesisID, "GENID2")
	a.Equal(service2.state.genesisHash, hashDigest)
	a.Equal(service2.state.config, cfg)
	a.Equal(service2.state.threadpool, mThreadPool)
	a.Equal(service2.state.service, service2)
	a.Equal(service2.state.xorBuilder.MaxIterations, 10)

}
