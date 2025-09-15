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

package gossip

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util"
)

const testNetTimeout = 100 * time.Millisecond

func TestMain(m *testing.M) {

	logging.Base().SetLevel(logging.Debug)
	// increase limit on max allowed number of sockets
	err := util.SetFdSoftLimit(500)
	if err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// create a fully connected network of size `nodesCount`
func spinNetwork(t *testing.T, nodesCount int, cfg config.Local) ([]*networkImpl, []*messageCounter) {
	cfg.GossipFanout = nodesCount - 1
	cfg.NetAddress = "127.0.0.1:0"
	cfg.IncomingMessageFilterBucketCount = 5
	cfg.IncomingMessageFilterBucketSize = 32
	cfg.OutgoingMessageFilterBucketCount = 3
	cfg.OutgoingMessageFilterBucketSize = 32
	cfg.EnableOutgoingNetworkMessageFiltering = false
	cfg.DNSBootstrapID = "" // prevent attempts of getting bootstrap SRV from DNS server(s)

	log := logging.TestingLog(t)
	start := time.Now()
	nodesAddresses := []string{}
	gossipNodes := []network.GossipNode{}
	for nodeIdx := 0; nodeIdx < nodesCount; nodeIdx++ {
		gossipNode, err := network.NewWebsocketGossipNode(log.With("node", nodeIdx), cfg, nodesAddresses, "go-test-agreement-network-genesis", config.Devtestnet)
		if err != nil {
			t.Fatalf("fail making ws node: %v", err)
		}
		gossipNode.Start()
		address, _ := gossipNode.Address()
		log.Debugf("node[%d] addr=%#v", nodeIdx, address)
		nodesAddresses = append(nodesAddresses, address)
		gossipNodes = append(gossipNodes, gossipNode)
	}

	for _, gossipNode := range gossipNodes {
		gossipNode.RequestConnectOutgoing(false, nil) // no disconnect.
	}

	networkImpls := []*networkImpl{}
	msgCounters := []*messageCounter{}
	for _, gossipNode := range gossipNodes {
		networkImpl := WrapNetwork(gossipNode, log, cfg).(*networkImpl)
		networkImpls = append(networkImpls, networkImpl)
		networkImpl.Start()
		msgCounter := startMessageCounter(networkImpl)
		msgCounters = append(msgCounters, msgCounter)
	}

	// wait until a 2-way connection was established across all the nodes
	for {
		keepWaiting := false
		for nodeIdx, gossipNode := range gossipNodes {
			numPeers := gossipNode.(*network.WebsocketNetwork).NumPeers()
			if numPeers < (nodesCount - 1) {
				log.Debugf("node[%d] have %d peers want %d", nodeIdx, numPeers, nodesCount-1)
				keepWaiting = true
				break
			}
		}
		if keepWaiting {
			time.Sleep(50 * time.Millisecond)
		} else {
			break
		}
	}
	log.Infof("network established, %d nodes connected in %s", nodesCount, time.Since(start).String())
	return networkImpls, msgCounters
}

func shutdownNetwork(nets []*networkImpl, counters []*messageCounter) {
	wg := &sync.WaitGroup{}
	wg.Add(len(nets))
	for _, net := range nets {
		go func(net network.GossipNode) {
			defer wg.Done()
			net.ClearHandlers()
			net.Stop()
		}(net.net)
	}
	for _, counter := range counters {
		counter.stop()
	}
	wg.Wait()
}

func TestNetworkImplFullStackLong(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}

	testNetworkImplFull(t, 10)
}

func TestNetworkImplFullStackQuick(t *testing.T) {
	partitiontest.PartitionTest(t)

	if !testing.Short() {
		t.Skip()
	}

	testNetworkImplFull(t, 5)
}

func testNetworkImplAgreementVote(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	nets[0].Broadcast(protocol.AgreementVoteTag, []byte{1})
	for i, counter := range counters {
		if i != 0 {
			if !counter.verify(t, 1, 0, 0) {
				writeDetailedErrorInfo(t, i, nets)
				return
			}
		} else if !counter.verify(t, 0, 0, 0) {
			return
		}
	}
}

func testNetworkImplProposalPayload(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	nets[0].Broadcast(protocol.ProposalPayloadTag, []byte{1})
	for i, counter := range counters {
		if i != 0 {
			if !counter.verify(t, 0, 1, 0) {
				writeDetailedErrorInfo(t, i, nets)
				return
			}
		} else if !counter.verify(t, 0, 0, 0) {
			return
		}
	}
}

func testNetworkImplVoteBundle(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	nets[0].Broadcast(protocol.VoteBundleTag, []byte{1})
	for i, counter := range counters {
		if i != 0 {
			if !counter.verify(t, 0, 0, 1) {
				writeDetailedErrorInfo(t, i, nets)
				return
			}
		} else if !counter.verify(t, 0, 0, 0) {
			return
		}
	}
}

func testNetworkImplMixed(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	nets[0].Broadcast(protocol.AgreementVoteTag, []byte{1})
	nets[0].Broadcast(protocol.ProposalPayloadTag, []byte{1})
	nets[0].Broadcast(protocol.ProposalPayloadTag, []byte{1})
	nets[0].Broadcast(protocol.VoteBundleTag, []byte{1})
	nets[0].Broadcast(protocol.VoteBundleTag, []byte{1})
	nets[0].Broadcast(protocol.VoteBundleTag, []byte{1})
	for i, counter := range counters {
		if i != 0 {
			if !counter.verify(t, 1, 2, 3) {
				writeDetailedErrorInfo(t, i, nets)
				return
			}
		} else if !counter.verify(t, 0, 0, 0) {
			return
		}
	}
}

func testNetworkImplMixed2(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	const loadSize = 12
	for i := byte(0); i < loadSize; i++ {
		ok := nets[0].Broadcast(protocol.AgreementVoteTag, []byte{i})
		assert.NoError(t, ok)
		if i%2 == 0 {
			ok = nets[0].Broadcast(protocol.ProposalPayloadTag, []byte{i})
			assert.NoError(t, ok)
		}
		if i%4 == 0 {
			ok = nets[0].Broadcast(protocol.VoteBundleTag, []byte{i})
			assert.NoError(t, ok)
		}
	}
	for i, counter := range counters {
		if i != 0 {
			if !counter.verify(t, loadSize, loadSize/2, loadSize/4) {
				writeDetailedErrorInfo(t, i, nets)
				t.Logf("fail counter=%#v", counter)

				return
			}
		} else if !counter.verify(t, 0, 0, 0) {
			return
		}
	}
}

func testNetworkImplReordered(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	sendStart := time.Now()
	const loadSize = 12
	// repeat in parallel.
	wg := &sync.WaitGroup{}
	wg.Add(loadSize)
	for i := byte(0); i < loadSize; i++ {
		go func(i byte) {
			ok := nets[0].Broadcast(protocol.AgreementVoteTag, []byte{i})
			assert.NoError(t, ok)
			if i%2 == 0 {
				ok = nets[0].Broadcast(protocol.ProposalPayloadTag, []byte{i})
				assert.NoError(t, ok)
			}
			if i%4 == 0 {
				ok = nets[0].Broadcast(protocol.VoteBundleTag, []byte{i})
				assert.NoError(t, ok)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	sendEnd := time.Now()
	sendTime := sendEnd.Sub(sendStart)
	t.Logf("sent %d in %s", loadSize, sendTime.String())
	for i, counter := range counters {
		if i != 0 {
			if !counter.verify(t, loadSize, loadSize/2, loadSize/4) {
				writeDetailedErrorInfo(t, i, nets)
				return
			}
		} else if !counter.verify(t, 0, 0, 0) {
			return
		}
	}
}

func testNetworkImplMultisource(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	for i := byte(0); i < byte(nodesCount); i++ {
		nets[i].Broadcast(protocol.AgreementVoteTag, []byte{i})
	}
	for i, counter := range counters {
		if !counter.verify(t, uint32(nodesCount-1), 0, 0) {
			writeDetailedErrorInfo(t, i, nets)
			return
		}
	}
}

func testNetworkImplRebroadcast(t *testing.T, nodesCount int, cfg config.Local) {
	t.Logf("%s start", t.Name())
	defer t.Logf("%s end", t.Name())
	nets, counters := spinNetwork(t, nodesCount, cfg)
	defer shutdownNetwork(nets, counters)

	rebroadcastNodes := min(nodesCount, 3)
	for i := byte(0); i < byte(rebroadcastNodes); i++ {
		ok := nets[i].Broadcast(protocol.AgreementVoteTag, []byte{i, i + 1})
		assert.NoError(t, ok)
	}

	for i, counter := range counters {
		if i >= rebroadcastNodes {
			if !counter.verify(t, uint32(rebroadcastNodes), uint32((nodesCount-2)*rebroadcastNodes), 0) {
				writeDetailedErrorInfo(t, i, nets)
				return
			}
		} else {
			if !counter.verify(t, uint32(rebroadcastNodes-1), uint32((nodesCount-2)*rebroadcastNodes+1), 0) {
				writeDetailedErrorInfo(t, i, nets)
				return
			}
		}
	}
}

func writeDetailedErrorInfo(t *testing.T, i int, nets []*networkImpl) {
	address, _ := nets[i].net.Address()
	t.Errorf("failed on i=%d address %+v\n", i, address)
	for _, n := range nets {
		address, _ := n.net.Address()
		t.Errorf("node %v\n", address)
	}
}

func testNetworkImplFull(t *testing.T, nodesCount int) {
	// We crank up the buffer sizes so that we can just send a
	// bunch of messages and then wait for them to all filter
	// through. Production code will drop messages sometimes,
	// which is a different test of logic that agremeent needs to
	// deal with.
	cfg := config.GetDefaultLocal()
	cfg.MaxConnectionsPerIP = nodesCount
	cfg.AgreementIncomingVotesQueueLength = 100
	cfg.AgreementIncomingProposalsQueueLength = 100
	cfg.AgreementIncomingBundlesQueueLength = 100
	t.Run("AgreementVoteTag", func(t *testing.T) {
		testNetworkImplAgreementVote(t, nodesCount, cfg)
	})

	t.Run("ProposalPayloadTag", func(t *testing.T) {
		testNetworkImplProposalPayload(t, nodesCount, cfg)
	})

	t.Run("VoteBundleTag", func(t *testing.T) {
		testNetworkImplVoteBundle(t, nodesCount, cfg)
	})

	t.Run("MixedTags", func(t *testing.T) {
		testNetworkImplMixed(t, nodesCount, cfg)
	})

	t.Run("MixedTags2", func(t *testing.T) {
		testNetworkImplMixed2(t, nodesCount, cfg)
	})

	t.Run("Reordered", func(t *testing.T) {
		testNetworkImplReordered(t, nodesCount, cfg)
	})

	t.Run("Multisource", func(t *testing.T) {
		testNetworkImplMultisource(t, nodesCount, cfg)
	})

	t.Run("Rebroadcast", func(t *testing.T) {
		testNetworkImplRebroadcast(t, nodesCount, cfg)
	})
}
