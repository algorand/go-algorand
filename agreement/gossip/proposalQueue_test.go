// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type queueTestPeer struct{ addr []byte }

func (p queueTestPeer) GetNetwork() network.GossipNode { return nil }
func (p queueTestPeer) RoutingAddr() []byte            { return p.addr }

// TestProposalQueueSourceIsRoutingAddr checks that proposals are queued by
// the RoutingAddr of their sender, so that two connections from one address
// share one turn.
func TestProposalQueueSourceIsRoutingAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	i := WrapNetwork(nil, logging.TestingLog(t), config.GetDefaultLocal()).(*networkImpl)
	// Two connections from the same address, distinct peer values.
	connA1 := queueTestPeer{addr: []byte{10, 0, 0, 1}}
	connA2 := queueTestPeer{addr: []byte{10, 0, 0, 1}}
	connB := queueTestPeer{addr: []byte{10, 0, 0, 2}}
	connC := queueTestPeer{addr: []byte{10, 0, 0, 3}}
	for _, raw := range []network.IncomingMessage{
		{Sender: connA1, Tag: protocol.ProposalPayloadTag, Data: []byte("a0")},
		{Sender: connA2, Tag: protocol.ProposalPayloadTag, Data: []byte("a1")},
		{Sender: connB, Tag: protocol.ProposalPayloadTag, Data: []byte("b0")},
		{Sender: connC, Tag: protocol.ProposalPayloadTag, Data: []byte("c0")},
	} {
		i.processProposalMessage(raw)
	}

	// a1 waits for a's next turn, after b and c.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var got []string
	for range 4 {
		m, ok := i.NextProposal(ctx)
		require.True(t, ok)
		got = append(got, string(m.Data))
	}
	require.Equal(t, []string{"a0", "b0", "c0", "a1"}, got)
}
