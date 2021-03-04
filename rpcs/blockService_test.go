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

package rpcs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

type mockUnicastPeer struct {
	responseTopics network.Topics
}

func (mup *mockUnicastPeer) GetAddress() string {
	return ""
}
func (mup *mockUnicastPeer) Unicast(ctx context.Context, data []byte, tag protocol.Tag) error {
	return nil
}
func (mup *mockUnicastPeer) Version() string {
	return "2.1"
}
func (mup *mockUnicastPeer) Request(ctx context.Context, tag network.Tag, topics network.Topics) (resp *network.Response, e error) {
	return nil, nil
}
func (mup *mockUnicastPeer) Respond(ctx context.Context, reqMsg network.IncomingMessage, topics network.Topics) (e error) {
	mup.responseTopics = topics
	return nil
}

// TestHandleCatchupReqNegative covers the error reporting in handleCatchupReq
func TestHandleCatchupReqNegative(t *testing.T) {

	reqMsg := network.IncomingMessage{
		Sender: &mockUnicastPeer{},
		Data:   nil, // topics
	}
	ls := BlockService{
		ledger: nil,
	}

	// case where topics is nil
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics := reqMsg.Sender.(*mockUnicastPeer).responseTopics
	val, found := respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, "UnmarshallTopics: could not read the number of topics", string(val))

	// case where round number is missing
	reqTopics := network.Topics{}
	reqMsg.Data = reqTopics.MarshallTopics()
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics = reqMsg.Sender.(*mockUnicastPeer).responseTopics

	val, found = respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, noRoundNumberErrMsg, string(val))

	// case where data type is missing
	roundNumberData := make([]byte, 0)
	reqTopics = network.Topics{network.MakeTopic(RoundKey, roundNumberData)}
	reqMsg.Data = reqTopics.MarshallTopics()
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics = reqMsg.Sender.(*mockUnicastPeer).responseTopics

	val, found = respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, noDataTypeErrMsg, string(val))

	// case where round number is corrupted
	roundNumberData = make([]byte, 0)
	reqTopics = network.Topics{network.MakeTopic(RoundKey, roundNumberData),
		network.MakeTopic(RequestDataTypeKey, []byte(BlockAndCertValue)),
	}
	reqMsg.Data = reqTopics.MarshallTopics()
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics = reqMsg.Sender.(*mockUnicastPeer).responseTopics

	val, found = respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, roundNumberParseErrMsg, string(val))
}
