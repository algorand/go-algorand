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

package agreement

import (
	"encoding/base64"
	"testing"

	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// This test is only necessary for transition to msgp encoding
// of the player state machine for agreement persistence
func TestProposalTableMsgpEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	type messageMetadata struct {
		raw network.IncomingMessage
	}
	encoded, err := base64.StdEncoding.DecodeString("gqdQZW5kaW5ngQGHqUNhbmNlbGxlZMKjRXJywKVJbnB1dImmQnVuZGxlgK9Db21wb3VuZE1lc3NhZ2WCqFByb3Bvc2FsgKRWb3RlgK1NZXNzYWdlSGFuZGxlgKhQcm9wb3NhbICjVGFnolBQtVVuYXV0aGVudGljYXRlZEJ1bmRsZYC3VW5hdXRoZW50aWNhdGVkUHJvcG9zYWyAs1VuYXV0aGVudGljYXRlZFZvdGWApFZvdGWApVByb3RvgqNFcnLAp1ZlcnNpb26goVQApFRhaWzAqVRhc2tJbmRleD+rUGVuZGluZ05leHQB")
	require.NoError(t, err)

	// run on master a3e90ad to get the encoded data for above
	// pt := proposalTable{}
	// msg := messageEvent{
	// 	Input: message{
	// 		Tag:           protocol.ProposalPayloadTag,
	// 		MessageHandle: &messageMetadata{raw: network.IncomingMessage{Tag: protocol.Tag("mytag"), Data: []byte("some data")}},
	// 	},
	// 	TaskIndex: 63}
	// pt.push(&msg)
	// result := protocol.EncodeReflect(&pt)
	// fmt.Println(base64.StdEncoding.EncodeToString(result))

	var ptMsgp, ptReflect proposalTable
	err = protocol.Decode(encoded, &ptMsgp)
	require.NoError(t, err)
	err = protocol.DecodeReflect(encoded, &ptReflect)
	require.NoError(t, err)

	msgMsgp := ptMsgp.pop(ptMsgp.PendingNext)
	msgReflect := ptReflect.pop(ptReflect.PendingNext)

	// After setting MessageHandle to nil they should be the same
	msgMsgp.Input.MessageHandle = nil
	msgReflect.Input.MessageHandle = nil
	require.Equal(t, msgMsgp, msgReflect)
	// Check that the other fields we have manually set are still the same
	require.Equal(t, msgMsgp.Input.Tag, protocol.ProposalPayloadTag)
	require.Equal(t, msgMsgp.TaskIndex, uint64(63))

}
