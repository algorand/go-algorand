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

package network

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/stretchr/testify/require"
)

func TestCheckSlowWritingPeer(t *testing.T) {
	partitiontest.PartitionTest(t)

	now := time.Now()
	peer := wsPeer{
		intermittentOutgoingMessageEnqueueTime: 0,
		wsPeerCore: wsPeerCore{net: &WebsocketNetwork{
			log: logging.TestingLog(t),
		}},
	}
	require.Equal(t, peer.CheckSlowWritingPeer(now), false)

	peer.intermittentOutgoingMessageEnqueueTime = now.UnixNano()
	require.Equal(t, peer.CheckSlowWritingPeer(now), false)

	peer.intermittentOutgoingMessageEnqueueTime = now.Add(-maxMessageQueueDuration * 2).UnixNano()
	require.Equal(t, peer.CheckSlowWritingPeer(now), true)

}

// TestGetRequestNonce tests if unique values are generated each time
func TestGetRequestNonce(t *testing.T) {
	partitiontest.PartitionTest(t)

	numValues := 1000
	peer := wsPeer{}
	valueChannel := make(chan uint64, numValues)
	for x := 0; x < numValues; x++ {
		go func() {
			ans := peer.getRequestNonce()
			val, _ := binary.Uvarint(ans)
			valueChannel <- val
		}()
	}

	// Timeout
	maxWait := time.After(2 * time.Second)

	// check if all the values are unique
	seenValue := make([]bool, numValues+1)
	for x := 0; x < numValues; x++ {
		select {
		case val := <-valueChannel:
			require.Equal(t, false, seenValue[val])
			seenValue[val] = true
		case <-maxWait:
			break
		}
	}
	// Check if all the values were generated
	for x := 1; x <= numValues; x++ {
		require.Equal(t, true, seenValue[x])
	}
}

func TestDefaultMessageTagsLength(t *testing.T) {
	partitiontest.PartitionTest(t)

	for tag := range defaultSendMessageTags {
		require.Equal(t, 2, len(tag))
	}
}

// TestAtomicVariablesAlignment ensures that the 64-bit atomic variables
// offsets are 64-bit aligned. This is required due to go atomic library
// limitation.
func TestAtomicVariablesAlignment(t *testing.T) {
	partitiontest.PartitionTest(t)

	p := wsPeer{}
	require.True(t, (unsafe.Offsetof(p.requestNonce)%8) == 0)
	require.True(t, (unsafe.Offsetof(p.lastPacketTime)%8) == 0)
	require.True(t, (unsafe.Offsetof(p.intermittentOutgoingMessageEnqueueTime)%8) == 0)
	require.True(t, (unsafe.Offsetof(p.duplicateFilterCount)%8) == 0)
}

func TestTagCounterFiltering(t *testing.T) {
	partitiontest.PartitionTest(t)

	tagCounterTags := map[string]*metrics.TagCounter{
		"networkSentBytesByTag":       networkSentBytesByTag,
		"networkReceivedBytesByTag":   networkReceivedBytesByTag,
		"networkMessageReceivedByTag": networkMessageReceivedByTag,
		"networkMessageSentByTag":     networkMessageSentByTag,
	}
	for name, tag := range tagCounterTags {
		t.Run(name, func(t *testing.T) {
			require.NotZero(t, len(tag.AllowedTags))
			tag.Add("TEST_TAG", 1)
			b := strings.Builder{}
			tag.WriteMetric(&b, "")
			result := b.String()
			require.Contains(t, result, "_UNK")
			require.NotContains(t, result, "TEST_TAG")
		})
	}
}

func TestVersionToMajorMinor(t *testing.T) {
	partitiontest.PartitionTest(t)

	ma, mi, err := versionToMajorMinor("1.2")
	require.NoError(t, err)
	require.Equal(t, int64(1), ma)
	require.Equal(t, int64(2), mi)

	ma, mi, err = versionToMajorMinor("1.2.3")
	require.Error(t, err)
	require.Zero(t, ma)
	require.Zero(t, mi)

	ma, mi, err = versionToMajorMinor("1")
	require.Error(t, err)
	require.Zero(t, ma)
	require.Zero(t, mi)

	ma, mi, err = versionToMajorMinor("a.b")
	require.Error(t, err)
	require.Zero(t, ma)
	require.Zero(t, mi)
}

func TestVersionToFeature(t *testing.T) {
	partitiontest.PartitionTest(t)

	tests := []struct {
		ver      string
		hdr      string
		expected peerFeatureFlag
	}{
		{"1.2", "", peerFeatureFlag(0)},
		{"1.2.3", "", peerFeatureFlag(0)},
		{"a.b", "", peerFeatureFlag(0)},
		{"2.1", "", peerFeatureFlag(0)},
		{"2.1", PeerFeatureProposalCompression, peerFeatureFlag(0)},
		{"2.2", "", peerFeatureFlag(0)},
		{"2.2", "test", peerFeatureFlag(0)},
		{"2.2", strings.Join([]string{"a", "b"}, ","), peerFeatureFlag(0)},
		{"2.2", PeerFeatureProposalCompression, pfCompressedProposal},
		{"2.2", strings.Join([]string{PeerFeatureProposalCompression, "test"}, ","), pfCompressedProposal},
		{"2.2", strings.Join([]string{PeerFeatureProposalCompression, "test"}, ", "), pfCompressedProposal},
		{"2.3", PeerFeatureProposalCompression, pfCompressedProposal},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			f := decodePeerFeatures(test.ver, test.hdr)
			require.Equal(t, test.expected, f)
		})
	}
}
