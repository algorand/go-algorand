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

package network

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestUnmarshallMessageOfInterestErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	tags, err := unmarshallMessageOfInterest([]byte{0x88})
	require.Equal(t, errUnableUnmarshallMessage, err)
	require.Equal(t, 0, len(tags))

	invalidTopics := Topics{Topic{key: "something-else", data: []byte{}}}
	tags, err = unmarshallMessageOfInterest(invalidTopics.MarshallTopics())
	require.Equal(t, errInvalidMessageOfInterest, err)
	require.Equal(t, 0, len(tags))

	longTagsList := ""
	for i := 0; i < 1024; i++ {
		longTagsList += ",XQ"
	}
	longTagsList = longTagsList[1:]
	longtagsTopics := Topics{Topic{key: "tags", data: []byte(longTagsList)}}
	tags, err = unmarshallMessageOfInterest(longtagsTopics.MarshallTopics())
	require.Equal(t, errInvalidMessageOfInterestLength, err)
	require.Equal(t, 0, len(tags))
}

func TestMarshallMessageOfInterest(t *testing.T) {
	partitiontest.PartitionTest(t)

	bytes := marshallMessageOfInterest([]protocol.Tag{protocol.AgreementVoteTag})
	tags, err := unmarshallMessageOfInterest(bytes)
	require.NoError(t, err)
	require.Equal(t, tags[protocol.AgreementVoteTag], true)
	require.Equal(t, 1, len(tags))

	bytes = marshallMessageOfInterest([]protocol.Tag{protocol.AgreementVoteTag, protocol.NetPrioResponseTag})
	tags, err = unmarshallMessageOfInterest(bytes)
	require.NoError(t, err)
	require.Equal(t, tags[protocol.AgreementVoteTag], true)
	require.Equal(t, tags[protocol.NetPrioResponseTag], true)
	require.Equal(t, 2, len(tags))

	bytes = marshallMessageOfInterest([]protocol.Tag{protocol.AgreementVoteTag, protocol.AgreementVoteTag})
	tags, err = unmarshallMessageOfInterest(bytes)
	require.NoError(t, err)
	require.Equal(t, tags[protocol.AgreementVoteTag], true)
	require.Equal(t, 1, len(tags))
}

func TestDefaultSendMessageTagsMarshalRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	cloned := maps.Clone(defaultSendMessageTags)

	toBytes := func(tags map[protocol.Tag]bool) []byte {
		return marshallMessageOfInterestMap(tags)
	}
	toTags := func(data []byte) map[protocol.Tag]bool {
		tags, err := unmarshallMessageOfInterest(data)
		require.NoError(t, err)
		return tags
	}

	// Test that default messages of interest round-trip correctly
	result := toTags(toBytes(cloned))
	require.Equal(t, cloned, result, "default messages of interest should round-trip")
}
