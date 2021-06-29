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

package network

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testPartitioning"
)

func TestUnmarshallMessageOfInterestErrors(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

	bytes := MarshallMessageOfInterest([]protocol.Tag{protocol.AgreementVoteTag})
	tags, err := unmarshallMessageOfInterest(bytes)
	require.NoError(t, err)
	require.Equal(t, tags[protocol.AgreementVoteTag], true)
	require.Equal(t, 1, len(tags))

	bytes = MarshallMessageOfInterest([]protocol.Tag{protocol.AgreementVoteTag, protocol.NetPrioResponseTag})
	tags, err = unmarshallMessageOfInterest(bytes)
	require.NoError(t, err)
	require.Equal(t, tags[protocol.AgreementVoteTag], true)
	require.Equal(t, tags[protocol.NetPrioResponseTag], true)
	require.Equal(t, 2, len(tags))

	bytes = MarshallMessageOfInterest([]protocol.Tag{protocol.AgreementVoteTag, protocol.AgreementVoteTag})
	tags, err = unmarshallMessageOfInterest(bytes)
	require.NoError(t, err)
	require.Equal(t, tags[protocol.AgreementVoteTag], true)
	require.Equal(t, 1, len(tags))
}
