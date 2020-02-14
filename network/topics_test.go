// Copyright (C) 2019-2020 Algorand, Inc.
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
)

// Test the marshall/unmarshall of Topics
func TestTopics(t *testing.T) {

	topics := Topics{
		Topic{
			key:  "key1",
			data: []byte("value 1"),
		},
		Topic{
			key:  "Key2",
			data: []byte("value of key2"),
		},
	}

	// Check if the topics were initialized correctly
	require.Equal(t, 2, len(topics))

	require.Equal(t, "key1", topics[0].key)
	require.Equal(t, "value 1", string(topics[0].data))

	require.Equal(t, "Key2", topics[1].key)
	require.Equal(t, "value of key2", string(topics[1].data))

	// Check if can be marshalled without errors
	buffer, e := topics.MarshallTopics()
	require.Empty(t, e)

	// Check if can be unmarshalled without errors
	unMarshalled, e := UnmarshallTopics(buffer)
	require.Empty(t, e)

	// Check if the unmarshalled is equal to the original
	require.Equal(t, len(topics), len(unMarshalled))

	require.Equal(t, topics[0].key, unMarshalled[0].key)
	require.Equal(t, topics[0].data, unMarshalled[0].data)

	require.Equal(t, topics[1].key, unMarshalled[1].key)
	require.Equal(t, topics[1].data, unMarshalled[1].data)
}
