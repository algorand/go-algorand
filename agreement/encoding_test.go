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

package agreement

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestEmptyEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var v vote
	require.Equal(t, 1, len(protocol.Encode(&v)))

	var f proposal
	require.Equal(t, 1, len(protocol.Encode(&f)))

	var b bundle
	require.Equal(t, 1, len(protocol.Encode(&b)))
}

// TestMsgpTypeAliasCompat ensures that type switching between types and type aliases
// is backwards compatible.
func TestMsgpTypeAliasCompat(t *testing.T) {
	partitiontest.PartitionTest(t)

	encodedRound := protocol.Encode(round(rand.Uint64()))
	var roundDecoded round
	err := protocol.Decode(encodedRound, &roundDecoded)
	require.NoError(t, err)
	var basicsRoundDecoded basics.Round
	err = protocol.Decode(encodedRound, &basicsRoundDecoded)
	require.NoError(t, err)
	require.Equal(t, roundDecoded, basicsRoundDecoded)

	encodedBasicsRound := protocol.Encode(basics.Round(rand.Uint64()))
	err = protocol.Decode(encodedBasicsRound, &roundDecoded)
	require.NoError(t, err)
	err = protocol.Decode(encodedBasicsRound, &basicsRoundDecoded)
	require.NoError(t, err)
	require.Equal(t, roundDecoded, basicsRoundDecoded)
}
