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

package encoded

import (
	"math"
	"testing"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestEncodedKVRecordV6Allocbounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for version, params := range config.Consensus {
		require.GreaterOrEqualf(t, uint64(KVRecordV6MaxValueLength), params.MaxBoxSize, "Allocbound constant no longer valid as of consensus version %s", version)
		longestPossibleBoxName := string(make([]byte, params.MaxAppKeyLen))
		longestPossibleKey := apps.MakeBoxKey(math.MaxUint64, longestPossibleBoxName)
		require.GreaterOrEqualf(t, KVRecordV6MaxValueLength, len(longestPossibleKey), "Allocbound constant no longer valid as of consensus version %s", version)
	}
}

func TestEncodedKVDataSize(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	currentConsensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

	require.GreaterOrEqual(t, KVRecordV6MaxKeyLength, currentConsensusParams.MaxAppKeyLen)
	require.GreaterOrEqual(t, uint64(KVRecordV6MaxValueLength), currentConsensusParams.MaxBoxSize)

	kvEntry := KVRecordV6{
		Key:   make([]byte, KVRecordV6MaxKeyLength),
		Value: make([]byte, KVRecordV6MaxValueLength),
	}

	crypto.RandBytes(kvEntry.Key[:])
	crypto.RandBytes(kvEntry.Value[:])

	encoded := kvEntry.MarshalMsg(nil)
	require.GreaterOrEqual(t, MaxEncodedKVDataSize, len(encoded))

}
