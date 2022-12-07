package encoded

import (
	"math"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
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
		longestPossibleKey := logic.MakeBoxKey(basics.AppIndex(math.MaxUint64), longestPossibleBoxName)
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
