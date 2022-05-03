package ledger

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestOnlineAccountsCacheBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var oac onlineAccountsCache
	oac.init()

	addr := basics.Address(crypto.Hash([]byte{byte(0)}))

	accountsNum := 50
	for i := 0; i < accountsNum; i++ {
		acct := persistedOnlineAccountData{
			addr:        addr,
			round:       basics.Round(i),
			rowid:       int64(i),
			accountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		oac.writeFront(acct)
	}

	// verify that all these accounts are truly there.
	for i := 0; i < accountsNum; i++ {
		acct, has := oac.read(addr, basics.Round(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.round)
		require.Equal(t, addr, acct.addr)
		require.Equal(t, uint64(i), acct.accountData.MicroAlgos.Raw)
		require.Equal(t, int64(i), acct.rowid)
	}

	for i := proto.MaxBalLookback; i < uint64(accountsNum) + proto.MaxBalLookback; i++ {
		acct := persistedOnlineAccountData{
			addr:        addr,
			round:       basics.Round(i),
			rowid:       int64(i),
			accountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: i}},
		}
		oac.writeFront(acct)
	}

	oac.prune(basics.Round(proto.MaxBalLookback-1))

	// verify that all these accounts are truly there.
	acct, has := oac.read(addr, basics.Round(proto.MaxBalLookback-1))
	require.True(t, has)
	require.Equal(t, basics.Round(accountsNum-1), acct.round)
	require.Equal(t, addr, acct.addr)
	require.Equal(t, uint64(accountsNum-1), acct.accountData.MicroAlgos.Raw)
	require.Equal(t, int64(accountsNum-1), acct.rowid)


	for i := proto.MaxBalLookback; i < uint64(accountsNum) + proto.MaxBalLookback; i++ {
		acct, has := oac.read(addr, basics.Round(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.round)
		require.Equal(t, addr, acct.addr)
		require.Equal(t, uint64(i), acct.accountData.MicroAlgos.Raw)
		require.Equal(t, int64(i), acct.rowid)
	}
}