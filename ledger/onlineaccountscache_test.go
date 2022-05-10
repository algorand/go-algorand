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
	oac.init(nil)

	addr := basics.Address(crypto.Hash([]byte{byte(0)}))

	roundsNum := 50
	for i := 0; i < roundsNum; i++ {
		acct := persistedOnlineAccountData{
			addr:        addr,
			updRound:    basics.Round(i),
			rowid:       int64(i),
			accountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}, VoteLastValid: 1000},
		}
		oac.writeFront(acct)
	}

	// verify that all these onlineaccounts are truly there.
	for i := 0; i < roundsNum; i++ {
		acct, has := oac.read(addr, basics.Round(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.updRound)
		require.Equal(t, addr, acct.addr)
		require.Equal(t, uint64(i), acct.accountData.MicroAlgos.Raw)
		require.Equal(t, int64(i), acct.rowid)
	}

	for i := proto.MaxBalLookback; i < uint64(roundsNum)+proto.MaxBalLookback; i++ {
		acct := persistedOnlineAccountData{
			addr:        addr,
			updRound:    basics.Round(i),
			rowid:       int64(i),
			accountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: i}, VoteLastValid: 1000},
		}
		oac.writeFront(acct)
	}

	oac.prune(basics.Round(proto.MaxBalLookback - 1))

	// verify that all these accounts are truly there.
	acct, has := oac.read(addr, basics.Round(proto.MaxBalLookback-1))
	require.True(t, has)
	require.Equal(t, basics.Round(roundsNum-1), acct.updRound)
	require.Equal(t, addr, acct.addr)
	require.Equal(t, uint64(roundsNum-1), acct.accountData.MicroAlgos.Raw)
	require.Equal(t, int64(roundsNum-1), acct.rowid)

	for i := proto.MaxBalLookback; i < uint64(roundsNum)+proto.MaxBalLookback; i++ {
		acct, has := oac.read(addr, basics.Round(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.updRound)
		require.Equal(t, addr, acct.addr)
		require.Equal(t, uint64(i), acct.accountData.MicroAlgos.Raw)
		require.Equal(t, int64(i), acct.rowid)
	}

	_, has = oac.read(addr, basics.Round(0))
	require.False(t, has)
}

func TestOnlineAccountsCachePruneOffline(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var oac onlineAccountsCache
	oac.init(nil)

	addr := basics.Address(crypto.Hash([]byte{byte(0)}))

	roundsNum := 50
	for i := 0; i < roundsNum; i++ {
		acct := persistedOnlineAccountData{
			addr:        addr,
			updRound:    basics.Round(i),
			rowid:       int64(i),
			accountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}, VoteLastValid: 1000},
		}
		oac.writeFront(acct)
	}
	acct := persistedOnlineAccountData{
		addr:        addr,
		updRound:    basics.Round(roundsNum),
		rowid:       int64(roundsNum),
		accountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(roundsNum)}},
	}
	oac.writeFront(acct)

	_, has := oac.read(addr, basics.Round(proto.MaxBalLookback))
	require.True(t, has)

	oac.prune(basics.Round(proto.MaxBalLookback))

	_, has = oac.read(addr, basics.Round(proto.MaxBalLookback))
	require.False(t, has)
}
