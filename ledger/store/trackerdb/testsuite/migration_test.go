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

package testsuite

import (
	"context"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func init() {
	// register tests that will run on each KV implementation
	registerTest("db-migration-check-basic", CustomTestChecBasicMigration)
	// Disabled since it's technically broken the way its written.
	// registerTest("db-migration-check-with-accounts", CustomTestCheckMigrationWithAccounts)
}

func CustomTestChecBasicMigration(t *customT) {
	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	// check round
	round, err := ar.AccountsRound()
	require.NoError(t, err)
	require.Equal(t, basics.Round(0), round) // initialized to round 0

	// check account totals
	totals, err := ar.AccountsTotals(context.Background(), false)
	require.NoError(t, err)
	require.Equal(t, uint64(0), totals.RewardsLevel)
	require.Equal(t, ledgercore.AlgoCount{}, totals.Online)
	require.Equal(t, ledgercore.AlgoCount{}, totals.Offline)
	require.Equal(t, ledgercore.AlgoCount{}, totals.NotParticipating)

	// check tx-tails
	txTailData, hashes, baseRound, err := ar.LoadTxTail(context.Background(), basics.Round(0))
	require.NoError(t, err)
	require.Len(t, txTailData, 0)                // no data
	require.Len(t, hashes, 0)                    // no data
	require.Equal(t, basics.Round(1), baseRound) // (the impls return +1 at the end)

	// check online accounts
	oas, err := ar.OnlineAccountsAll(99)
	require.NoError(t, err)
	require.Len(t, oas, 0)

	// check online round params
	oparams, endRound, err := ar.AccountsOnlineRoundParams()
	require.NoError(t, err)
	require.Len(t, oparams, 1)
	require.Equal(t, basics.Round(0), endRound)
	require.Equal(t, uint64(0), oparams[0].OnlineSupply)
	require.Equal(t, uint64(0), oparams[0].RewardsLevel)
	require.Equal(t, protocol.ConsensusCurrentVersion, oparams[0].CurrentProtocol)
}

func makeAccountData(status basics.Status, algos basics.MicroAlgos) basics.AccountData {
	ad := basics.AccountData{Status: status, MicroAlgos: algos}
	if status == basics.Online {
		ad.VoteFirstValid = 1
		ad.VoteLastValid = 100_000
	}
	return ad
}

func CustomTestCheckMigrationWithAccounts(t *customT) {
	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	// reset
	aw.AccountsReset(context.Background())

	initAccounts := make(map[basics.Address]basics.AccountData)

	addrA := basics.Address(crypto.Hash([]byte("a")))
	initAccounts[addrA] = makeAccountData(basics.Online, basics.MicroAlgos{Raw: 100})

	addrB := basics.Address(crypto.Hash([]byte("b")))
	initAccounts[addrB] = makeAccountData(basics.Online, basics.MicroAlgos{Raw: 42})

	addrC := basics.Address(crypto.Hash([]byte("c")))
	initAccounts[addrC] = makeAccountData(basics.Offline, basics.MicroAlgos{Raw: 30})

	addrD := basics.Address(crypto.Hash([]byte("d")))
	initAccounts[addrD] = makeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 7})

	params := trackerdb.Params{
		InitProto:    protocol.ConsensusCurrentVersion,
		InitAccounts: initAccounts,
	}

	// re-run migrations
	_, err = t.db.RunMigrations(context.Background(), params, logging.TestingLog(t), trackerdb.AccountDBVersion)
	require.NoError(t, err)

	// check account totals
	totals, err := ar.AccountsTotals(context.Background(), false)
	require.NoError(t, err)
	require.Equal(t, uint64(0), totals.RewardsLevel)
	require.Equal(t, ledgercore.AlgoCount{Money: basics.MicroAlgos{Raw: 142}}, totals.Online)
	require.Equal(t, ledgercore.AlgoCount{Money: basics.MicroAlgos{Raw: 30}}, totals.Offline)
	require.Equal(t, ledgercore.AlgoCount{Money: basics.MicroAlgos{Raw: 7}}, totals.NotParticipating)

	// check online accounts
	oas, err := ar.OnlineAccountsAll(99)
	require.NoError(t, err)
	require.Len(t, oas, 2)

	// check online round params
	oparams, endRound, err := ar.AccountsOnlineRoundParams()
	require.NoError(t, err)
	require.Len(t, oparams, 1)
	require.Equal(t, basics.Round(0), endRound)
	require.Equal(t, uint64(142), oparams[0].OnlineSupply)
	require.Equal(t, uint64(0), oparams[0].RewardsLevel)
	require.Equal(t, protocol.ConsensusCurrentVersion, oparams[0].CurrentProtocol)
}
