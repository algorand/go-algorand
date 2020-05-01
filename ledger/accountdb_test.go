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

package ledger

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

func randomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

func randomAccountData(rewardsLevel uint64) basics.AccountData {
	var data basics.AccountData

	// Avoid overflowing totals
	data.MicroAlgos.Raw = crypto.RandUint64() % (1 << 32)

	switch crypto.RandUint64() % 3 {
	case 0:
		data.Status = basics.Online
	case 1:
		data.Status = basics.Offline
	default:
		data.Status = basics.NotParticipating
	}

	data.RewardsBase = rewardsLevel
	return data
}

func randomAccounts(niter int) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	for i := 0; i < niter; i++ {
		res[randomAddress()] = randomAccountData(0)
	}

	return res
}

func randomDeltas(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates map[basics.Address]accountDelta, totals map[basics.Address]basics.AccountData, imbalance int64) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	updates = make(map[basics.Address]accountDelta)
	totals = make(map[basics.Address]basics.AccountData)

	// copy base -> totals
	for addr, data := range base {
		totals[addr] = data
	}

	// Change some existing accounts
	{
		i := 0
		for addr, old := range base {
			if i >= len(base)/2 || i >= niter {
				break
			}

			if addr == testPoolAddr {
				continue
			}
			i++

			new := randomAccountData(rewardsLevel)
			updates[addr] = accountDelta{old: old, new: new}
			imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
			totals[addr] = new
			break
		}
	}

	// Change some new accounts
	for i := 0; i < niter; i++ {
		addr := randomAddress()
		old := totals[addr]
		new := randomAccountData(rewardsLevel)
		updates[addr] = accountDelta{old: old, new: new}
		imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
		totals[addr] = new
	}

	return
}

func randomDeltasBalanced(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates map[basics.Address]accountDelta, totals map[basics.Address]basics.AccountData) {
	updates, totals, imbalance := randomDeltas(niter, base, rewardsLevel)

	oldPool := base[testPoolAddr]
	newPool := oldPool
	newPool.MicroAlgos.Raw += uint64(imbalance)

	updates[testPoolAddr] = accountDelta{old: oldPool, new: newPool}
	totals[testPoolAddr] = newPool

	return updates, totals
}

func checkAccounts(t *testing.T, tx *sql.Tx, rnd basics.Round, accts map[basics.Address]basics.AccountData) {
	r, _, err := accountsRound(tx)
	require.NoError(t, err)
	require.Equal(t, r, rnd)

	aq, err := accountsDbInit(tx, tx)
	require.NoError(t, err)

	var totalOnline, totalOffline, totalNotPart uint64

	for addr, data := range accts {
		d, err := aq.lookup(addr)
		require.NoError(t, err)
		require.Equal(t, d, data)

		switch d.Status {
		case basics.Online:
			totalOnline += d.MicroAlgos.Raw
		case basics.Offline:
			totalOffline += d.MicroAlgos.Raw
		case basics.NotParticipating:
			totalNotPart += d.MicroAlgos.Raw
		default:
			t.Errorf("unknown status %v", d.Status)
		}
	}

	all, err := accountsAll(tx)
	require.NoError(t, err)
	require.Equal(t, all, accts)

	totals, err := accountsTotals(tx, false)
	require.NoError(t, err)
	require.Equal(t, totals.Online.Money.Raw, totalOnline)
	require.Equal(t, totals.Offline.Money.Raw, totalOffline)
	require.Equal(t, totals.NotParticipating.Money.Raw, totalNotPart)
	require.Equal(t, totals.Participating().Raw, totalOnline+totalOffline)
	require.Equal(t, totals.All().Raw, totalOnline+totalOffline+totalNotPart)

	d, err := aq.lookup(randomAddress())
	require.NoError(t, err)
	require.Equal(t, d, basics.AccountData{})
}

func TestAccountDBInit(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs := dbOpenTest(t)
	setDbLogging(t, dbs)
	defer dbs.close()

	tx, err := dbs.wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := randomAccounts(20)
	err = accountsInit(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)

	err = accountsInit(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)
}

func TestAccountDBRound(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs := dbOpenTest(t)
	setDbLogging(t, dbs)
	defer dbs.close()

	tx, err := dbs.wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := randomAccounts(20)
	err = accountsInit(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)

	for i := 1; i < 10; i++ {
		updates, newaccts, _ := randomDeltas(20, accts, 0)
		accts = newaccts
		err = accountsNewRound(tx, updates, 0, proto)
		require.NoError(t, err)
		err = updateAccountsRound(tx, basics.Round(i), 0)
		require.NoError(t, err)
		checkAccounts(t, tx, basics.Round(i), accts)
	}
}

func BenchmarkReadingAllBalances(b *testing.B) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	//b.N = 50000
	dbs := dbOpenTest(b)
	setDbLogging(b, dbs)
	defer dbs.close()

	tx, err := dbs.wdb.Handle.Begin()
	require.NoError(b, err)

	secrets := crypto.GenerateOneTimeSignatureSecrets(15, 500)
	pubVrfKey, _ := crypto.VrfKeygenFromSeed([32]byte{0, 1, 2, 3})
	updates := map[basics.Address]basics.AccountData{}

	for i := 0; i < b.N; i++ {
		addr := randomAddress()
		updates[addr] = basics.AccountData{
			MicroAlgos:         basics.MicroAlgos{Raw: 0x000ffffffffffffff},
			Status:             basics.NotParticipating,
			RewardsBase:        uint64(i),
			RewardedMicroAlgos: basics.MicroAlgos{Raw: 0x000ffffffffffffff},
			VoteID:             secrets.OneTimeSignatureVerifier,
			SelectionID:        pubVrfKey,
			VoteFirstValid:     basics.Round(0x000ffffffffffffff),
			VoteLastValid:      basics.Round(0x000ffffffffffffff),
			VoteKeyDilution:    0x000ffffffffffffff,
			AssetParams: map[basics.AssetIndex]basics.AssetParams{
				0x000ffffffffffffff: basics.AssetParams{
					Total:         0x000ffffffffffffff,
					Decimals:      0x2ffffff,
					DefaultFrozen: true,
					UnitName:      "12345678",
					AssetName:     "12345678901234567890123456789012",
					URL:           "12345678901234567890123456789012",
					MetadataHash:  pubVrfKey,
					Manager:       addr,
					Reserve:       addr,
					Freeze:        addr,
					Clawback:      addr,
				},
			},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				0x000ffffffffffffff: basics.AssetHolding{
					Amount: 0x000ffffffffffffff,
					Frozen: true,
				},
			},
		}
	}
	accountsInit(tx, updates, proto)
	tx.Commit()
	tx, err = dbs.rdb.Handle.Begin()
	require.NoError(b, err)

	b.ResetTimer()
	// read all the balances in the database.
	bal, err2 := accountsAll(tx)
	require.NoError(b, err2)
	tx.Commit()

	prevHash := crypto.Digest{}
	for _, accountBalance := range bal {
		encodedAccountBalance := protocol.Encode(&accountBalance)
		prevHash = crypto.Hash(append(encodedAccountBalance, ([]byte(prevHash[:]))...))
	}
	require.Equal(b, b.N, len(bal))
}
