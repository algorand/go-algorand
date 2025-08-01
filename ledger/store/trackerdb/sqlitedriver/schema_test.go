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

package sqlitedriver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	storetesting "github.com/algorand/go-algorand/ledger/store/testing"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
)

func TestAccountsReencoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	oldEncodedAccountsData := [][]byte{
		{132, 164, 97, 108, 103, 111, 206, 5, 234, 236, 80, 164, 97, 112, 97, 114, 129, 206, 0, 3, 60, 164, 137, 162, 97, 109, 196, 32, 49, 54, 101, 102, 97, 97, 51, 57, 50, 52, 97, 54, 102, 100, 57, 100, 51, 97, 52, 56, 50, 52, 55, 57, 57, 97, 52, 97, 99, 54, 53, 100, 162, 97, 110, 167, 65, 80, 84, 75, 73, 78, 71, 162, 97, 117, 174, 104, 116, 116, 112, 58, 47, 47, 115, 111, 109, 101, 117, 114, 108, 161, 99, 196, 32, 183, 97, 139, 76, 1, 45, 180, 52, 183, 186, 220, 252, 85, 135, 185, 87, 156, 87, 158, 83, 49, 200, 133, 169, 43, 205, 26, 148, 50, 121, 28, 105, 161, 102, 196, 32, 183, 97, 139, 76, 1, 45, 180, 52, 183, 186, 220, 252, 85, 135, 185, 87, 156, 87, 158, 83, 49, 200, 133, 169, 43, 205, 26, 148, 50, 121, 28, 105, 161, 109, 196, 32, 60, 69, 244, 159, 234, 26, 168, 145, 153, 184, 85, 182, 46, 124, 227, 144, 84, 113, 176, 206, 109, 204, 245, 165, 100, 23, 71, 49, 32, 242, 146, 68, 161, 114, 196, 32, 183, 97, 139, 76, 1, 45, 180, 52, 183, 186, 220, 252, 85, 135, 185, 87, 156, 87, 158, 83, 49, 200, 133, 169, 43, 205, 26, 148, 50, 121, 28, 105, 161, 116, 205, 3, 32, 162, 117, 110, 163, 65, 80, 75, 165, 97, 115, 115, 101, 116, 129, 206, 0, 3, 60, 164, 130, 161, 97, 0, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
		{132, 164, 97, 108, 103, 111, 206, 5, 230, 217, 88, 164, 97, 112, 97, 114, 129, 206, 0, 3, 60, 175, 137, 162, 97, 109, 196, 32, 49, 54, 101, 102, 97, 97, 51, 57, 50, 52, 97, 54, 102, 100, 57, 100, 51, 97, 52, 56, 50, 52, 55, 57, 57, 97, 52, 97, 99, 54, 53, 100, 162, 97, 110, 167, 65, 80, 84, 75, 105, 110, 103, 162, 97, 117, 174, 104, 116, 116, 112, 58, 47, 47, 115, 111, 109, 101, 117, 114, 108, 161, 99, 196, 32, 111, 157, 243, 205, 146, 155, 167, 149, 44, 226, 153, 150, 6, 105, 206, 72, 182, 218, 38, 146, 98, 94, 57, 205, 145, 152, 12, 60, 175, 149, 94, 13, 161, 102, 196, 32, 111, 157, 243, 205, 146, 155, 167, 149, 44, 226, 153, 150, 6, 105, 206, 72, 182, 218, 38, 146, 98, 94, 57, 205, 145, 152, 12, 60, 175, 149, 94, 13, 161, 109, 196, 32, 60, 69, 244, 159, 234, 26, 168, 145, 153, 184, 85, 182, 46, 124, 227, 144, 84, 113, 176, 206, 109, 204, 245, 165, 100, 23, 71, 49, 32, 242, 146, 68, 161, 114, 196, 32, 111, 157, 243, 205, 146, 155, 167, 149, 44, 226, 153, 150, 6, 105, 206, 72, 182, 218, 38, 146, 98, 94, 57, 205, 145, 152, 12, 60, 175, 149, 94, 13, 161, 116, 205, 1, 44, 162, 117, 110, 164, 65, 80, 84, 75, 165, 97, 115, 115, 101, 116, 130, 206, 0, 3, 56, 153, 130, 161, 97, 10, 161, 102, 194, 206, 0, 3, 60, 175, 130, 161, 97, 0, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
		{131, 164, 97, 108, 103, 111, 206, 5, 233, 179, 208, 165, 97, 115, 115, 101, 116, 130, 206, 0, 3, 60, 164, 130, 161, 97, 2, 161, 102, 194, 206, 0, 3, 60, 175, 130, 161, 97, 30, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
		{131, 164, 97, 108, 103, 111, 206, 0, 3, 48, 104, 165, 97, 115, 115, 101, 116, 129, 206, 0, 1, 242, 159, 130, 161, 97, 0, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
	}
	dbs, _ := storetesting.DbOpenTest(t, true)
	storetesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	secrets := crypto.GenerateOneTimeSignatureSecrets(15, 500)
	pubVrfKey, _ := crypto.VrfKeygenFromSeed([32]byte{0, 1, 2, 3})
	var stateProofID merklesignature.Verifier
	crypto.RandBytes(stateProofID.Commitment[:])

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		AccountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)

		for _, oldAccData := range oldEncodedAccountsData {
			addr := ledgertesting.RandomAddress()
			_, err = tx.ExecContext(ctx, "INSERT INTO accountbase (address, data) VALUES (?, ?)", addr[:], oldAccData)
			if err != nil {
				return err
			}
		}
		for i := 0; i < 100; i++ {
			addr := ledgertesting.RandomAddress()
			accData := basics.AccountData{
				MicroAlgos:         basics.MicroAlgos{Raw: 0x000ffffffffffffff},
				Status:             basics.NotParticipating,
				RewardsBase:        uint64(i),
				RewardedMicroAlgos: basics.MicroAlgos{Raw: 0x000ffffffffffffff},
				VoteID:             secrets.OneTimeSignatureVerifier,
				SelectionID:        pubVrfKey,
				StateProofID:       stateProofID.Commitment,
				VoteFirstValid:     basics.Round(0x000ffffffffffffff),
				VoteLastValid:      basics.Round(0x000ffffffffffffff),
				VoteKeyDilution:    0x000ffffffffffffff,
				AssetParams: map[basics.AssetIndex]basics.AssetParams{
					0x000ffffffffffffff: {
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
					0x000ffffffffffffff: {
						Amount: 0x000ffffffffffffff,
						Frozen: true,
					},
				},
			}

			_, err = tx.ExecContext(ctx, "INSERT INTO accountbase (address, data) VALUES (?, ?)", addr[:], protocol.Encode(&accData))
			if err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)

	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		modifiedAccounts, err := reencodeAccounts(ctx, tx)
		if err != nil {
			return err
		}
		if len(oldEncodedAccountsData) != int(modifiedAccounts) {
			return fmt.Errorf("len(oldEncodedAccountsData) != int(modifiedAccounts) %d != %d", len(oldEncodedAccountsData), int(modifiedAccounts))
		}
		require.Equal(t, len(oldEncodedAccountsData), int(modifiedAccounts))
		return nil
	})
	require.NoError(t, err)
}

// TestAccountDBTxTailLoad checks txtailNewRound and LoadTxTail delete and load right data
func TestAccountDBTxTailLoad(t *testing.T) {
	partitiontest.PartitionTest(t)

	const inMem = true
	dbs, _ := storetesting.DbOpenTest(t, inMem)
	storetesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	arw := NewAccountsSQLReaderWriter(tx)

	err = accountsCreateTxTailTable(context.Background(), tx)
	require.NoError(t, err)

	// insert 1500 rounds and retain past 1001
	startRound := basics.Round(1)
	endRound := basics.Round(1500)
	roundData := make([][]byte, 1500)
	const retainSize = 1001
	for i := startRound; i <= endRound; i++ {
		data := trackerdb.TxTailRound{Hdr: bookkeeping.BlockHeader{TimeStamp: int64(i)}}
		roundData[i-1] = protocol.Encode(&data)
	}
	forgetBefore := (endRound + 1).SubSaturate(retainSize)
	err = arw.TxtailNewRound(context.Background(), startRound, roundData, forgetBefore)
	require.NoError(t, err)

	data, _, baseRound, err := arw.LoadTxTail(context.Background(), endRound)
	require.NoError(t, err)
	require.Len(t, data, retainSize)
	require.Equal(t, basics.Round(endRound-retainSize+1), baseRound) // 500...1500

	for i, entry := range data {
		require.Equal(t, int64(i+int(baseRound)), entry.Hdr.TimeStamp)
	}
}

func TestRemoveStrayStateProofID(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := ledgertesting.RandomAccounts(20, true)
	expectedAccts := make(map[basics.Address]basics.AccountData)
	for addr, acct := range accts {
		rand.Read(acct.StateProofID[:])
		accts[addr] = acct

		expectedAcct := acct
		if acct.SelectionID.IsEmpty() {
			expectedAcct.StateProofID = merklesignature.Commitment{}
		}
		expectedAccts[addr] = expectedAcct
	}

	buildDB := func(accounts map[basics.Address]basics.AccountData) (db.Pair, *sql.Tx) {
		dbs, _ := storetesting.DbOpenTest(t, true)
		storetesting.SetDbLogging(t, dbs)

		tx, err := dbs.Wdb.Handle.Begin()
		require.NoError(t, err)

		// this is the same seq as AccountsInitTest makes but it stops
		// before the online accounts table creation to generate a trie and commit it
		_, err = accountsInit(tx, accounts, config.Consensus[protocol.ConsensusCurrentVersion].RewardUnit)
		require.NoError(t, err)

		err = accountsAddNormalizedBalance(tx, config.Consensus[protocol.ConsensusCurrentVersion].RewardUnit)
		require.NoError(t, err)

		err = accountsCreateResourceTable(context.Background(), tx)
		require.NoError(t, err)

		err = performResourceTableMigration(context.Background(), tx, nil)
		require.NoError(t, err)

		return dbs, tx
	}

	dbs, tx := buildDB(accts)
	defer dbs.Close()
	defer tx.Rollback()

	// make second copy of DB to prepare expected/fixed merkle trie
	expectedDBs, expectedTx := buildDB(expectedAccts)
	defer expectedDBs.Close()
	defer expectedTx.Rollback()

	// create account hashes
	computeRootHash := func(tx *sql.Tx, expected bool) (crypto.Digest, error) {
		rows, err := tx.Query("SELECT address, data FROM accountbase")
		require.NoError(t, err)
		defer rows.Close()

		mc, err := MakeMerkleCommitter(tx, false)
		require.NoError(t, err)
		trie, err := merkletrie.MakeTrie(mc, trackerdb.TrieMemoryConfig)
		require.NoError(t, err)

		var addr basics.Address
		for rows.Next() {
			var addrbuf []byte
			var encodedAcctData []byte
			err = rows.Scan(&addrbuf, &encodedAcctData)
			require.NoError(t, err)
			copy(addr[:], addrbuf)
			var ba trackerdb.BaseAccountData
			err = protocol.Decode(encodedAcctData, &ba)
			require.NoError(t, err)
			if expected && ba.SelectionID.IsEmpty() {
				require.Zero(t, ba.StateProofID)
			}
			addHash := trackerdb.AccountHashBuilderV6(addr, &ba, encodedAcctData)
			added, err := trie.Add(addHash)
			require.NoError(t, err)
			require.True(t, added)
		}
		_, err = trie.Evict(true)
		require.NoError(t, err)
		return trie.RootHash()
	}
	oldRoot, err := computeRootHash(tx, false)
	require.NoError(t, err)
	require.NotEmpty(t, oldRoot)

	expectedRoot, err := computeRootHash(expectedTx, true)
	require.NoError(t, err)
	require.NotEmpty(t, expectedRoot)

	err = accountsCreateOnlineAccountsTable(context.Background(), tx)
	require.NoError(t, err)
	err = performOnlineAccountsTableMigration(context.Background(), tx, nil, nil)
	require.NoError(t, err)

	// get the new hash and ensure it does not match to the old one (data migrated)
	mc, err := MakeMerkleCommitter(tx, false)
	require.NoError(t, err)
	trie, err := merkletrie.MakeTrie(mc, trackerdb.TrieMemoryConfig)
	require.NoError(t, err)

	newRoot, err := trie.RootHash()
	require.NoError(t, err)
	require.NotEmpty(t, newRoot)

	require.NotEqual(t, oldRoot, newRoot)
	require.Equal(t, expectedRoot, newRoot)

	rows, err := tx.Query("SELECT addrid, data FROM accountbase")
	require.NoError(t, err)
	defer rows.Close()

	for rows.Next() {
		var addrid sql.NullInt64
		var encodedAcctData []byte
		err = rows.Scan(&addrid, &encodedAcctData)
		require.NoError(t, err)
		var ba trackerdb.BaseAccountData
		err = protocol.Decode(encodedAcctData, &ba)
		require.NoError(t, err)
		if ba.SelectionID.IsEmpty() {
			require.Zero(t, ba.StateProofID)
		}
	}
}
