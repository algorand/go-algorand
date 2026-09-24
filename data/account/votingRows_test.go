// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package account

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

// makeSmallTestKey creates a participation key with a small dilution so batch
// rollovers happen quickly in tests.
func makeSmallTestKey(t *testing.T, a *require.Assertions, first, last basics.Round, dilution uint64) (PersistedParticipation, db.Accessor) {
	partDB, err := db.MakeAccessor(t.Name()+"_part", false, true)
	a.NoError(err)

	var addr basics.Address
	crypto.RandBytes(addr[:])
	part, err := FillDBWithParticipationKeys(partDB, addr, first, last, dilution)
	a.NoError(err)
	return part, partDB
}

// queryInt runs a query that yields a single integer.
func queryInt(a *require.Assertions, store db.Accessor, query string, args ...any) (n int) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRow(query, args...).Scan(&n)
	})
	a.NoError(err)
	return n
}

func countTableRows(a *require.Assertions, store db.Accessor, table string) int {
	return queryInt(a, store, "SELECT count(*) FROM "+table)
}

// hasColumn reports whether a table has a column.
func hasColumn(a *require.Assertions, store db.Accessor, table, column string) bool {
	return queryInt(a, store, "SELECT count(*) FROM pragma_table_info(?) WHERE name=?", table, column) > 0
}

// requireNoAutoIndex checks the subkey tables have no separate index B-tree
// (a rowid table with a composite primary key gets an automatic one, which
// would cost an extra page write per deleted row).
func requireNoAutoIndex(a *require.Assertions, store db.Accessor) {
	a.Zero(queryInt(a, store, "SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name IN ('VotingBatches', 'VotingOffsets')"),
		"subkey tables carry a separate index B-tree")
}

func execSQL(a *require.Assertions, store db.Accessor, query string, args ...any) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	})
	a.NoError(err)
}

func readPartkeyVotingHeader(a *require.Assertions, store db.Accessor) (hdr crypto.OneTimeSignatureSecretsHeader) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		hdr, err = readVotingHeader(tx, partkeyFileVotingTarget)
		return err
	})
	a.NoError(err)
	return hdr
}

func encodedVotingSnapshot(secrets *crypto.OneTimeSignatureSecrets) []byte {
	snap := secrets.Snapshot()
	return protocol.Encode(&snap)
}

// requireRetiredIDUnusable checks a restore of the store cannot sign id.
func requireRetiredIDUnusable(a *require.Assertions, store db.Accessor, verifier crypto.OneTimeSignatureVerifier, id crypto.OneTimeSignatureIdentifier) {
	restored, err := RestoreParticipationUnmigrated(store)
	a.NoError(err)
	msg := crypto.OneTimeSignatureSubkeyBatchID{Batch: 1}
	sig := restored.Voting.Sign(id, msg)
	a.False(verifier.Verify(id, msg, sig), "restored secrets signed a retired identifier")
}

func setupTestDBAtVer3(partDB db.Accessor, part Participation) error {
	// a version 2 file plus the state proof column, as the v2->v3 migration left it
	if err := setupTestDBAtVer2(partDB, part); err != nil {
		return err
	}
	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.Exec("ALTER TABLE ParticipationAccount ADD COLUMN stateProof BLOB"); err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE ParticipationAccount SET stateProof=?", protocol.Encode(part.StateProofSecrets)); err != nil {
			return err
		}
		_, err := tx.Exec("UPDATE schema SET version=? WHERE tablename=?", PartTableSchemaVersionWholeBlob, PartTableSchemaName)
		return err
	})
}

// TestMigrateLegacyVersions covers every legacy .partkey schema version: the
// file is read as-is by the read-only restore and left untouched, then
// migrated to the latest version, with the header, the rows, the dropped
// legacy column, and a restore equal to the original checked.  Two damaged v3
// files must roll back untouched.
func TestMigrateLegacyVersions(t *testing.T) {
	partitiontest.PartitionTest(t)

	setups := map[int]func(db.Accessor, Participation) error{1: setupTestDBAtVer1, 2: setupTestDBAtVer2, 3: setupTestDBAtVer3}
	cases := []struct {
		name      string
		version   int
		advance   basics.Round
		exhausted bool
		damage    string // SQL that makes the file unusable; the migration must roll back
	}{
		{"v1", 1, 55, false, ""},
		{"v2", 2, 55, false, ""},
		{"v3", 3, 55, false, ""},
		{"v3Exhausted", 3, 999, true, ""},
		{"v3CorruptBlobRollsBack", 3, 55, false, "UPDATE ParticipationAccount SET voting=substr(voting, 1, length(voting)/2)"},
		{"v3TwoAccountRowsRollBack", 3, 55, false, "INSERT INTO ParticipationAccount SELECT * FROM ParticipationAccount"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			const dilution = 10

			part, tmpDB := makeSmallTestKey(t, a, 0, 300, dilution)
			defer closeDBS(tmpDB)
			part.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(tc.advance, dilution), dilution)
			snap := votingSnapshot(part.Voting)
			a.Equal(tc.exhausted, snap.Header().Exhausted())

			partDB, err := db.MakeAccessor(t.Name(), false, true)
			a.NoError(err)
			defer closeDBS(partDB)
			a.NoError(setups[tc.version](partDB, part.Participation))

			// the read-only restore reads the file as-is, with the metadata
			// its version has, and leaves it untouched
			restored, err := RestoreParticipationUnmigrated(partDB)
			a.NoError(err)
			a.Equal(encodedVotingSnapshot(part.Voting), encodedVotingSnapshot(restored.Voting))
			a.Equal(tc.version >= 3, restored.StateProofSecrets != nil)
			versions, err := getSchemaVersions(partDB)
			a.NoError(err)
			a.Equal(tc.version, versions[PartTableSchemaName])

			if tc.damage != "" {
				execSQL(a, partDB, tc.damage)

				// unusable content is reported with the quarantine sentinel
				// (the node renames the file instead of failing to start) and
				// the whole migration transaction rolls back
				err = Migrate(partDB)
				a.ErrorIs(err, ErrCorruptedVotingData)
				_, err = RestoreParticipation(partDB)
				a.ErrorIs(err, ErrCorruptedVotingData)
				versions, err = getSchemaVersions(partDB)
				a.NoError(err)
				a.Equal(tc.version, versions[PartTableSchemaName])
				a.True(hasColumn(a, partDB, "ParticipationAccount", "voting"))
				a.False(hasColumn(a, partDB, "ParticipationAccount", "votingHeader"))
				a.Zero(queryInt(a, partDB, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('VotingBatches', 'VotingOffsets')"),
					"migration tables survived the rollback")
				return
			}

			a.NoError(Migrate(partDB))
			versions, err = getSchemaVersions(partDB)
			a.NoError(err)
			a.Equal(PartTableSchemaVersion, versions[PartTableSchemaName])
			a.NoError(testDBContainsAllColumns(partDB))
			assertStateProofTablesExists(a, partDB)
			requireNoAutoIndex(a, partDB)

			// the legacy blob column is gone, the header column is present
			a.True(hasColumn(a, partDB, "ParticipationAccount", "votingHeader"))
			a.False(hasColumn(a, partDB, "ParticipationAccount", "voting"))
			a.Equal(len(snap.Batches), countTableRows(a, partDB, "VotingBatches"))
			a.Equal(len(snap.Offsets), countTableRows(a, partDB, "VotingOffsets"))
			a.Equal(snap.Header(), readPartkeyVotingHeader(a, partDB))

			// full restore equals the original; metadata the version lacked
			// comes back zero
			restored, err = RestoreParticipation(partDB)
			a.NoError(err)
			a.Equal(encodedVotingSnapshot(part.Voting), encodedVotingSnapshot(restored.Voting))
			a.Equal(part.Parent, restored.Parent)
			if tc.version >= 2 {
				a.Equal(part.KeyDilution, restored.KeyDilution)
			} else {
				a.Zero(restored.KeyDilution)
			}
			a.Equal(tc.version >= 3, restored.StateProofSecrets != nil)
		})
	}
}

// TestMigrationErasesLegacyBlob verifies the v3 migration leaves no trace of
// the legacy voting blob in the file even when the caller's accessor was
// opened without secure_delete: the blob held every subkey.
func TestMigrationErasesLegacyBlob(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	part, tmpDB := makeSmallTestKey(t, a, 0, 300, 10)
	defer closeDBS(tmpDB)
	// a secret that only the legacy blob and the batch rows contain
	secret := part.Voting.Batches[3].SK
	fileContains := func(path string, needle []byte) bool {
		data, err := os.ReadFile(path)
		a.NoError(err)
		return bytes.Contains(data, needle)
	}

	// build the v3 file with a plain (non-erasable) accessor, as the genesis
	// generator and older tools do, and close it so the WAL is checkpointed
	path := filepath.Join(t.TempDir(), "legacy.partkey")
	partDB, err := db.MakeAccessor(path, false, false)
	a.NoError(err)
	a.NoError(setupTestDBAtVer3(partDB, part.Participation))
	// compact the fixture: building it rewrote the account row without
	// secure_delete, leaving a stale copy of the blob in free pages that a
	// real v3 file (written once, then updated under secure_delete) never has
	_, err = partDB.Handle.Exec("VACUUM")
	a.NoError(err)
	partDB.Close()
	a.True(fileContains(path, secret[:]), "fixture does not contain the secret; the test proves nothing")

	// migrate through the same kind of accessor
	partDB, err = db.MakeAccessor(path, false, false)
	a.NoError(err)
	a.NoError(Migrate(partDB))
	restored, err := RestoreParticipation(partDB)
	a.NoError(err)
	a.Equal(encodedVotingSnapshot(part.Voting), encodedVotingSnapshot(restored.Voting))
	partDB.Close()

	// the secret now lives only in its row; retire it through the erasable
	// accessor the node uses, then check the file: only the migration's
	// leftovers could still hold it
	partDB, err = db.MakeErasableAccessor(path)
	a.NoError(err)
	restored, err = RestoreParticipation(partDB)
	a.NoError(err)
	restored.Store = partDB
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	a.NoError(<-restored.DeleteOldKeys(basics.Round(45), proto)) // consumes batches 0..3
	partDB.Close()
	a.NoFileExists(path + "-wal")
	a.False(fileContains(path, secret[:]), "retired subkey recoverable from the migrated file")
}

// TestSyncVotingRows drives the per-round synchronizer through every
// transition against a real store, checking the rows, the header, repair of
// drifted rows, and the refusals that protect forward security (a stored
// cursor ahead of memory, an undecodable stored header).
func TestSyncVotingRows(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	const dilution = 8
	// FirstValid 0 gives a key whose FirstBatch is 0 (the uint64 edge for
	// batch-1 arithmetic); batches 0..12
	part, partDB := makeSmallTestKey(t, a, 0, 100, dilution)
	defer closeDBS(partDB)
	secrets := part.Voting

	// sync brings the store from its stored header to the given memory state
	sync := func(mem *crypto.OneTimeSignatureSecrets) error {
		return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			return syncVotingRowsAndHeader(tx, partkeyFileVotingTarget, votingSnapshot(mem))
		})
	}
	// advance moves memory to id, syncs, and checks header, row counts, and
	// reassembly against memory
	advance := func(id crypto.OneTimeSignatureIdentifier, what string) {
		secrets.DeleteBeforeFineGrained(id, dilution)
		a.NoError(sync(secrets), what)
		hdr := votingSnapshot(secrets).Header()
		a.Equal(hdr, readPartkeyVotingHeader(a, partDB), what)
		a.Equal(int(hdr.BatchCount), countTableRows(a, partDB, "VotingBatches"), what)
		a.Equal(int(hdr.OffsetCount), countTableRows(a, partDB, "VotingOffsets"), what)
		restored, err := RestoreParticipationUnmigrated(partDB)
		a.NoError(err, what)
		a.Equal(encodedVotingSnapshot(secrets), encodedVotingSnapshot(restored.Voting), what)
	}

	// fresh: unchanged header is a no-op
	a.Zero(readPartkeyVotingHeader(a, partDB).FirstBatch)
	a.NoError(sync(secrets))
	advance(crypto.OneTimeSignatureIdentifier{}, "unchanged")

	advance(crypto.OneTimeSignatureIdentifier{Batch: 0, Offset: 2}, "first expansion")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 0, Offset: 5}, "same-batch trim")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 1, Offset: 1}, "rollover")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 3}, "multi-batch jump")

	// drifted rows are repaired by the next transition: a stray row below the
	// cursor makes the trim remove too many rows, a lost row too few
	execSQL(a, partDB, "INSERT INTO VotingOffsets (off, data) VALUES (0, x'00')")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 4}, "repair after stray row")
	execSQL(a, partDB, "DELETE FROM VotingOffsets WHERE off=(SELECT MIN(off) FROM VotingOffsets)")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 5}, "repair after lost row")

	// stored header ahead of memory (on either cursor field): refused,
	// nothing written
	current := votingSnapshot(secrets).Header()
	ahead := current
	ahead.FirstOffset++
	ahead.OffsetCount--
	execSQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", protocol.Encode(&ahead))
	a.ErrorContains(sync(secrets), "refusing to resurrect")
	a.Equal(ahead, readPartkeyVotingHeader(a, partDB))
	ahead = current
	ahead.FirstBatch++
	execSQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", protocol.Encode(&ahead))
	a.ErrorContains(sync(secrets), "refusing to resurrect")
	// ... and so is an undecodable stored header (failing closed: a rewrite
	// from possibly-stale memory could resurrect retired keys)
	execSQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", []byte{0xff, 0x00})
	batchRows, offsetRows := countTableRows(a, partDB, "VotingBatches"), countTableRows(a, partDB, "VotingOffsets")
	a.ErrorContains(sync(secrets), "undecodable")
	a.Equal(batchRows, countTableRows(a, partDB, "VotingBatches"))
	a.Equal(offsetRows, countTableRows(a, partDB, "VotingOffsets"))
	execSQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", protocol.Encode(&current))

	// jump that runs out of batches: exhausted, every row erased, and a
	// restore cannot sign an identifier that was live a moment ago
	lastLive := crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 6}
	advance(crypto.OneTimeSignatureIdentifier{Batch: 50}, "exhausted")
	a.True(readPartkeyVotingHeader(a, partDB).Exhausted())
	requireRetiredIDUnusable(a, partDB, secrets.OneTimeSignatureVerifier, lastLive)

	// an exhausted store is terminal: a live copy of the key is refused
	a.ErrorContains(sync(crypto.GenerateOneTimeSignatureSecrets(0, 3)), "refusing to resurrect")
}

// TestDeleteOldKeysLifecycle walks a key through DeleteOldKeys from its first
// round past the end of its life, verifying the file reassembles to exactly
// the in-memory state after every round, that batch rows only churn on a
// rollover, and that the end of life erases every subkey row.
func TestDeleteOldKeysLifecycle(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	const dilution = 10
	part, partDB := makeSmallTestKey(t, a, 0, 300, dilution) // batches 0..30, coverage through round 309
	defer closeDBS(partDB)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// a fresh Persist stores one row per batch subkey, no offsets, and a
	// header that says so
	a.Equal(len(part.Voting.Batches), countTableRows(a, partDB, "VotingBatches"))
	a.Zero(countTableRows(a, partDB, "VotingOffsets"))
	fresh := readPartkeyVotingHeader(a, partDB)
	a.Equal(uint64(len(part.Voting.Batches)), fresh.BatchCount)
	a.Zero(fresh.OffsetCount)

	// every round through 120, then a jump into the final batch, past the
	// end of the key, and one more round on the dead key
	var rounds []basics.Round
	for r := basics.Round(1); r <= 120; r++ {
		rounds = append(rounds, r)
	}
	rounds = append(rounds, 305, 311, 315)

	prevBatchRows := countTableRows(a, partDB, "VotingBatches")
	for _, r := range rounds {
		firstBatchBefore := part.Voting.FirstBatch
		a.NoError(<-part.DeleteOldKeys(r, proto))

		// persisted state reconstructs to exactly the in-memory state
		restored, err := RestoreParticipationUnmigrated(partDB)
		a.NoError(err)
		a.Equal(encodedVotingSnapshot(part.Voting), encodedVotingSnapshot(restored.Voting), "round %d", r)

		// batch rows only churn when a batch is consumed (expanded into offsets)
		batchRows := countTableRows(a, partDB, "VotingBatches")
		if part.Voting.FirstBatch == firstBatchBefore {
			a.Equal(prevBatchRows, batchRows, "batch rows changed off-rollover at round %d", r)
		} else {
			a.Less(batchRows, prevBatchRows, "batch rows not trimmed at rollover round %d", r)
		}
		prevBatchRows = batchRows
	}

	// end of life: every subkey row erased and no retired round signable
	a.Empty(part.Voting.Offsets)
	a.Zero(countTableRows(a, partDB, "VotingOffsets"), "retired offset subkeys survived on disk")
	a.Zero(countTableRows(a, partDB, "VotingBatches"))
	a.True(readPartkeyVotingHeader(a, partDB).Exhausted())
	requireRetiredIDUnusable(a, partDB, part.Voting.OneTimeSignatureVerifier, basics.OneTimeIDForRound(305, dilution))
}

// TestRestoreDetectsCorruption verifies a damaged header or damaged subkey
// tables are reported with the quarantine sentinel instead of loading a key
// that silently cannot vote.
func TestRestoreDetectsCorruption(t *testing.T) {
	partitiontest.PartitionTest(t)

	cases := []struct {
		name      string
		tamperSQL string
		wantErr   string
	}{
		{"undecodableHeader", "UPDATE ParticipationAccount SET votingHeader=x'ff00'", "undecodable voting header"},
		{"missingBatchRow", "DELETE FROM VotingBatches WHERE batch=(SELECT MAX(batch) FROM VotingBatches)", "missing or extra rows"},
		{"misplacedOffsetRow", "UPDATE VotingOffsets SET off=off-1 WHERE off=(SELECT MIN(off) FROM VotingOffsets)", "offset row 0 has index"},
		{"undecodableVRF", "UPDATE ParticipationAccount SET vrf=x'ff00'", "undecodable VRF"},
		{"twoAccountRows", "INSERT INTO ParticipationAccount SELECT * FROM ParticipationAccount", "exactly one account row"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			const dilution = 10
			part, partDB := makeSmallTestKey(t, a, 0, 300, dilution)
			defer closeDBS(partDB)

			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			a.NoError(<-part.DeleteOldKeys(basics.Round(25), proto))

			// sanity: loads fine before the damage
			_, err := RestoreParticipationUnmigrated(partDB)
			a.NoError(err)

			execSQL(a, partDB, tc.tamperSQL)
			_, err = RestoreParticipationUnmigrated(partDB)
			a.ErrorContains(err, tc.wantErr)
			// the sentinel lets the node quarantine the file as *.old
			a.ErrorIs(err, ErrCorruptedVotingData)
		})
	}
}
