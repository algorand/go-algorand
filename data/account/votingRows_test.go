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
	"context"
	"database/sql"
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

func countTableRows(a *require.Assertions, store db.Accessor, table string) (n int) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRow("SELECT count(*) FROM " + table).Scan(&n)
	})
	a.NoError(err)
	return n
}

// tableColumnsTx lists the column names of a table.
func tableColumnsTx(tx *sql.Tx, table string) (names []string, err error) {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func tableColumns(a *require.Assertions, store db.Accessor, table string) (names []string) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		names, err = tableColumnsTx(tx, table)
		return err
	})
	a.NoError(err)
	return names
}

func readPartkeyVotingHeader(a *require.Assertions, store db.Accessor) (hdr crypto.OneTimeSignatureSecretsHeader) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		hdr, err = readVotingHeader(tx, partkeyFileVotingTarget)
		return err
	})
	a.NoError(err)
	return hdr
}

func execPartkeySQL(a *require.Assertions, store db.Accessor, query string, args ...any) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	})
	a.NoError(err)
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
	rawVRF := protocol.Encode(part.VRF)
	voting := part.Voting.Snapshot()
	rawVoting := protocol.Encode(&voting)
	rawStateProof := protocol.Encode(part.StateProofSecrets)

	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE ParticipationAccount (
		parent BLOB,

		vrf BLOB,
		voting BLOB,

		firstValid INTEGER,
		lastValid INTEGER,

		keyDilution INTEGER NOT NULL DEFAULT 0,
		stateProof BLOB
	);`)
		if err != nil {
			return err
		}

		if err := setupSchemaForTest(tx, 3); err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO ParticipationAccount (parent, vrf, voting, firstValid, lastValid, keyDilution, stateProof) VALUES (?, ?, ?, ?, ?, ?, ?)",
			part.Parent[:], rawVRF, rawVoting, part.FirstValid, part.LastValid, part.KeyDilution, rawStateProof)
		return err
	})
}

// TestMigrateFromVersion3 converts hand-built version 3 files (a mid-life key
// and an exhausted one) and verifies the header, the rows, the dropped legacy
// column, and that the restored secrets equal the original; a file whose blob
// is damaged must roll back untouched.
func TestMigrateFromVersion3(t *testing.T) {
	partitiontest.PartitionTest(t)

	cases := []struct {
		name      string
		advance   basics.Round
		exhausted bool
		corrupt   bool
	}{
		{"midLife", 55, false, false},
		{"exhausted", 999, true, false},
		{"corruptBlobRollsBack", 55, false, true},
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

			partDB, err := db.MakeAccessor(t.Name()+"_v3", false, true)
			a.NoError(err)
			defer closeDBS(partDB)
			a.NoError(setupTestDBAtVer3(partDB, part.Participation))

			if tc.corrupt {
				// mangle the voting blob so the conversion fails mid-transaction
				var raw []byte
				err = partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
					return tx.QueryRow("SELECT voting FROM ParticipationAccount").Scan(&raw)
				})
				a.NoError(err)
				execPartkeySQL(a, partDB, "UPDATE ParticipationAccount SET voting=?", raw[:len(raw)/2])

				a.Error(Migrate(partDB))

				// the whole migration transaction rolled back
				versions, err := getSchemaVersions(partDB)
				a.NoError(err)
				a.Equal(3, versions[PartTableSchemaName])
				columns := tableColumns(a, partDB, "ParticipationAccount")
				a.Contains(columns, "voting")
				a.NotContains(columns, "votingHeader")
				var n int
				err = partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
					return tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('VotingBatches', 'VotingOffsets')").Scan(&n)
				})
				a.NoError(err)
				a.Zero(n, "migration tables survived the rollback")
				return
			}

			a.NoError(Migrate(partDB))

			versions, err := getSchemaVersions(partDB)
			a.NoError(err)
			a.Equal(PartTableSchemaVersion, versions[PartTableSchemaName])
			a.NoError(testDBContainsAllColumns(partDB))

			// the legacy blob column is gone, the header column is present
			columns := tableColumns(a, partDB, "ParticipationAccount")
			a.Contains(columns, "votingHeader")
			a.NotContains(columns, "voting")

			a.Equal(len(snap.Batches), countTableRows(a, partDB, "VotingBatches"))
			a.Equal(len(snap.Offsets), countTableRows(a, partDB, "VotingOffsets"))
			a.Equal(snap.Header(), readPartkeyVotingHeader(a, partDB))

			// full restore equals the original
			restored, err := RestoreParticipation(partDB)
			a.NoError(err)
			a.Equal(encodedVotingSnapshot(part.Voting), encodedVotingSnapshot(restored.Voting))
			a.Equal(part.Parent, restored.Parent)
			a.Equal(part.KeyDilution, restored.KeyDilution)
		})
	}
}

// TestSyncVotingRows drives the per-round synchronizer through every
// transition against a real store, checking the rows, the header, repair of
// drifted rows, and the forward-security guard.
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
			stored, err := readVotingHeader(tx, partkeyFileVotingTarget)
			if err != nil {
				return err
			}
			return syncVotingRows(tx, partkeyFileVotingTarget, stored, votingSnapshot(mem))
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
	execPartkeySQL(a, partDB, "INSERT INTO VotingOffsets (batch, off, data) VALUES (4, 0, x'00')")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 4}, "repair after stray row")
	execPartkeySQL(a, partDB, "DELETE FROM VotingOffsets WHERE off=(SELECT MIN(off) FROM VotingOffsets)")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 5}, "repair after lost row")

	// stored header ahead of memory (on either cursor field): refused,
	// nothing written
	current := votingSnapshot(secrets).Header()
	ahead := current
	ahead.FirstOffset++
	ahead.OffsetCount--
	execPartkeySQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", protocol.Encode(&ahead))
	a.ErrorContains(sync(secrets), "refusing to resurrect")
	a.Equal(ahead, readPartkeyVotingHeader(a, partDB))
	ahead = current
	ahead.FirstBatch++
	execPartkeySQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", protocol.Encode(&ahead))
	a.ErrorContains(sync(secrets), "refusing to resurrect")
	execPartkeySQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", protocol.Encode(&current))

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

// TestDeleteOldKeysRefusesUnsafeStore verifies DeleteOldKeys writes nothing
// when the stored header cannot be trusted: an undecodable header fails
// closed, and a header ahead of memory is refused rather than rewound (a
// rewrite from memory could resurrect retired keys either way).
func TestDeleteOldKeysRefusesUnsafeStore(t *testing.T) {
	partitiontest.PartitionTest(t)

	cases := []struct {
		name    string
		header  func(current crypto.OneTimeSignatureSecretsHeader) []byte
		wantErr string
	}{
		{"undecodableHeader", func(crypto.OneTimeSignatureSecretsHeader) []byte { return []byte{0xff, 0x00} }, "undecodable"},
		{"futureCursor", func(h crypto.OneTimeSignatureSecretsHeader) []byte {
			h.FirstBatch += 5
			h.BatchCount -= 5
			return protocol.Encode(&h)
		}, "refusing to resurrect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			const dilution = 10
			part, partDB := makeSmallTestKey(t, a, 0, 300, dilution)
			defer closeDBS(partDB)

			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			a.NoError(<-part.DeleteOldKeys(basics.Round(25), proto))
			batchRows := countTableRows(a, partDB, "VotingBatches")
			offsetRows := countTableRows(a, partDB, "VotingOffsets")

			execPartkeySQL(a, partDB, "UPDATE ParticipationAccount SET votingHeader=?", tc.header(votingSnapshot(part.Voting).Header()))

			err := <-part.DeleteOldKeys(basics.Round(26), proto)
			a.ErrorContains(err, tc.wantErr)
			a.Equal(batchRows, countTableRows(a, partDB, "VotingBatches"), "rows written despite an unsafe stored header")
			a.Equal(offsetRows, countTableRows(a, partDB, "VotingOffsets"))
		})
	}
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
		{"wrongOffsetBatch", "UPDATE VotingOffsets SET batch=batch+1 WHERE off=(SELECT MIN(off) FROM VotingOffsets)", "expected batch"},
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

			execPartkeySQL(a, partDB, tc.tamperSQL)
			_, err = RestoreParticipationUnmigrated(partDB)
			a.ErrorContains(err, tc.wantErr)
			// the sentinel lets the node quarantine the file as *.old
			a.ErrorIs(err, ErrCorruptedVotingData)
		})
	}
}
