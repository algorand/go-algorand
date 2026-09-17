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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func registryCountRows(a *require.Assertions, registry *participationDB, table string) (n int) {
	err := registry.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRow("SELECT count(*) FROM " + table).Scan(&n)
	})
	a.NoError(err)
	return n
}

func registryReadRawVotingHeader(a *require.Assertions, registry *participationDB, id ParticipationID) (raw []byte) {
	err := registry.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRow(selectRollingVotingByID, id[:]).Scan(new(int64), &raw)
	})
	a.NoError(err)
	return raw
}

func registryReadVotingHeader(a *require.Assertions, registry *participationDB, id ParticipationID) crypto.OneTimeSignatureSecretsHeader {
	hdr, err := decodeVotingHeader(registryReadRawVotingHeader(a, registry, id))
	a.NoError(err)
	return hdr
}

func registryExecSQL(a *require.Assertions, registry *participationDB, query string, args ...any) {
	err := registry.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	})
	a.NoError(err)
}

// registryEvict drops a key from the cache the way the corrupt-record
// exclusion at load does, leaving its rows on disk.
func registryEvict(registry *participationDB, id ParticipationID) {
	registry.mutex.Lock()
	delete(registry.cache, id)
	delete(registry.dirty, id)
	registry.mutex.Unlock()
}

// createRollingV1 is the Rolling table as created by user_version 1
// registries: the whole voting secrets in a single blob column.
const createRollingV1 = `CREATE TABLE Rolling (
		pk INTEGER PRIMARY KEY NOT NULL,

		lastVoteRound               INTEGER,
		lastBlockProposalRound      INTEGER,
		lastStateProofRound         INTEGER,
		effectiveFirstRound         INTEGER,
		effectiveLastRound          INTEGER,

		voting BLOB
	)`

// TestRegistryMigrationV1ToV2 hand-builds a version-1 registry (whole voting
// blob in Rolling.voting) holding a mid-life key and an exhausted key, and
// verifies opening it converts to a votingHeader column plus per-subkey rows
// with identical restored secrets.
func TestRegistryMigrationV1ToV2(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const dilution = 10
	midLife := makeTestParticipation(a, 1, 1, 200, dilution)
	midLife.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(55, dilution), dilution)
	a.NotEmpty(midLife.Voting.Offsets)
	exhausted := makeTestParticipation(a, 2, 1, 200, dilution)
	exhausted.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(999, dilution), dilution)
	a.True(votingSnapshot(exhausted.Voting).Header().Exhausted())

	rootDB, err := db.OpenPair(t.Name(), true)
	a.NoError(err)

	// build the version-1 schema by hand and insert the records with legacy blobs
	err = rootDB.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for _, ddl := range []string{createKeysets, createRollingV1, createStateProof} {
			if _, err := tx.Exec(ddl); err != nil {
				return err
			}
		}
		if _, err := db.SetUserVersion(ctx, tx, 1); err != nil {
			return err
		}
		for _, p := range []Participation{midLife, exhausted} {
			id := p.ID()
			result, err := tx.Exec(insertKeysetQuery, id[:], p.Parent[:], p.FirstValid, p.LastValid, p.KeyDilution,
				protocol.Encode(p.VRF), protocol.Encode(&p.StateProofSecrets.SignerContext))
			if err != nil {
				return err
			}
			pk, err := result.LastInsertId()
			if err != nil {
				return err
			}
			if _, err = tx.Exec("INSERT INTO Rolling (pk, voting) VALUES (?, ?)", pk, protocol.Encode(p.Voting)); err != nil {
				return err
			}
		}
		return nil
	})
	a.NoError(err)

	// opening the registry runs dbSchemaUpgrade1
	registry, err := makeParticipationRegistry(rootDB, logging.TestingLog(t))
	a.NoError(err)
	defer registryCloseTest(t, registry, "")

	err = rootDB.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		version, err := db.GetUserVersion(ctx, tx)
		a.Equal(int32(2), version)
		columns, err2 := tableColumnsTx(tx, "Rolling")
		a.NoError(err2)
		a.Contains(columns, "votingHeader")
		a.NotContains(columns, "voting")
		return err
	})
	a.NoError(err)

	// only the mid-life key contributes rows; the exhausted one has none
	a.Equal(len(midLife.Voting.Batches), registryCountRows(a, registry, "VotingBatches"))
	a.Equal(len(midLife.Voting.Offsets), registryCountRows(a, registry, "VotingOffsets"))
	a.Equal(votingSnapshot(midLife.Voting).Header(), registryReadVotingHeader(a, registry, midLife.ID()))
	a.True(registryReadVotingHeader(a, registry, exhausted.ID()).Exhausted())

	// cache built from the converted store equals the original secrets
	for _, p := range []Participation{midLife, exhausted} {
		record := registry.Get(p.ID())
		a.False(record.IsZero())
		a.Equal(encodedVotingSnapshot(p.Voting), encodedVotingSnapshot(record.Voting))
	}
}

// TestRegistryKeyLifecycle inserts a mid-life key and walks it through
// DeleteExpired+Flush to the end of its life, verifying after every flush
// that the store reassembles to exactly the cached secrets, that a flush
// without voting progress leaves the voting state untouched, and that the
// end of life erases every subkey row.
func TestRegistryKeyLifecycle(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	const dilution = 10
	// LastValid 309 puts the end of validity at the very end of the final
	// batch (30), so exhaustion happens while the record is still registered
	p := makeTestParticipation(a, 1, 1, 309, dilution)
	p.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(37, dilution), dilution)
	a.NotEmpty(p.Voting.Offsets)

	id, err := registry.Insert(p)
	a.NoError(err)
	a.NoError(registry.Register(id, 1))
	a.NoError(registry.Flush(defaultTimeout))

	// a mid-life insert stores the offsets too
	a.Equal(len(p.Voting.Batches), registryCountRows(a, registry, "VotingBatches"))
	a.Equal(len(p.Voting.Offsets), registryCountRows(a, registry, "VotingOffsets"))

	reloadEqualsCache := func(what string) {
		cached := registry.Get(id)
		a.False(cached.IsZero(), what)
		a.NoError(registry.initializeCache())
		reloaded := registry.Get(id)
		a.False(reloaded.IsZero(), what)
		a.Equal(encodedVotingSnapshot(cached.Voting), encodedVotingSnapshot(reloaded.Voting), what)
	}
	reloadEqualsCache("insert")

	// a flush without voting progress leaves header and rows untouched
	headerBefore := registryReadRawVotingHeader(a, registry, id)
	a.NoError(registry.Record(p.Parent, 38, Vote))
	a.NoError(registry.Flush(defaultTimeout))
	a.Equal(headerBefore, registryReadRawVotingHeader(a, registry, id))
	a.Equal(len(p.Voting.Offsets), registryCountRows(a, registry, "VotingOffsets"))
	a.Equal(basics.Round(38), registry.Get(id).LastVote)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for _, round := range []basics.Round{40, 47, 61, 100, 200, 300, 309} {
		a.NoError(registry.DeleteExpired(round, proto))
		a.NoError(registry.Flush(defaultTimeout))
		reloadEqualsCache(fmt.Sprintf("round %d", round))
	}

	// end of life: every subkey row erased, nothing left to resurrect
	a.Zero(registryCountRows(a, registry, "VotingOffsets"), "retired offset subkeys survived in the registry")
	a.Zero(registryCountRows(a, registry, "VotingBatches"))
	a.True(registryReadVotingHeader(a, registry, id).Exhausted())
	record := registry.Get(id)
	a.Empty(record.Voting.Offsets)
	a.Empty(record.Voting.Batches)
}

// TestRegistryExcludesCorruptRecord verifies a record whose voting data is
// damaged is excluded from the cache with a warning instead of blocking the
// whole registry (and the node) from loading, that healthy records survive,
// and what a re-insert of the key from its key file may do: replace the rows
// when the stored header still establishes the deletion state (lost subkey
// rows), but nothing when it does not (an undecodable, empty, or foreign
// header) — the registry may be ahead of the key file, so the copy must
// neither reach the store nor become usable from the cache.
func TestRegistryExcludesCorruptRecord(t *testing.T) {
	partitiontest.PartitionTest(t)

	const dilution = 10
	damageHeader := func(a *require.Assertions, registry *participationDB, corruptID ParticipationID, header any) {
		registryExecSQL(a, registry, "UPDATE Rolling SET votingHeader=? WHERE pk=(SELECT pk FROM Keysets WHERE participationID=?)", header, corruptID[:])
	}
	cases := []struct {
		name string
		// rounds voted (and persisted) before the damage, so the registry is
		// ahead of the fresh key-file copy that is re-inserted later
		advance basics.Round
		damage  func(a *require.Assertions, registry *participationDB, corruptID ParticipationID, healthy Participation)
		// refused is the error the re-insert must fail with; empty means it
		// must succeed and replace the rows
		refused string
	}{
		{"missingBatchRow", 0, func(a *require.Assertions, registry *participationDB, corruptID ParticipationID, _ Participation) {
			registryExecSQL(a, registry, "DELETE FROM VotingBatches WHERE batch=(SELECT MAX(batch) FROM VotingBatches) AND pk=(SELECT pk FROM Keysets WHERE participationID=?)", corruptID[:])
		}, ""},
		{"undecodableHeader", 150, func(a *require.Assertions, registry *participationDB, corruptID ParticipationID, _ Participation) {
			damageHeader(a, registry, corruptID, []byte{0xff, 0x00})
		}, "undecodable"},
		{"emptyHeader", 150, func(a *require.Assertions, registry *participationDB, corruptID ParticipationID, _ Participation) {
			damageHeader(a, registry, corruptID, nil)
		}, "no voting header stored"},
		{"foreignHeader", 0, func(a *require.Assertions, registry *participationDB, corruptID ParticipationID, healthy Participation) {
			// another key's header with a cursor ahead of the stored rows
			foreign := votingSnapshot(healthy.Voting).Header()
			foreign.FirstBatch += 5
			foreign.BatchCount -= 5
			damageHeader(a, registry, corruptID, protocol.Encode(&foreign))
		}, "different voting key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			registry, dbfile := getRegistry(t)
			defer registryCloseTest(t, registry, dbfile)

			pHealthy := makeTestParticipation(a, 1, 1, 200, dilution)
			healthyID, err := registry.Insert(pHealthy)
			a.NoError(err)
			pCorrupt := makeTestParticipation(a, 2, 1, 200, dilution)
			corruptID, err := registry.Insert(pCorrupt)
			a.NoError(err)
			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			if tc.advance != 0 {
				a.NoError(registry.DeleteExpired(tc.advance, proto))
			}
			a.NoError(registry.Flush(defaultTimeout))

			corruptRows := func() (keysets, batches int) {
				err := registry.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
					if err := tx.QueryRow("SELECT count(*) FROM Keysets WHERE participationID=?", corruptID[:]).Scan(&keysets); err != nil {
						return err
					}
					return tx.QueryRow("SELECT count(*) FROM VotingBatches WHERE pk=(SELECT pk FROM Keysets WHERE participationID=?)", corruptID[:]).Scan(&batches)
				})
				a.NoError(err)
				return keysets, batches
			}
			_, batchesBefore := corruptRows()

			tc.damage(a, registry, corruptID, pHealthy)

			a.NoError(registry.initializeCache())
			a.True(registry.Get(corruptID).IsZero(), "corrupt record not excluded")
			a.False(registry.Get(healthyID).IsZero(), "healthy record lost")

			// re-insert the key-file copy, as loadParticipationKeys does in
			// the same startup
			reinsertedID, err := registry.Insert(pCorrupt)
			a.Equal(corruptID, reinsertedID)

			keysets, batches := corruptRows()
			a.Equal(1, keysets, "duplicate Keysets row after re-insert")
			if tc.refused != "" {
				// refused: the copy is not usable from the cache, the stored
				// rows are untouched, and a reload keeps the record excluded,
				// so no retired round is signable
				a.ErrorContains(err, tc.refused)
				a.True(registry.Get(corruptID).IsZero(), "rejected copy usable from the cache")
				a.Equal(batchesBefore, batches, "stored rows replaced despite an unusable header")
				a.NoError(registry.Flush(defaultTimeout))
				a.NoError(registry.initializeCache())
				a.True(registry.Get(corruptID).IsZero(), "older copy resurrected the excluded record")
				a.False(registry.Get(healthyID).IsZero())
				return
			}

			// replaced with exactly the inserted copy, and the next round's
			// deletion flush works for every key
			a.NoError(err)
			a.Equal(len(pCorrupt.Voting.Batches), batches, "re-inserted copy not stored intact")
			a.Equal(votingSnapshot(pCorrupt.Voting).Header(), registryReadVotingHeader(a, registry, corruptID))
			a.NoError(registry.DeleteExpired(1, proto))
			a.NoError(registry.Flush(defaultTimeout))
			a.NoError(registry.initializeCache())
			a.False(registry.Get(corruptID).IsZero(), "re-inserted record not restored")
			a.False(registry.Get(healthyID).IsZero(), "healthy record lost after re-insert")
		})
	}
}

// TestInsertFastForwardsLaggingCopy verifies re-inserting a lagging copy of a
// key (the .partkey file and the registry are independent stores) cannot
// rewind the persisted deletion cursor and resurrect retired rounds: the
// inserted copy is fast-forwarded to the stored cursor, and an exhausted
// store exhausts the copy.
func TestInsertFastForwardsLaggingCopy(t *testing.T) {
	partitiontest.PartitionTest(t)

	const dilution = 10
	cases := []struct {
		name          string
		lastValid     basics.Round
		advance       []basics.Round // DeleteExpired rounds before the copy is re-inserted
		lagRound      basics.Round   // how far the lagging copy got
		retiredRound  basics.Round   // must not be signable after the re-insert
		liveRound     basics.Round   // must still be signable (0: none, the key is exhausted)
		minFirstBatch uint64
	}{
		// vote through round 999 (stored cursor at batch 101), copy at round 500
		{"midLife", 3000, []basics.Round{999}, 500, 500, 1500, 101},
		// LastValid 209 keeps the record registered through the end of its
		// final batch (20): expand it, exhaust it, copy at round 100
		{"exhausted", 209, []basics.Round{200, 209}, 100, 205, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			registry, dbfile := getRegistry(t)
			defer registryCloseTest(t, registry, dbfile)

			p := makeTestParticipation(a, 1, 1, tc.lastValid, dilution)
			behind := p
			behindVoting := p.Voting.Snapshot()
			behind.Voting = &behindVoting

			id, err := registry.Insert(p)
			a.NoError(err)
			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			for _, round := range tc.advance {
				a.NoError(registry.DeleteExpired(round, proto))
			}
			a.NoError(registry.Flush(defaultTimeout))
			stored := registryReadVotingHeader(a, registry, id)
			a.Equal(tc.liveRound == 0, stored.Exhausted())

			// the lagging copy only reached lagRound; evict the key and re-insert it
			registryEvict(registry, id)
			behind.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(tc.lagRound, dilution), dilution)
			reinsertedID, err := registry.Insert(behind)
			a.NoError(err)
			a.Equal(id, reinsertedID)
			a.NoError(registry.Flush(defaultTimeout))

			// the persisted cursor did not rewind
			after := registryReadVotingHeader(a, registry, id)
			a.GreaterOrEqual(after.FirstBatch, tc.minFirstBatch, "persisted deletion cursor rewound")
			a.Equal(stored.Exhausted(), after.Exhausted())
			if stored.Exhausted() {
				a.Zero(registryCountRows(a, registry, "VotingOffsets"), "retired offsets regenerated")
				a.Zero(registryCountRows(a, registry, "VotingBatches"))
			}

			// after a reload, retired rounds cannot produce valid signatures
			// while live rounds still can
			a.NoError(registry.initializeCache())
			record := registry.Get(id)
			a.False(record.IsZero())
			msg := crypto.OneTimeSignatureSubkeyBatchID{Batch: 1}
			retired := basics.OneTimeIDForRound(tc.retiredRound, dilution)
			a.False(p.Voting.OneTimeSignatureVerifier.Verify(retired, msg, record.Voting.Sign(retired, msg)), "retired round signed after re-inserting a lagging copy")
			if tc.liveRound != 0 {
				live := basics.OneTimeIDForRound(tc.liveRound, dilution)
				a.True(p.Voting.OneTimeSignatureVerifier.Verify(live, msg, record.Voting.Sign(live, msg)), "live round unusable after fast-forward")
			}
		})
	}
}

// TestRegisterStaleSnapshotDoesNotTouchVoting reproduces a registration
// whose record snapshot predates a flush that already advanced the persisted
// deletion cursor (a flush lagging a full round).  Registration must persist
// only the registration window and leave the newer cursor alone, instead of
// failing with the monotonicity error.
func TestRegisterStaleSnapshotDoesNotTouchVoting(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	const dilution = 10
	p := makeTestParticipation(a, 1, 1, 200, dilution)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.NoError(registry.Flush(defaultTimeout))

	// snapshot the record as Register would, before the cursor advances
	stale := registry.Get(id)
	stale.EffectiveFirst = 1
	stale.EffectiveLast = stale.LastValid
	staleOp := &registerOp{updated: map[ParticipationID]updatingParticipationRecord{
		id: {ParticipationRecord: stale, required: true},
	}}

	// a full round of deletion is flushed first
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	a.NoError(registry.DeleteExpired(50, proto))
	a.NoError(registry.Flush(defaultTimeout))
	advanced := registry.Get(id)
	a.NotZero(advanced.Voting.FirstBatch)

	// the lagging registration lands afterwards and must succeed
	registry.writeQueue <- makeOpRequest(staleOp)
	a.NoError(registry.Flush(defaultTimeout))

	// the persisted cursor is the advanced one and the registration is stored
	a.Equal(votingSnapshot(advanced.Voting).Header(), registryReadVotingHeader(a, registry, id))
	a.NoError(registry.initializeCache())
	reloaded := registry.Get(id)
	a.Equal(basics.Round(1), reloaded.EffectiveFirst)
	a.Equal(p.LastValid, reloaded.EffectiveLast)
	a.Equal(encodedVotingSnapshot(advanced.Voting), encodedVotingSnapshot(reloaded.Voting))

	// the public Register path leaves pending changes dirty for the flush
	a.NoError(registry.DeleteExpired(60, proto))
	registry.mutex.RLock()
	_, dirtyBefore := registry.dirty[id]
	registry.mutex.RUnlock()
	a.True(dirtyBefore)
	a.NoError(registry.Register(id, 61))
	registry.mutex.RLock()
	_, dirtyAfter := registry.dirty[id]
	registry.mutex.RUnlock()
	a.True(dirtyAfter, "Register must not clear a pending flush")
	a.NoError(registry.Flush(defaultTimeout))
}

// TestFlushIsolatesCorruptHeader verifies a key whose stored header is
// undecodable fails closed (nothing rewritten from memory) without taking the
// other keys' flush down with it.
func TestFlushIsolatesCorruptHeader(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	pA := makeTestParticipation(a, 1, 1, 200, 10)
	idA, err := registry.Insert(pA)
	a.NoError(err)
	pB := makeTestParticipation(a, 2, 1, 200, 10)
	idB, err := registry.Insert(pB)
	a.NoError(err)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	a.NoError(registry.DeleteExpired(20, proto))
	a.NoError(registry.Flush(defaultTimeout))

	// corrupt B's stored header
	registryExecSQL(a, registry, "UPDATE Rolling SET votingHeader=? WHERE pk=(SELECT pk FROM Keysets WHERE participationID=?)", []byte{0xff, 0x00}, idB[:])
	bOffsetRows := func() (n int) {
		err := registry.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			return tx.QueryRow("SELECT count(*) FROM VotingOffsets WHERE pk=(SELECT pk FROM Keysets WHERE participationID=?)", idB[:]).Scan(&n)
		})
		a.NoError(err)
		return n
	}
	bRowsBefore := bOffsetRows()

	// the next round's flush reports B's failure but still persists A
	a.NoError(registry.DeleteExpired(25, proto))
	err = registry.Flush(defaultTimeout)
	a.ErrorContains(err, "undecodable")
	a.Equal(bRowsBefore, bOffsetRows(), "B's rows were rewritten despite an undecodable header")

	cachedA := registry.Get(idA)
	a.Equal(votingSnapshot(cachedA.Voting).Header(), registryReadVotingHeader(a, registry, idA), "A's deletion was not persisted")

	// only B stays dirty for retry
	registry.mutex.RLock()
	_, aDirty := registry.dirty[idA]
	_, bDirty := registry.dirty[idB]
	registry.mutex.RUnlock()
	a.False(aDirty)
	a.True(bDirty)
}
