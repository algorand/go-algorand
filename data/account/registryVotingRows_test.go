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
// with identical restored secrets.  A blob that cannot be converted fails the
// upgrade.
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
	// a legacy record stored without voting secrets (empty blob)
	noVoting := makeTestParticipation(a, 3, 1, 200, dilution)
	noVoting.Voting = nil
	// a legacy record whose blob decodes but cannot be converted: offset
	// subkeys with no expanded batch (FirstBatch 0)
	unconvertible := makeTestParticipation(a, 4, 1, 200, dilution)
	unconvertible.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(55, dilution), dilution)
	unconvertibleSnap := unconvertible.Voting.Snapshot()
	unconvertibleSnap.FirstBatch = 0
	unconvertibleBlob := protocol.Encode(&unconvertibleSnap)

	// buildV1 builds the version-1 schema by hand and inserts the records
	// with legacy blobs
	buildV1 := func(name string, parts []Participation) db.Pair {
		rootDB, err := db.OpenPair(name, true)
		a.NoError(err)
		err = rootDB.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			for _, ddl := range []string{createKeysets, createRollingV1, createStateProof} {
				if _, err := tx.Exec(ddl); err != nil {
					return err
				}
			}
			if _, err := db.SetUserVersion(ctx, tx, 1); err != nil {
				return err
			}
			for _, p := range parts {
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
				var rawVoting []byte
				switch {
				case id == unconvertible.ID():
					rawVoting = unconvertibleBlob
				case p.Voting != nil:
					rawVoting = protocol.Encode(p.Voting)
				}
				if _, err = tx.Exec("INSERT INTO Rolling (pk, voting) VALUES (?, ?)", pk, rawVoting); err != nil {
					return err
				}
			}
			return nil
		})
		a.NoError(err)
		return rootDB
	}

	// opening the registry runs dbSchemaUpgrade1
	rootDB := buildV1(t.Name(), []Participation{midLife, exhausted, noVoting})
	registry, err := makeParticipationRegistry(rootDB, logging.TestingLog(t))
	a.NoError(err)
	defer registryCloseTest(t, registry, "")

	err = rootDB.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		version, err := db.GetUserVersion(ctx, tx)
		a.Equal(int32(2), version)
		return err
	})
	a.NoError(err)
	a.True(hasColumn(a, rootDB.Rdb, "Rolling", "votingHeader"))
	a.False(hasColumn(a, rootDB.Rdb, "Rolling", "voting"))
	requireNoAutoIndex(a, rootDB.Rdb)

	// only the mid-life key contributes rows; the exhausted one has none
	a.Equal(len(midLife.Voting.Batches), countTableRows(a, registry.store.Rdb, "VotingBatches"))
	a.Equal(len(midLife.Voting.Offsets), countTableRows(a, registry.store.Rdb, "VotingOffsets"))
	a.Equal(votingSnapshot(midLife.Voting).Header(), registryReadVotingHeader(a, registry, midLife.ID()))
	a.True(registryReadVotingHeader(a, registry, exhausted.ID()).Exhausted())

	// cache built from the converted store equals the original secrets
	for _, p := range []Participation{midLife, exhausted} {
		record := registry.Get(p.ID())
		a.False(record.IsZero())
		a.Equal(encodedVotingSnapshot(p.Voting), encodedVotingSnapshot(record.Voting))
	}

	// the record without voting secrets loads as a zero-value placeholder
	// (TestFlushWithoutVotingSecrets covers flushing it)
	a.Empty(registryReadRawVotingHeader(a, registry, noVoting.ID()))
	a.True(registry.Get(noVoting.ID()).Voting.MsgIsZero())

	// the unconvertible record fails the upgrade, and with it the open
	// (db.Initialize reports only the schema versions; the cause is logged)
	badDB := buildV1(t.Name()+"_unconvertible", []Participation{midLife, unconvertible})
	_, err = makeParticipationRegistry(badDB, logging.TestingLog(t))
	a.ErrorContains(err, "failed to upgrade database")
}

// TestFlushWithoutVotingSecrets verifies a key stored without voting secrets
// keeps flushing its rolling fields: the cache holds a zero-value Voting for
// it (Duplicate never returns nil), which must not be mistaken for a key
// whose stored header went missing.
func TestFlushWithoutVotingSecrets(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 1, 1, 200, 10)
	p.Voting = nil
	p.VRF = nil
	id, err := registry.Insert(p)
	a.NoError(err)
	a.NoError(registry.Register(id, 1))
	a.NoError(registry.Flush(defaultTimeout))
	a.Empty(registryReadRawVotingHeader(a, registry, id))

	// the per-round deletion pass hands the flush a zero-value Voting
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for round := basics.Round(10); round <= 30; round += 10 {
		a.NoError(registry.DeleteExpired(round, proto))
		a.NoError(registry.Record(p.Parent, round, Vote))
		a.NoError(registry.Flush(defaultTimeout), "round %d", round)
	}

	// the rolling fields landed and nothing was invented for the voting state
	a.NoError(registry.initializeCache())
	record := registry.Get(id)
	a.False(record.IsZero())
	a.Equal(basics.Round(30), record.LastVote)
	a.True(record.Voting.MsgIsZero())
	a.Empty(registryReadRawVotingHeader(a, registry, id))
	a.Zero(countTableRows(a, registry.store.Rdb, "VotingBatches"))
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
	a.Equal(len(p.Voting.Batches), countTableRows(a, registry.store.Rdb, "VotingBatches"))
	a.Equal(len(p.Voting.Offsets), countTableRows(a, registry.store.Rdb, "VotingOffsets"))

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
	a.Equal(len(p.Voting.Offsets), countTableRows(a, registry.store.Rdb, "VotingOffsets"))
	a.Equal(basics.Round(38), registry.Get(id).LastVote)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for _, round := range []basics.Round{40, 47, 61, 100, 200, 300, 309} {
		a.NoError(registry.DeleteExpired(round, proto))
		a.NoError(registry.Flush(defaultTimeout))
		reloadEqualsCache(fmt.Sprintf("round %d", round))
	}

	// end of life: every subkey row erased, nothing left to resurrect
	a.Zero(countTableRows(a, registry.store.Rdb, "VotingOffsets"), "retired offset subkeys survived in the registry")
	a.Zero(countTableRows(a, registry.store.Rdb, "VotingBatches"))
	a.True(registryReadVotingHeader(a, registry, id).Exhausted())
	record := registry.Get(id)
	a.Empty(record.Voting.Offsets)
	a.Empty(record.Voting.Batches)
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

// TestDeleteExpiredMergesOnlyVoting verifies the per-round deletion pass,
// whose snapshots are taken before it re-acquires the lock, merges only the
// advanced voting secrets into the cache: a Register or Record that landed in
// between must survive instead of being overwritten by the stale snapshot and
// flushed over.
func TestDeleteExpiredMergesOnlyVoting(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	const dilution = 10
	p := makeTestParticipation(a, 1, 1, 200, dilution)
	id, err := registry.Insert(p)
	a.NoError(err)

	// the snapshot DeleteExpired would work on, taken before the concurrent
	// updates below
	stale := registry.Get(id)
	a.Zero(stale.EffectiveFirst)
	a.Zero(stale.LastVote)

	// concurrent registration and vote recording land in the live entry
	a.NoError(registry.Register(id, 1))
	a.NoError(registry.Record(p.Parent, 5, Vote))
	live := registry.Get(id)
	a.Equal(basics.Round(1), live.EffectiveFirst)
	a.Equal(basics.Round(5), live.LastVote)

	// the deletion pass advances the stale snapshot's secrets and merges
	stale.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(6, dilution), dilution)
	registry.mutex.Lock()
	registry.mergeAdvancedVoting([]ParticipationRecord{stale})
	_, dirty := registry.dirty[id]
	registry.mutex.Unlock()
	a.True(dirty)

	merged := registry.Get(id)
	a.Equal(basics.Round(1), merged.EffectiveFirst, "registration lost to a stale snapshot")
	a.Equal(p.LastValid, merged.EffectiveLast)
	a.Equal(basics.Round(5), merged.LastVote, "recorded vote lost to a stale snapshot")
	a.Equal(encodedVotingSnapshot(stale.Voting), encodedVotingSnapshot(merged.Voting), "advanced voting secrets not merged")

	// and the flush persists the merged state, not the snapshot
	a.NoError(registry.Flush(defaultTimeout))
	a.NoError(registry.initializeCache())
	reloaded := registry.Get(id)
	a.Equal(basics.Round(1), reloaded.EffectiveFirst)
	a.Equal(basics.Round(5), reloaded.LastVote)
	a.Equal(encodedVotingSnapshot(stale.Voting), encodedVotingSnapshot(reloaded.Voting))

	// a snapshot of a record deleted in between must not resurrect it
	a.NoError(registry.Delete(id))
	registry.mutex.Lock()
	registry.mergeAdvancedVoting([]ParticipationRecord{stale})
	registry.mutex.Unlock()
	a.True(registry.Get(id).IsZero())
}
