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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

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

func encodedVotingSnapshot(secrets *crypto.OneTimeSignatureSecrets) []byte {
	snap := secrets.Snapshot()
	return protocol.Encode(&snap)
}

// registryPK returns the Keysets primary key of a stored participation ID.
func registryPK(a *require.Assertions, registry *participationDB, id ParticipationID) int64 {
	return int64(queryInt(a, registry.store.Rdb, selectPK, id[:]))
}

// TestSyncVotingRows drives the per-round synchronizer through every
// transition against a real registry, checking the rows, the header, repair
// of drifted rows, and the refusals that protect forward security (a stored
// cursor ahead of memory, an undecodable stored header).
func TestSyncVotingRows(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	const dilution = 8
	// FirstValid 0 gives a key whose FirstBatch is 0 (the uint64 edge for
	// batch-1 arithmetic); batches 0..12
	p := makeTestParticipation(a, 1, 0, 100, dilution)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.NoError(registry.Flush(defaultTimeout))
	pk := registryPK(a, registry, id)
	secrets := p.Voting

	// sync brings the store from its stored header to the given memory state
	// and stores the resulting header, as updateRollingFields does
	sync := func(mem *crypto.OneTimeSignatureSecrets) error {
		return registry.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			stored, err := readVotingHeader(tx, pk)
			if err != nil {
				return err
			}
			hdr, err := syncVotingRows(tx, pk, stored, votingSnapshot(mem))
			if err != nil || hdr == nil {
				return err
			}
			return updateVotingHeader(tx, pk, *hdr)
		})
	}
	// reload reads the key back from the registry's tables
	reload := func() *crypto.OneTimeSignatureSecrets {
		a.NoError(registry.initializeCache())
		record := registry.Get(id)
		a.False(record.IsZero())
		return record.Voting
	}
	// advance moves memory to id, syncs, and checks header, row counts, and
	// reassembly against memory
	advance := func(id crypto.OneTimeSignatureIdentifier, what string) {
		secrets.DeleteBeforeFineGrained(id, dilution)
		a.NoError(sync(secrets), what)
		hdr := votingSnapshot(secrets).Header()
		a.Equal(hdr, registryReadVotingHeader(a, registry, p.ID()), what)
		a.Equal(int(hdr.BatchCount), countTableRows(a, registry.store.Rdb, "VotingBatches"), what)
		a.Equal(int(hdr.OffsetCount), countTableRows(a, registry.store.Rdb, "VotingOffsets"), what)
		a.Equal(encodedVotingSnapshot(secrets), encodedVotingSnapshot(reload()), what)
	}

	// fresh: unchanged header is a no-op
	a.Zero(registryReadVotingHeader(a, registry, id).FirstBatch)
	a.NoError(sync(secrets))
	advance(crypto.OneTimeSignatureIdentifier{}, "unchanged")

	advance(crypto.OneTimeSignatureIdentifier{Batch: 0, Offset: 2}, "first expansion")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 0, Offset: 5}, "same-batch trim")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 1, Offset: 1}, "rollover")
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 3}, "multi-batch jump")

	// drifted rows are repaired by the next transition: a stray row below the
	// cursor makes the trim remove too many rows, a lost row too few
	execSQL(a, registry.store.Wdb, "INSERT INTO VotingOffsets (pk, off, data) VALUES (?, 0, x'00')", pk)
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 4}, "repair after stray row")
	execSQL(a, registry.store.Wdb, "DELETE FROM VotingOffsets WHERE pk=? AND off=(SELECT MIN(off) FROM VotingOffsets WHERE pk=?)", pk, pk)
	advance(crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 5}, "repair after lost row")

	// stored header ahead of memory (on either cursor field): refused,
	// nothing written
	current := votingSnapshot(secrets).Header()
	ahead := current
	ahead.FirstOffset++
	ahead.OffsetCount--
	execSQL(a, registry.store.Wdb, updateVotingHeaderPK, protocol.Encode(&ahead), pk)
	a.ErrorContains(sync(secrets), "refusing to resurrect")
	a.Equal(ahead, registryReadVotingHeader(a, registry, id))
	ahead = current
	ahead.FirstBatch++
	execSQL(a, registry.store.Wdb, updateVotingHeaderPK, protocol.Encode(&ahead), pk)
	a.ErrorContains(sync(secrets), "refusing to resurrect")
	// ... and so is an undecodable stored header (failing closed: a rewrite
	// from possibly-stale memory could resurrect retired keys)
	execSQL(a, registry.store.Wdb, updateVotingHeaderPK, []byte{0xff, 0x00}, pk)
	batchRows, offsetRows := countTableRows(a, registry.store.Rdb, "VotingBatches"), countTableRows(a, registry.store.Rdb, "VotingOffsets")
	a.ErrorContains(sync(secrets), "undecodable")
	a.Equal(batchRows, countTableRows(a, registry.store.Rdb, "VotingBatches"))
	a.Equal(offsetRows, countTableRows(a, registry.store.Rdb, "VotingOffsets"))
	execSQL(a, registry.store.Wdb, updateVotingHeaderPK, protocol.Encode(&current), pk)

	// jump that runs out of batches: exhausted, every row erased, and a
	// reload cannot sign an identifier that was live a moment ago
	lastLive := crypto.OneTimeSignatureIdentifier{Batch: 5, Offset: 6}
	advance(crypto.OneTimeSignatureIdentifier{Batch: 50}, "exhausted")
	a.True(registryReadVotingHeader(a, registry, id).Exhausted())
	msg := crypto.OneTimeSignatureSubkeyBatchID{Batch: 1}
	a.False(secrets.OneTimeSignatureVerifier.Verify(lastLive, msg, reload().Sign(lastLive, msg)), "reloaded secrets signed a retired identifier")

	// an exhausted store is terminal: a live copy of the key is refused
	a.ErrorContains(sync(crypto.GenerateOneTimeSignatureSecrets(0, 3)), "refusing to resurrect")
}
