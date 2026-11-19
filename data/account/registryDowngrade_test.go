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
	"os"
	"path/filepath"
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

// openFileRegistry opens the registry in file as algod does, creating it or
// upgrading it to the current schema.
func openFileRegistry(t *testing.T, file string) *participationDB {
	pair, err := db.OpenErasablePair(file)
	require.NoError(t, err)
	registry, err := makeParticipationRegistry(pair, logging.TestingLog(t))
	require.NoError(t, err)
	return registry
}

// withRegistryFile runs fn in a transaction on its own connection to file.
// fn must report a failure by returning an error, not through a require
// assertion: one that fails inside the transaction ends the goroutine with the
// connection still in use, and closing the accessor then waits forever.
func withRegistryFile(a *require.Assertions, file string, readOnly bool, fn func(ctx context.Context, tx *sql.Tx) error) {
	accessor, err := db.MakeAccessor(file, readOnly, false)
	a.NoError(err)
	defer accessor.Close()
	a.NoError(accessor.Atomic(fn))
}

// dumpRegistryFile returns the schema version and every row of every table
// but EraseWAL's scratch table, to compare a registry before and after an
// operation that must leave it as it was.
func dumpRegistryFile(a *require.Assertions, file string) map[string][][]any {
	dump := make(map[string][][]any)
	withRegistryFile(a, file, true, func(ctx context.Context, tx *sql.Tx) error {
		version, err := db.GetUserVersion(ctx, tx)
		if err != nil {
			return err
		}
		dump["user_version"] = [][]any{{version}}

		var tables []string
		rows, err := tx.Query("SELECT name FROM sqlite_master WHERE type='table' AND name != ? ORDER BY name", walEraseScratchTable)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name string
			if err = rows.Scan(&name); err != nil {
				return err
			}
			tables = append(tables, name)
		}
		rows.Close()

		for _, table := range tables {
			rows, err := tx.Query("SELECT * FROM " + table + " ORDER BY 1, 2")
			if err != nil {
				return err
			}
			cols, err := rows.Columns()
			if err != nil {
				return err
			}
			dump[table] = [][]any{}
			for rows.Next() {
				vals := make([]any, len(cols))
				ptrs := make([]any, len(cols))
				for i := range vals {
					ptrs[i] = &vals[i]
				}
				if err = rows.Scan(ptrs...); err != nil {
					return err
				}
				dump[table] = append(dump[table], vals)
			}
			rows.Close()
		}
		return nil
	})
	return dump
}

// registryFileVersion returns the schema version of the registry in file.
func registryFileVersion(a *require.Assertions, file string) (version int32) {
	withRegistryFile(a, file, true, func(ctx context.Context, tx *sql.Tx) (err error) {
		version, err = db.GetUserVersion(ctx, tx)
		return err
	})
	return version
}

// cycleRecord is what the registry must hold for a key: its encoded voting
// secrets (nil for a key without them) and the round of its last vote.
type cycleRecord struct {
	voting   []byte
	lastVote basics.Round
}

// recordsFromRegistry reads the expected state of every key from an open
// registry; keys it no longer has are left out.
func recordsFromRegistry(registry *participationDB, ids []ParticipationID) map[ParticipationID]cycleRecord {
	records := make(map[ParticipationID]cycleRecord)
	for _, id := range ids {
		record := registry.Get(id)
		if record.IsZero() {
			continue
		}
		var voting []byte
		if !record.Voting.MsgIsZero() {
			voting = encodedVotingSnapshot(record.Voting)
		}
		records[id] = cycleRecord{voting: voting, lastVote: record.LastVote}
	}
	return records
}

// recordsFromV1File reads the state of every key from a version 1 registry
// file, as algod 5.0 would read it.
func recordsFromV1File(a *require.Assertions, file string) map[ParticipationID]cycleRecord {
	records := make(map[ParticipationID]cycleRecord)
	withRegistryFile(a, file, true, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT k.participationID, r.lastVoteRound, r.voting
			FROM Rolling r JOIN Keysets k ON k.pk = r.pk`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rawID, voting []byte
			var lastVote sql.NullInt64
			if err = rows.Scan(&rawID, &lastVote, &voting); err != nil {
				return err
			}
			var id ParticipationID
			copy(id[:], rawID)
			records[id] = cycleRecord{voting: voting, lastVote: basics.Round(lastVote.Int64)}
		}
		return rows.Err()
	})
	return records
}

// requireRegistryV1 checks a downgraded registry file has the version 1
// schema as algod 5.0 creates it, holds exactly the expected keys, and has an
// empty write-ahead log.
func requireRegistryV1(a *require.Assertions, file string, want map[ParticipationID]cycleRecord) {
	a.EqualValues(registrySchemaVotingBlob, registryFileVersion(a, file))
	var ddl string
	withRegistryFile(a, file, true, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='Rolling'").Scan(&ddl)
	})
	a.Equal(createRollingV1, ddl)
	a.Equal(want, recordsFromV1File(a, file))
	if info, err := os.Stat(file + "-wal"); err == nil {
		a.Zero(info.Size(), "the write-ahead log still holds pages")
	}
}

// advanceV1File does to a version 1 registry file what algod 5.0 does once
// round has passed: it deletes the keys that expired before round, moves the
// voting secrets of the others past round, and records a vote by voter in
// round. want is updated to match.
func advanceV1File(a *require.Assertions, file string, round basics.Round, voter ParticipationID, want map[ParticipationID]cycleRecord) {
	withRegistryFile(a, file, false, func(ctx context.Context, tx *sql.Tx) error {
		for _, query := range []string{
			"DELETE FROM StateProofKeys WHERE pk IN (SELECT pk FROM Keysets WHERE lastValidRound < ?)",
			"DELETE FROM Rolling WHERE pk IN (SELECT pk FROM Keysets WHERE lastValidRound < ?)",
			"DELETE FROM Keysets WHERE lastValidRound < ?",
		} {
			if _, err := tx.Exec(query, round); err != nil {
				return err
			}
		}

		type row struct {
			pk       int64
			id       ParticipationID
			dilution uint64
			voting   []byte
		}
		var live []row
		rows, err := tx.Query(`SELECT r.pk, k.participationID, k.keyDilution, r.voting
			FROM Rolling r JOIN Keysets k ON k.pk = r.pk
			WHERE k.firstValidRound <= ?`, round)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r row
			var rawID []byte
			if err = rows.Scan(&r.pk, &rawID, &r.dilution, &r.voting); err != nil {
				return err
			}
			copy(r.id[:], rawID)
			live = append(live, r)
		}
		rows.Close()

		for _, r := range live {
			if len(r.voting) > 0 {
				var secrets crypto.OneTimeSignatureSecrets
				if err = protocol.Decode(r.voting, &secrets); err != nil {
					return err
				}
				secrets.DeleteBeforeFineGrained(basics.OneTimeIDForRound(round+1, r.dilution), r.dilution)
				r.voting = encodedVotingSnapshot(&secrets)
			}
			if _, err = tx.Exec("UPDATE Rolling SET voting=? WHERE pk=?", r.voting, r.pk); err != nil {
				return err
			}
			if r.id == voter {
				if _, err = tx.Exec("UPDATE Rolling SET lastVoteRound=? WHERE pk=?", round, r.pk); err != nil {
					return err
				}
			}
		}
		return nil
	})
	clear(want)
	for id, record := range recordsFromV1File(a, file) {
		want[id] = record
	}
}

// TestRegistryDowngradeUpgradeCycles moves a registry between the current
// schema and version 1 several times. In each cycle the current code uses the
// registry for some rounds, DowngradeRegistry converts it, algod 5.0's writes
// to the version 1 file are imitated for more rounds, and opening the file
// upgrades it again. After every step the registry must hold each key's
// voting secrets and last vote exactly as the last writer left them, and the
// mid-life key must still sign for the next round under its registered
// verifier.
func TestRegistryDowngradeUpgradeCycles(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	const dilution = 10
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	file := filepath.Join(t.TempDir(), config.ParticipationRegistryFilename)

	// long lives through every cycle; short runs out of voting subkeys at
	// round 59, the last round of the second cycle's current-code phase, and
	// expires in the following algod 5.0 phase; noVoting has no voting
	// secrets at all
	long := makeTestParticipation(a, 1, 1, 1000, dilution)
	short := makeTestParticipation(a, 2, 1, 59, dilution)
	noVoting := makeTestParticipation(a, 3, 1, 1000, dilution)
	noVoting.Voting = nil
	noVoting.VRF = nil

	registry := openFileRegistry(t, file)
	var ids []ParticipationID
	for _, p := range []Participation{long, short, noVoting} {
		id, err := registry.Insert(p)
		a.NoError(err)
		a.NoError(registry.Register(id, 1))
		keys := p.StateProofSecrets.GetAllKeys()
		spKeys := make(StateProofKeys, len(keys))
		copy(spKeys, keys)
		a.NoError(registry.AppendKeys(id, spKeys))
		ids = append(ids, id)
	}
	a.NoError(registry.Flush(defaultTimeout))

	cycles := []struct {
		current, v1 []basics.Round
	}{
		{current: []basics.Round{5, 12, 19}, v1: []basics.Round{26, 33}},
		{current: []basics.Round{40, 47, 59}, v1: []basics.Round{66, 73}},
		{current: []basics.Round{80, 87, 99}, v1: []basics.Round{106, 113}},
	}
	sawExhausted := false
	var round basics.Round
	for c, cycle := range cycles {
		for _, round = range cycle.current {
			a.NoError(registry.DeleteExpired(round, proto))
			a.NoError(registry.Record(long.Parent, round, Vote))
			a.NoError(registry.Flush(defaultTimeout))
		}
		want := recordsFromRegistry(registry, ids)
		a.Contains(want, long.ID())
		registryCloseTest(t, registry, "")
		before := dumpRegistryFile(a, file)

		downgraded, err := DowngradeRegistry(file, false)
		a.NoError(err, "cycle %d", c)
		a.Len(downgraded, len(want))
		for _, d := range downgraded {
			a.Contains(want, d.ParticipationID)
			a.Equal(d.Voting == nil, want[d.ParticipationID].voting == nil)
			if d.Voting != nil && d.Voting.Exhausted() {
				a.Equal(short.ID(), d.ParticipationID)
				sawExhausted = true
			}
		}
		requireRegistryV1(a, file, want)
		after := dumpRegistryFile(a, file)
		a.Equal(before["Keysets"], after["Keysets"])
		a.Equal(before["StateProofKeys"], after["StateProofKeys"])

		for _, round = range cycle.v1 {
			advanceV1File(a, file, round, long.ID(), want)
		}

		registry = openFileRegistry(t, file)
		a.EqualValues(registrySchemaVotingRows, registryFileVersion(a, file))
		a.Equal(want, recordsFromRegistry(registry, ids), "cycle %d", c)

		next := round + 1
		record, err := registry.GetForRound(long.ID(), next)
		a.NoError(err)
		otsID := basics.OneTimeIDForRound(next, dilution)
		sig := record.Voting.Sign(otsID, testMessage("cycle"))
		a.True(long.Voting.OneTimeSignatureVerifier.Verify(otsID, testMessage("cycle"), sig), "cycle %d", c)
	}
	a.True(sawExhausted, "no cycle downgraded a key without subkeys left")
	a.True(registry.Get(short.ID()).IsZero(), "the expired key survived")
	registryCloseTest(t, registry, "")
}

// TestRegistryDowngradeThenUpgradeIsLossless downgrades a registry and opens
// it again with no use in between: every row must come back unchanged. It also
// pins the current schema version, so a new registry migration without a
// matching downgrade step fails here.
func TestRegistryDowngradeThenUpgradeIsLossless(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	const dilution = 10
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	file := filepath.Join(t.TempDir(), config.ParticipationRegistryFilename)

	registry := openFileRegistry(t, file)
	parts := []Participation{
		makeTestParticipation(a, 1, 1, 1000, dilution),
		makeTestParticipation(a, 2, 1, 39, dilution),
	}
	for _, p := range parts {
		id, err := registry.Insert(p)
		a.NoError(err)
		a.NoError(registry.Register(id, 1))
	}
	a.NoError(registry.DeleteExpired(39, proto))
	a.NoError(registry.Record(parts[0].Parent, 39, Vote))
	a.NoError(registry.Flush(defaultTimeout))
	registryCloseTest(t, registry, "")

	before := dumpRegistryFile(a, file)
	a.Equal([][]any{{int32(registrySchemaVotingRows)}}, before["user_version"],
		"the registry schema changed: DowngradeRegistry must convert the new version too")
	a.NotEmpty(before["VotingBatches"])
	a.NotEmpty(before["VotingOffsets"])

	_, err := DowngradeRegistry(file, false)
	a.NoError(err)
	registryCloseTest(t, openFileRegistry(t, file), "")
	a.Equal(before, dumpRegistryFile(a, file))
}

// TestRegistryDowngradeRefusals checks a dry run and every refused downgrade
// leave the registry file as it was.
func TestRegistryDowngradeRefusals(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	const dilution = 10
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dir := t.TempDir()
	p := makeTestParticipation(a, 1, 1, 1000, dilution)
	makeFile := func(name string) string {
		file := filepath.Join(dir, name)
		registry := openFileRegistry(t, file)
		id, err := registry.Insert(p)
		a.NoError(err)
		a.NoError(registry.Register(id, 1))
		a.NoError(registry.DeleteExpired(25, proto))
		a.NoError(registry.Flush(defaultTimeout))
		registryCloseTest(t, registry, "")
		return file
	}

	// a dry run converts and verifies, then rolls back
	file := makeFile("dryrun.sqlite")
	before := dumpRegistryFile(a, file)
	records, err := DowngradeRegistry(file, true)
	a.NoError(err)
	a.Len(records, 1)
	a.Equal(p.ID(), records[0].ParticipationID)
	a.Equal(before, dumpRegistryFile(a, file))

	// a missing subkey row fails the conversion
	file = makeFile("missingrow.sqlite")
	withRegistryFile(a, file, false, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE FROM VotingOffsets WHERE off = (SELECT max(off) FROM VotingOffsets)")
		return err
	})
	before = dumpRegistryFile(a, file)
	_, err = DowngradeRegistry(file, false)
	a.ErrorContains(err, "cannot be downgraded")
	a.Equal(before, dumpRegistryFile(a, file))

	// a version 1 registry is left alone
	file = makeFile("twice.sqlite")
	_, err = DowngradeRegistry(file, false)
	a.NoError(err)
	before = dumpRegistryFile(a, file)
	_, err = DowngradeRegistry(file, false)
	a.ErrorIs(err, ErrRegistryAlreadyVersion1)
	a.Equal(before, dumpRegistryFile(a, file))

	// so is a schema version this code does not know
	file = makeFile("future.sqlite")
	withRegistryFile(a, file, false, func(ctx context.Context, tx *sql.Tx) error {
		_, err := db.SetUserVersion(ctx, tx, registrySchemaVotingRows+1)
		return err
	})
	before = dumpRegistryFile(a, file)
	_, err = DowngradeRegistry(file, false)
	a.ErrorContains(err, "schema version 3")
	a.Equal(before, dumpRegistryFile(a, file))

	// a missing file is not created
	missing := filepath.Join(dir, "missing.sqlite")
	_, err = DowngradeRegistry(missing, false)
	a.ErrorIs(err, os.ErrNotExist)
	a.NoFileExists(missing)
}
