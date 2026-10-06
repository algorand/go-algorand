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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

// These tests check that no retired voting subkey is recoverable from a key
// store's files, the write-ahead log included.  The detector looks for the
// private seed of each subkey: the encoded subkey is stored verbatim in its
// row, the seed is a 32-byte random string that appears nowhere else, and a
// page image of the row in the log carries it unsplit.

// subkeySeedMarker precedes the seed in an encoded ephemeral subkey: the
// msgpack "SK" key followed by the header of a 64-byte bin (the ed25519
// private key, whose first half is the seed).
var subkeySeedMarker = []byte{0xa2, 'S', 'K', 0xc4, 0x40}

// seedSet returns the seeds of every subkey of a snapshot.
func seedSet(a *require.Assertions, snap crypto.OneTimeSignatureSecretsPersistent) map[string]struct{} {
	seeds := make(map[string]struct{})
	for _, rows := range [][]crypto.KeyedSubkey{snap.EncodedBatches(), snap.EncodedOffsets()} {
		for _, row := range rows {
			i := bytes.Index(row.Key, subkeySeedMarker)
			a.GreaterOrEqual(i, 0, "encoded subkey has no SK field")
			seed := row.Key[i+len(subkeySeedMarker):][:32]
			seeds[string(seed)] = struct{}{}
		}
	}
	return seeds
}

// seedsIn counts the seeds that appear in data.
func seedsIn(data []byte, seeds map[string]struct{}) (n int) {
	for seed := range seeds {
		if bytes.Contains(data, []byte(seed)) {
			n++
		}
	}
	return n
}

func readFileOrEmpty(a *require.Assertions, path string) []byte {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	a.NoError(err)
	return data
}

// walErasureProbe records the write-ahead log as EraseWAL leaves it after
// overwriting it and before truncating it, so a test can tell an overwritten
// log from a merely truncated one.  The hook runs on whatever goroutine
// erases (the registry's write thread), so it only records; tests assert on
// what it took afterwards.
type walErasureProbe struct {
	path string // the database file; its log is path+"-wal"
	mu   deadlock.Mutex
	logs [][]byte
}

func installWALErasureProbe(acc *db.Accessor, path string) *walErasureProbe {
	p := &walErasureProbe{path: path}
	acc.SetEraseWALHook(p.record)
	return p
}

func (p *walErasureProbe) record() {
	data, _ := os.ReadFile(p.path + "-wal")
	p.mu.Lock()
	p.logs = append(p.logs, data)
	p.mu.Unlock()
}

// take returns the logs recorded since the last call.
func (p *walErasureProbe) take() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	logs := p.logs
	p.logs = nil
	return logs
}

// requireOverwritten checks every recorded log was inspected while it still
// had its frames and held none of the seeds.
func (p *walErasureProbe) requireOverwritten(a *require.Assertions, seeds map[string]struct{}, what string) (recorded int) {
	for _, log := range p.take() {
		a.NotEmpty(log, "the log was truncated before being overwritten, %s", what)
		a.Zero(seedsIn(log, seeds), "subkey in the overwritten write-ahead log before truncation, %s", what)
		recorded++
	}
	return recorded
}

// retiredSeedTracker follows a key's subkeys through deletions, accumulating
// the seeds of the retired ones and checking none is left in the store's
// files, nor in the log as overwritten before each truncation.
type retiredSeedTracker struct {
	a       *require.Assertions
	path    string // the database file; its log is path+"-wal"
	probe   *walErasureProbe
	live    map[string]struct{}
	retired map[string]struct{}
	erased  int // erasures that overwrote the log
}

func newRetiredSeedTracker(a *require.Assertions, acc *db.Accessor, path string, secrets *crypto.OneTimeSignatureSecrets) *retiredSeedTracker {
	return &retiredSeedTracker{
		a:       a,
		path:    path,
		probe:   installWALErasureProbe(acc, path),
		live:    seedSet(a, votingSnapshot(secrets)),
		retired: make(map[string]struct{}),
	}
}

// advance records the subkeys retired since the last call.
func (tr *retiredSeedTracker) advance(secrets *crypto.OneTimeSignatureSecrets) {
	now := seedSet(tr.a, votingSnapshot(secrets))
	for seed := range tr.live {
		if _, ok := now[seed]; !ok {
			tr.retired[seed] = struct{}{}
		}
	}
	tr.live = now
}

func (tr *retiredSeedTracker) retiredInLog() int {
	return seedsIn(readFileOrEmpty(tr.a, tr.path+"-wal"), tr.retired)
}

// requireErased checks neither the database file nor its log holds a
// retired seed, and that the log held none once overwritten, before it was
// truncated.
func (tr *retiredSeedTracker) requireErased(what string) {
	tr.a.Zero(seedsIn(readFileOrEmpty(tr.a, tr.path), tr.retired), "retired subkey in the database file, %s", what)
	tr.a.Zero(tr.retiredInLog(), "retired subkey in the write-ahead log, %s", what)
	tr.erased += tr.probe.requireOverwritten(tr.a, tr.retired, what)
}

// requireDetectorWorks checks the live seeds are found in the database file,
// so that finding none of the retired ones means something.
func (tr *retiredSeedTracker) requireDetectorWorks() {
	tr.a.Equal(len(tr.live), seedsIn(readFileOrEmpty(tr.a, tr.path), tr.live), "the detector does not see the live subkeys")
}

// TestRegistryWALHoldsNoRetiredSubkeys drives keys through a file-backed
// registry (install with state proof keys, per-round deletion across
// rollovers to exhaustion, deletion of a live key) and checks after every
// write that no retired subkey is recoverable from the registry file or its
// write-ahead log.
func TestRegistryWALHoldsNoRetiredSubkeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	registry, dbfile := getRegistryImpl(t, false, true)
	defer registryCloseTest(t, registry, dbfile)
	walPath := dbfile + "-wal"

	const dilution = 10
	p := makeTestParticipation(a, 1, 1, 309, dilution)
	p.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(37, dilution), dilution)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.NoError(registry.AppendKeys(id, p.StateProofSecrets.GetAllKeys()))
	a.NoError(registry.Register(id, 1))
	a.NoError(registry.Flush(defaultTimeout))

	tr := newRetiredSeedTracker(a, &registry.store.Wdb, dbfile, registry.Get(id).Voting)
	tr.requireDetectorWorks()
	a.FileExists(walPath)
	a.Zero(seedsIn(readFileOrEmpty(a, walPath), tr.live), "installed subkeys left in the write-ahead log")

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	var rounds []basics.Round
	for r := basics.Round(38); r <= 82; r++ {
		rounds = append(rounds, r)
	}
	rounds = append(rounds, 150, 300, 309)
	for _, r := range rounds {
		a.NoError(registry.DeleteExpired(r, proto))
		a.NoError(registry.Flush(defaultTimeout))
		tr.advance(registry.Get(id).Voting)
		tr.requireErased(fmt.Sprintf("round %d", r))
	}
	a.True(registryReadVotingHeader(a, registry, id).Exhausted())
	a.Greater(len(tr.retired), 60)
	a.Greater(tr.erased, 4, "rollovers and shrinking rounds should have overwritten the log")

	// deleting a live key retires every subkey it had; the insert's erase
	// runs before Insert returns, the deletion's before the flush returns
	p2 := makeTestParticipation(a, 2, 1, 309, dilution)
	id2, err := registry.Insert(p2)
	a.NoError(err)
	seeds2 := seedSet(a, votingSnapshot(p2.Voting))
	a.Equal(len(seeds2), seedsIn(readFileOrEmpty(a, dbfile), seeds2))
	a.Equal(1, tr.probe.requireOverwritten(a, seeds2, "insert"))
	a.NoError(registry.Delete(id2))
	a.NoError(registry.Flush(defaultTimeout))
	a.Zero(seedsIn(readFileOrEmpty(a, dbfile), seeds2), "deleted key's subkeys in the registry file")
	a.Zero(seedsIn(readFileOrEmpty(a, walPath), seeds2), "deleted key's subkeys in the write-ahead log")
	tr.probe.requireOverwritten(a, seeds2, "delete")
}

// TestRegistryMigrationErasesWAL checks the registry upgrade from the
// whole-blob format leaves no subkey image in the log.
func TestRegistryMigrationErasesWAL(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const dilution = 10
	p := makeTestParticipation(a, 1, 1, 200, dilution)
	p.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(55, dilution), dilution)
	seeds := seedSet(a, votingSnapshot(p.Voting))

	dbName := filepath.Join(t.TempDir(), "registry.sqlite")
	rootDB, err := db.OpenErasablePair(dbName)
	a.NoError(err)
	// the version-1 schema with the key stored as a legacy blob
	err = rootDB.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for _, ddl := range []string{createKeysets, createRollingV1, createStateProof} {
			if _, err := tx.Exec(ddl); err != nil {
				return err
			}
		}
		if _, err := db.SetUserVersion(ctx, tx, 1); err != nil {
			return err
		}
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
		_, err = tx.Exec("INSERT INTO Rolling (pk, voting) VALUES (?, ?)", pk, protocol.Encode(p.Voting))
		return err
	})
	a.NoError(err)
	// the fixture's own writes are not what is under test
	a.NoError(rootDB.Wdb.EraseWAL(context.Background(), true))
	a.Zero(seedsIn(readFileOrEmpty(a, dbName+"-wal"), seeds))

	probe := installWALErasureProbe(&rootDB.Wdb, dbName)
	registry, err := makeParticipationRegistry(rootDB, logging.TestingLog(t))
	a.NoError(err)
	defer registryCloseTest(t, registry, "")
	record := registry.Get(p.ID())
	a.False(record.IsZero())
	a.Equal(encodedVotingSnapshot(p.Voting), encodedVotingSnapshot(record.Voting))
	a.Equal(len(seeds), seedsIn(readFileOrEmpty(a, dbName), seeds))
	a.Equal(1, probe.requireOverwritten(a, seeds, "migration"))
	a.Zero(seedsIn(readFileOrEmpty(a, dbName+"-wal"), seeds), "migrated subkeys left in the write-ahead log")
}
