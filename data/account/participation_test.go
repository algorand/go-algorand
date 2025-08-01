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

package account

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

var partableColumnNames = [...]string{"parent", "vrf", "voting", "stateProof", "firstValid", "lastValid", "keyDilution"}

func TestParticipation_NewDB(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	_, rootDB, partDB, err := setupParticipationKey(t, a)
	a.NoError(err)
	closeDBS(rootDB, partDB)
}

func setupParticipationKey(t *testing.T, a *require.Assertions) (PersistedParticipation, db.Accessor, db.Accessor, error) {
	root, rootDB, partDB := createTestDBs(a, t.Name())

	part, err := FillDBWithParticipationKeys(partDB, root.Address(), 0, 3000, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	a.NoError(err)
	a.NotNil(part)

	versions, err := getSchemaVersions(partDB)
	a.NoError(err)
	a.Equal(versions[PartTableSchemaName], PartTableSchemaVersion)
	return part, rootDB, partDB, err
}

func setupkeyWithNoDBS(t *testing.T, a *require.Assertions) PersistedParticipation {
	part, rootDB, partDB, err := setupParticipationKey(t, a)
	a.NoError(err)
	a.NotNil(part)

	closeDBS(rootDB, partDB)
	return part
}

func createTestDBs(a *require.Assertions, name string) (Root, db.Accessor, db.Accessor) {
	rootDB, err := db.MakeAccessor(name, false, true)
	a.NoError(err)
	a.NotNil(rootDB)
	root, err := GenerateRoot(rootDB)
	a.NoError(err)
	a.NotNil(root)

	partDB, err := db.MakeAccessor(name+"_part", false, true)
	a.NoError(err)
	a.NotNil(partDB)

	return root, rootDB, partDB
}

func getSchemaVersions(db db.Accessor) (versions map[string]int, err error) {
	err = db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		rows, err := tx.Query("SELECT tablename, version FROM schema")
		if err != nil {
			return
		}
		defer rows.Close()

		versions = make(map[string]int)
		for rows.Next() {
			var tableName string
			var version int
			err = rows.Scan(&tableName, &version)
			if err != nil {
				return
			}
			versions[tableName] = version
		}

		err = rows.Err()
		if err != nil {
			return
		}
		return
	})
	return
}

func TestOverlapsInterval(t *testing.T) {
	partitiontest.PartitionTest(t)

	const before = basics.Round(95)
	const start = basics.Round(100)
	const middle = basics.Round(105)
	const end = basics.Round(110)
	const after = basics.Round(115)

	a := require.New(t)
	interval := Participation{
		FirstValid: start,
		LastValid:  end,
	}

	a.False(interval.OverlapsInterval(before, before))
	a.False(interval.OverlapsInterval(after, after))

	a.True(interval.OverlapsInterval(before, start))
	a.True(interval.OverlapsInterval(before, middle))
	a.True(interval.OverlapsInterval(before, end))
	a.True(interval.OverlapsInterval(before, after))

	a.True(interval.OverlapsInterval(start, start))
	a.True(interval.OverlapsInterval(start, middle))
	a.True(interval.OverlapsInterval(start, end))
	a.True(interval.OverlapsInterval(start, after))

	a.True(interval.OverlapsInterval(middle, middle))
	a.True(interval.OverlapsInterval(middle, end))
	a.True(interval.OverlapsInterval(middle, after))

	a.True(interval.OverlapsInterval(end, end))
	a.True(interval.OverlapsInterval(end, after))
}

func BenchmarkOldKeysDeletion(b *testing.B) {
	a := require.New(b)

	var rootAddr basics.Address
	crypto.RandBytes(rootAddr[:])

	partDB, err := db.MakeErasableAccessor(b.Name() + "_part")
	a.NoError(err)
	a.NotNil(partDB)
	defer func() {
		os.Remove(b.Name() + "_part")
	}()

	// make participation key
	lastValid := basics.Round(3000000)
	keyDilution := 10000
	if kd, err := strconv.Atoi(os.Getenv("DILUTION")); err == nil { // allow setting key dilution via env var
		keyDilution = kd
	}
	if lv, err := strconv.Atoi(os.Getenv("LASTVALID")); err == nil { // allow setting last valid via env var
		lastValid = basics.Round(lv)
	}
	b.Log("making part keys for firstValid 0 lastValid", lastValid, "dilution", keyDilution)
	part, err := FillDBWithParticipationKeys(partDB, rootAddr, 0, lastValid, uint64(keyDilution))
	a.NoError(err)
	a.NotNil(part)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	b.Log("starting DeleteOldKeys benchmark up to round", b.N)
	b.ResetTimer()
	for i := range basics.Round(b.N) {
		errCh := part.DeleteOldKeys(i, proto)
		err := <-errCh
		a.NoError(err)
	}
	part.Close()
}

func TestRetrieveFromDB(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	part, rootDB, partDB, err := setupParticipationKey(t, a)
	a.NoError(err)
	defer closeDBS(rootDB, partDB)

	retrievedPart, err := RestoreParticipation(partDB)
	a.NoError(err)
	a.NotNil(retrievedPart)

	// comparing the outputs:
	a.Equal(intoComparable(part), intoComparable(retrievedPart))

}

func TestRetrieveFromDBAtVersion1(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	ppart := setupkeyWithNoDBS(t, a)
	_, rootDB, partDB := createTestDBs(a, t.Name())
	defer closeDBS(rootDB, partDB)

	part := ppart.Participation
	a.NoError(setupTestDBAtVer1(partDB, part))

	retrivedPart, err := RestoreParticipation(partDB)
	a.NoError(err)
	assertionForRestoringFromDBAtLowVersion(a, retrivedPart)
	assertStateProofTablesExists(a, partDB)

	retrivedPart, err = RestoreParticipationWithSecrets(partDB)
	a.NoError(err)
	assertionForRestoringFromDBAtLowVersion(a, retrivedPart)
	assertStateProofTablesExists(a, partDB)
}

func TestRetrieveFromDBAtVersion2(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ppart := setupkeyWithNoDBS(t, a)
	_, rootDB, partDB := createTestDBs(a, t.Name())
	defer closeDBS(rootDB, partDB)

	part := ppart.Participation
	a.NoError(setupTestDBAtVer2(partDB, part))

	retrivedPart, err := RestoreParticipation(partDB)
	a.NoError(err)
	assertionForRestoringFromDBAtLowVersion(a, retrivedPart)
	assertStateProofTablesExists(a, partDB)
	versions, err := getSchemaVersions(partDB)
	a.NoError(err)
	a.Equal(versions[PartTableSchemaName], PartTableSchemaVersion)

	retrivedPart, err = RestoreParticipationWithSecrets(partDB)
	a.NoError(err)
	assertionForRestoringFromDBAtLowVersion(a, retrivedPart)
	assertStateProofTablesExists(a, partDB)
	versions, err = getSchemaVersions(partDB)
	a.NoError(err)
	a.Equal(versions[PartTableSchemaName], PartTableSchemaVersion)
}

func TestKeyRegCreation(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ppart := setupkeyWithNoDBS(t, a)

	txn := ppart.Participation.GenerateRegistrationTransaction(basics.MicroAlgos{Raw: 1000}, 0, 100, [32]byte{}, false)
	a.Equal(txn.StateProofPK.IsEmpty(), true)

	txn = ppart.Participation.GenerateRegistrationTransaction(basics.MicroAlgos{Raw: 1000}, 0, 100, [32]byte{}, true)
	a.Equal(txn.StateProofPK.IsEmpty(), false)
}

func closeDBS(dbAccessor ...db.Accessor) {
	for _, accessor := range dbAccessor {
		accessor.Close()
	}
}

func assertStateProofTablesExists(a *require.Assertions, store db.Accessor) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("select count(*) From StateProofKeys;")
		return err
	})
	a.NoError(err)

}
func assertionForRestoringFromDBAtLowVersion(a *require.Assertions, retrivedPart PersistedParticipation) {
	a.NotNil(retrivedPart)
	a.Nil(retrivedPart.StateProofSecrets)
}

func TestMigrateFromVersion1(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	part := setupkeyWithNoDBS(t, a).Participation

	_, rootDB, partDB := createTestDBs(a, t.Name())
	defer closeDBS(rootDB, partDB)

	a.NoError(setupTestDBAtVer1(partDB, part))
	a.NoError(Migrate(partDB))

	a.NoError(testDBContainsAllColumns(partDB))
}

func TestMigrationFromVersion2(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	part := setupkeyWithNoDBS(t, a).Participation

	_, rootDB, partDB := createTestDBs(a, t.Name())
	defer closeDBS(rootDB, partDB)

	a.NoError(setupTestDBAtVer2(partDB, part))
	a.NoError(Migrate(partDB))

	a.NoError(testDBContainsAllColumns(partDB))
}

func testDBContainsAllColumns(partDB db.Accessor) error {
	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec(fmt.Sprintf("select %v From ParticipationAccount;",
			strings.Join(partableColumnNames[:], ",")))
		return err
	})
}

func setupTestDBAtVer2(partDB db.Accessor, part Participation) error {
	rawVRF := protocol.Encode(part.VRF)
	voting := part.Voting.Snapshot()
	rawVoting := protocol.Encode(&voting)

	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		//set up an actual DB..
		_, err := tx.Exec(`CREATE TABLE ParticipationAccount (
		parent BLOB,

		vrf BLOB,
		voting BLOB,

		firstValid INTEGER,
		lastValid INTEGER,

		keyDilution INTEGER NOT NULL DEFAULT 0
	);`)
		if err != nil {
			return err
		}

		if err := setupSchemaForTest(tx, 2); err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO ParticipationAccount (parent, vrf, voting, firstValid, lastValid, keyDilution) VALUES (?, ?, ?, ?, ?, ?)",
			part.Parent[:], rawVRF, rawVoting, part.FirstValid, part.LastValid, part.KeyDilution)
		if err != nil {
			return err
		}
		return nil
	})
}

func setupSchemaForTest(tx *sql.Tx, version int) error {
	_, err := tx.Exec(`CREATE TABLE schema (tablename TEXT PRIMARY KEY, version INTEGER);`)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)", PartTableSchemaName, version)
	if err != nil {
		return err
	}
	return err
}

func setupTestDBAtVer1(partDB db.Accessor, part Participation) error {
	rawVRF := protocol.Encode(part.VRF)
	voting := part.Voting.Snapshot()
	rawVoting := protocol.Encode(&voting)

	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		//set up an actual DB..
		_, err := tx.Exec(`CREATE TABLE ParticipationAccount (
		parent BLOB,
		
		vrf BLOB,
		voting BLOB,

		firstValid INTEGER,
		lastValid INTEGER
	);`)
		if err != nil {
			return err
		}

		if err := setupSchemaForTest(tx, 1); err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO ParticipationAccount (parent, vrf, voting, firstValid, lastValid) VALUES (?, ?, ?, ?, ?)",
			part.Parent[:], rawVRF, rawVoting, part.FirstValid, part.LastValid)
		if err != nil {
			return err
		}
		return nil
	})
}

type comparablePartition struct {
	Parent basics.Address

	VRF              crypto.VRFSecrets
	Voting           []byte
	statProofSecrets []byte

	FirstValid basics.Round
	LastValid  basics.Round

	KeyDilution uint64
}

func intoComparable(part PersistedParticipation) comparablePartition {
	return comparablePartition{
		Parent:           part.Parent,
		VRF:              *part.VRF,
		Voting:           part.Voting.MarshalMsg(nil),
		statProofSecrets: protocol.Encode(part.StateProofSecrets),
		FirstValid:       part.FirstValid,
		LastValid:        part.LastValid,
		KeyDilution:      part.KeyDilution,
	}
}

func BenchmarkFillDB(b *testing.B) {
	a := require.New(b)
	root, _, partDB := createTestDBs(a, b.Name()+strconv.Itoa(b.N))

	tmp := config.Consensus[protocol.ConsensusCurrentVersion]
	cpy := config.Consensus[protocol.ConsensusCurrentVersion]
	cpy.StateProofInterval = 256
	config.Consensus[protocol.ConsensusCurrentVersion] = cpy
	defer func() { config.Consensus[protocol.ConsensusCurrentVersion] = tmp }()

	for i := 0; i < b.N; i++ {
		_, err := FillDBWithParticipationKeys(partDB, root.Address(), 0, 3000000, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		b.StopTimer()
		a.NoError(err)

		a.NoError(dropTables(partDB))
		b.StartTimer()
	}
}

func dropTables(partDB db.Accessor) error {
	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DROP TABLE ParticipationAccount;")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE schema;")
		return err
	})
}

func BenchmarkParticipationKeyRestoration(b *testing.B) {
	a := require.New(b)

	var rootAddr basics.Address
	crypto.RandBytes(rootAddr[:])

	dbname := b.Name() + "_part"
	defer os.Remove(dbname)

	partDB, err := db.MakeErasableAccessor(dbname)
	a.NoError(err)

	part, err := FillDBWithParticipationKeys(partDB, rootAddr, 0, 3000000, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	a.NoError(err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := RestoreParticipation(partDB)
		a.NoError(err)

		b.StopTimer()
		a.Equal(intoComparable(part), intoComparable(out))
		b.StartTimer()
	}
	part.Close()
}

func createMerkleSignatureSchemeTestDB(a *require.Assertions) *db.Accessor {
	tmpname := fmt.Sprintf("%015x", crypto.RandUint64())
	store, err := db.MakeAccessor(tmpname, false, true)
	a.NoError(err)
	a.NotNil(store)

	return &store
}

func TestKeyregValidityOverLimit(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	maxValidPeriod := basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].MaxKeyregValidPeriod)
	dilution := config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution

	var address basics.Address
	crypto.RandBytes(address[:])

	store := createMerkleSignatureSchemeTestDB(a)
	defer store.Close()
	firstValid := basics.Round(0)
	lastValid := maxValidPeriod + 1
	_, err := FillDBWithParticipationKeys(*store, address, firstValid, lastValid, dilution)
	a.Error(err)
}

func TestFillDBWithParticipationKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	dilution := config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution

	var address basics.Address
	crypto.RandBytes(address[:])

	store := createMerkleSignatureSchemeTestDB(a)
	defer store.Close()
	firstValid := basics.Round(0)
	lastValid := basics.Round(10000)
	_, err := FillDBWithParticipationKeys(*store, address, firstValid, lastValid, dilution)
	a.NoError(err)
}

func TestKeyregValidityPeriod(t *testing.T) { //nolint:paralleltest // Not parallel because it modifies config.Consensus
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// Patch the global consensus variable since FillDBWithParticipationKeys uses is to check the validity period
	// this allows us to reduce the runtime of the test while checking the logic of FillDBWithParticipationKeys
	version := config.Consensus[protocol.ConsensusCurrentVersion]
	oldValue := config.Consensus[protocol.ConsensusCurrentVersion].MaxKeyregValidPeriod
	version.MaxKeyregValidPeriod = 256*(1<<4) - 1
	config.Consensus[protocol.ConsensusCurrentVersion] = version
	defer func() {
		version.MaxKeyregValidPeriod = oldValue
		config.Consensus[protocol.ConsensusCurrentVersion] = version
	}()

	maxValidPeriod := basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].MaxKeyregValidPeriod)
	dilution := config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution

	var address basics.Address

	store := createMerkleSignatureSchemeTestDB(a)
	defer store.Close()
	firstValid := basics.Round(0)
	lastValid := maxValidPeriod
	crypto.RandBytes(address[:])
	_, err := FillDBWithParticipationKeys(*store, address, firstValid, lastValid, dilution)
	a.NoError(err)

	store = createMerkleSignatureSchemeTestDB(a)
	defer store.Close()
	firstValid = basics.Round(0)
	lastValid = maxValidPeriod + 1
	_, err = FillDBWithParticipationKeys(*store, address, firstValid, lastValid, dilution)
	a.Error(err)
}

func BenchmarkParticipationSign(b *testing.B) {
	access, err := db.MakeAccessor("writetest_root", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	access.Close()
	require.NoError(b, err)

	access, err = db.MakeAccessor("writetest", false, true)
	if err != nil {
		panic(err)
	}
	defer access.Close()
	keyDilution := uint64(10000) // DefaultKeyDilution is 10K
	firstValid := basics.Round(0)
	lastValid := basics.Round(b.N)
	numBatches := basics.OneTimeIDForRound(lastValid, keyDilution).Batch - basics.OneTimeIDForRound(firstValid, keyDilution).Batch + 1
	numKeys := b.N
	b.Log("generating", numKeys, "keys")
	t0 := time.Now()
	part, err := FillDBWithParticipationKeys(access, root.Address(), firstValid, lastValid, keyDilution)
	b.Log("generated keys, took", time.Since(t0))
	require.NoError(b, err)

	msg := testMessage("hello")

	// assert empty batch (no pregenerated keys)
	require.Empty(b, part.Voting.Offsets)
	// assert all batch keys are available
	require.Len(b, part.Voting.Batches, int(numBatches))

	// use the key many times: will force dynamic key generation
	b.ResetTimer()
	for rnd := 0; rnd < b.N; rnd++ {
		ephID := basics.OneTimeIDForRound(basics.Round(rnd), keyDilution)
		_ = part.Voting.Sign(ephID, msg)
	}
}

func BenchmarkID(b *testing.B) {
	pki := ParticipationKeyIdentity{}
	b.Run("existing", func(b *testing.B) {
		b.ReportAllocs() // demonstrate this is a single alloc
		for i := 0; i < b.N; i++ {
			pki.ID()
		}
	})
}
