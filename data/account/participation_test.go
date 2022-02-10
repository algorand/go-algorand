// Copyright (C) 2019-2022 Algorand, Inc.
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

	uuid "github.com/satori/go.uuid"
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

	part, err := FillDBWithParticipationKeys(partDB, rootAddr, 0, 3000000, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	a.NoError(err)
	a.NotNil(part)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		errCh := part.DeleteOldKeys(basics.Round(i), config.Consensus[protocol.ConsensusCurrentVersion])
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
}

func TestRetriveFromDBAtVersion2(t *testing.T) {
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
			return nil
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
		return nil
	}

	_, err = tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)", PartTableSchemaName, version)
	if err != nil {
		return nil
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
	cpy.CompactCertRounds = 256
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
	tmpname := uuid.NewV4().String() // could this just be a constant string instead? does it even matter?
	store, err := db.MakeAccessor(tmpname, false, true)
	a.NoError(err)
	a.NotNil(store)

	return &store
}

func TestKeyregValidityOverLimit(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	maxValidPeriod := config.Consensus[protocol.ConsensusCurrentVersion].MaxKeyregValidPeriod
	dilution := config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution

	var address basics.Address
	crypto.RandBytes(address[:])

	store := createMerkleSignatureSchemeTestDB(a)
	defer store.Close()
	firstValid := basics.Round(0)
	lastValid := basics.Round(maxValidPeriod + 1)
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

func TestKeyregValidityPeriod(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	maxValidPeriod := config.Consensus[protocol.ConsensusCurrentVersion].MaxKeyregValidPeriod
	dilution := config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution

	var address basics.Address

	store := createMerkleSignatureSchemeTestDB(a)
	defer store.Close()
	firstValid := basics.Round(0)
	lastValid := basics.Round(maxValidPeriod)
	crypto.RandBytes(address[:])
	_, err := FillDBWithParticipationKeys(*store, address, firstValid, lastValid, dilution)
	a.NoError(err)

	store = createMerkleSignatureSchemeTestDB(a)
	defer store.Close()
	firstValid = basics.Round(0)
	lastValid = basics.Round(maxValidPeriod + 1)
	_, err = FillDBWithParticipationKeys(*store, address, firstValid, lastValid, dilution)
	a.Error(err)
}
