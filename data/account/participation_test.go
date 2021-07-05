// Copyright (C) 2019-2021 Algorand, Inc.
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

func TestParticipation_NewDB(t *testing.T) {
	a := require.New(t)

	_, rootDB, partDB, err := setupParticipationKey(t, a)
	a.NoError(err)
	partDB.Close()
	rootDB.Close()
}

func setupParticipationKey(t *testing.T, a *require.Assertions) (PersistedParticipation, db.Accessor, db.Accessor, error) {
	root, rootDB, partDB, err := createTestDBs(t, a)

	part, err := FillDBWithParticipationKeys(partDB, root.Address(), 0, 0, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	a.NoError(err)
	a.NotNil(part)

	versions, err := getSchemaVersions(partDB)
	a.NoError(err)
	a.Equal(versions[PartTableSchemaName], PartTableSchemaVersion)
	return part, rootDB, partDB, err
}

func createTestDBs(t *testing.T, a *require.Assertions) (Root, db.Accessor, db.Accessor, error) {
	rootDB, err := db.MakeAccessor(t.Name(), false, true)
	a.NoError(err)
	a.NotNil(rootDB)
	root, err := GenerateRoot(rootDB)
	a.NoError(err)
	a.NotNil(root)

	partDB, err := db.MakeAccessor(t.Name()+"_part", false, true)
	a.NoError(err)
	a.NotNil(partDB)
	return root, rootDB, partDB, err
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

func TestRead(t *testing.T) {
	a := require.New(t)

	part, rootDB, partDB, err := setupParticipationKey(t, a)
	a.NoError(err)
	defer rootDB.Close()
	defer partDB.Close()

	t.Run("retrieve from DB", func(t *testing.T) {
		retrievedPart, err := RestoreParticipation(partDB)
		a.NoError(err)
		a.NotNil(retrievedPart)

		// comparing the outputs:
		a.Equal(intoComparable(part), intoComparable(retrievedPart))
	})

	t.Run("test migration", func(t *testing.T) {
		testDBMigration(t, part)
	})
}

func testDBMigration(t *testing.T, ppart PersistedParticipation) {
	a := require.New(t)
	_, rootDB, partDB, err := createTestDBs(t, a)
	a.NoError(err)
	defer rootDB.Close()
	defer partDB.Close()

	part := ppart.Participation

	a.NoError(setupTestDBAtVer1(err, partDB, part))

	a.NoError(Migrate(partDB))

	rawCompCert := protocol.Encode(part.CompactCertKey)
	err = partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE ParticipationAccount SET compactCert=?, keyDilution=?;",
			rawCompCert, part.KeyDilution)
		return err
	})
	a.NoError(err)

	retrievedPart, err := RestoreParticipation(partDB)
	a.NoError(err)
	a.NotNil(retrievedPart)

	// comparing the outputs:
	a.Equal(intoComparable(ppart), intoComparable(retrievedPart))
}

func setupTestDBAtVer1(err error, partDB db.Accessor, part Participation) error {
	rawVRF := protocol.Encode(part.VRF)
	voting := part.Voting.Snapshot()
	rawVoting := protocol.Encode(&voting)

	return partDB.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		//set up an actual DB..
		_, err = tx.Exec(`CREATE TABLE ParticipationAccount (
		parent BLOB,
		
		vrf BLOB,
		voting BLOB,

		firstValid INTEGER,
		lastValid INTEGER
	);`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(`CREATE TABLE schema (tablename TEXT PRIMARY KEY, version INTEGER);`)
		if err != nil {
			return err
		}

		_, err = tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)", PartTableSchemaName, 1)
		if err != nil {
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

// todo test the advancement of a single migration verion.

type comparablePartition struct {
	Parent basics.Address

	VRF            crypto.VRFSecrets
	Voting         []byte
	CompactCertKey crypto.SignatureAlgorithm

	FirstValid basics.Round
	LastValid  basics.Round

	KeyDilution uint64
}

func intoComparable(part PersistedParticipation) comparablePartition {
	return comparablePartition{
		Parent:         part.Parent,
		VRF:            *part.VRF,
		Voting:         part.Voting.MarshalMsg(nil),
		CompactCertKey: *part.CompactCertKey,
		FirstValid:     part.FirstValid,
		LastValid:      part.LastValid,
		KeyDilution:    part.KeyDilution,
	}
}
