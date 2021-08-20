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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func getRegistry(t *testing.T) *participationDB {
	rootDB, err := db.OpenPair(t.Name(), true)
	require.NoError(t, err)

	registry, err := makeParticipationRegistry(rootDB)
	require.NoError(t, err)
	require.NotNil(t, registry)

	return registry
}

func assertParticipation(t *testing.T, p Participation, pr ParticipationRecord) {
	require.Equal(t, p.FirstValid, pr.FirstValid)
	require.Equal(t, p.LastValid, pr.LastValid)
	require.Equal(t, p.KeyDilution, pr.KeyDilution)
	require.Equal(t, p.Parent, pr.Account)
}

// Insert participation records and make sure they can be fetched.
func TestParticipation_InsertGet(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := Participation{
		FirstValid:  1,
		LastValid:   2,
		KeyDilution: 3,
	}
	p.Parent[0] = 1

	p2 := Participation{
		FirstValid:  4,
		LastValid:   5,
		KeyDilution: 6,
	}
	p2.Parent[0] = 2

	insertAndVerify := func(part Participation) {
		id, err := registry.Insert(part)
		a.NoError(err)
		a.Equal(part.ParticipationID(), id)

		record, err := registry.Get(part.ParticipationID())
		a.NoError(err)
		assertParticipation(t, part, record)
	}

	// Verify inserting some records.
	insertAndVerify(p)
	insertAndVerify(p2)

	// Data should be persisted immediately, re-initialize cache and verify GetAll.
	registry.initializeCache()
	results, err := registry.GetAll()
	a.NoError(err)
	a.Len(results, 2)
	for _, record := range results {
		if record.Account == p.Parent {
			assertParticipation(t, p, record)
		} else if record.Account == p2.Parent {
			assertParticipation(t, p2, record)
		} else {
			a.Fail("unexpected account")
		}
	}
}

// Make sure a record can be deleted by id.
func TestParticipation_Delete(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := Participation{
		FirstValid:  1,
		LastValid:   2,
		KeyDilution: 3,
	}
	p.Parent[0] = 1

	p2 := Participation{
		FirstValid:  4,
		LastValid:   5,
		KeyDilution: 6,
	}
	p2.Parent[0] = 2

	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ParticipationID(), id)

	id, err = registry.Insert(p2)
	a.NoError(err)
	a.Equal(p2.ParticipationID(), id)

	err = registry.Delete(p.ParticipationID())
	a.NoError(err)

	// Delete should be persisted immediately. Verify p removed in GetAll.
	registry.initializeCache()
	results, err := registry.GetAll()
	a.NoError(err)
	a.Len(results, 1)
	assertParticipation(t, p2, results[0])
}

// Make sure the register function properly sets effective first/last for all effected records.
func TestParticipation_Register(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	// Overlapping keys.
	p := Participation{
		FirstValid:  250000,
		LastValid:   3000000,
		KeyDilution: 1,
	}
	p.Parent[0] = 1

	p2 := Participation{
		FirstValid:  2000000,
		LastValid:   4000000,
		KeyDilution: 2,
		Parent:      p.Parent,
	}

	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ParticipationID(), id)

	id, err = registry.Insert(p2)
	a.NoError(err)
	a.Equal(p2.ParticipationID(), id)

	verifyEffectiveRound := func(id ParticipationID, first, last int) {
		record, err := registry.Get(id)
		a.NoError(err)
		require.Equal(t, first, int(record.RegisteredFirst))
		require.Equal(t, last, int(record.RegisteredLast))
	}

	// Register the first key.
	err = registry.Register(p.ParticipationID(), 500000)
	a.NoError(err)
	verifyEffectiveRound(p.ParticipationID(), 500000, int(p.LastValid))

	// Register second key.
	err = registry.Register(p2.ParticipationID(), 2500000)
	a.NoError(err)
	verifyEffectiveRound(p.ParticipationID(), 500000, 2500000)
	verifyEffectiveRound(p2.ParticipationID(), 2500000, int(p2.LastValid))
}

// Test error when registering a non-existing participation ID.
func TestParticipation_RegisterInvalidID(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := Participation{
		FirstValid:  250000,
		LastValid:   3000000,
		KeyDilution: 1,
	}

	err := registry.Register(p.ParticipationID(), 10000000)
	a.EqualError(err, ErrParticipationIDNotFound.Error())
}

// Test error attempting to register a key with an invalid range.
func TestParticipation_RegisterInvalidRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := Participation{
		FirstValid:  250000,
		LastValid:   3000000,
		KeyDilution: 1,
	}

	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ParticipationID(), id)

	// Register the first key.
	err = registry.Register(p.ParticipationID(), 1000000000)
	a.EqualError(err, ErrInvalidRegisterRange.Error())
}

// Test the recording function.
func TestParticipation_Record(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	// Setup p
	p := Participation{
		FirstValid:  0,
		LastValid:   3000000,
		KeyDilution: 1,
	}
	p.Parent[0] = 1

	// Setup some other keys to make sure they are not updated.
	p2 := p
	p2.Parent[0] = 2
	p3 := p
	p3.Parent[0] = 3

	// Install and register all of the keys
	for _, part := range []Participation{p, p2, p3} {
		id, err := registry.Insert(part)
		a.NoError(err)
		a.Equal(part.ParticipationID(), id)
		err = registry.Register(part.ParticipationID(), 0)
		a.NoError(err)
	}

	all, err := registry.GetAll()
	a.NotNil(all)
	a.NoError(err)

	err = registry.Record(p.Parent, 1000, Vote)
	a.NoError(err)
	err = registry.Record(p.Parent, 2000, BlockProposal)
	a.NoError(err)
	err = registry.Record(p.Parent, 3000, CompactCertificate)
	a.NoError(err)

	// Verify that one and only one key was updated.
	test := func(registry ParticipationRegistry) {
		records, err := registry.GetAll()
		a.NoError(err)
		a.Len(records, 3)
		for _, record := range records {
			if record.ParticipationID == p.ParticipationID() {
				require.Equal(t, 1000, int(record.LastVote))
				require.Equal(t, 2000, int(record.LastBlockProposal))
				require.Equal(t, 3000, int(record.LastCompactCertificate))
			} else {
				require.Equal(t, 0, int(record.LastVote))
				require.Equal(t, 0, int(record.LastBlockProposal))
				require.Equal(t, 0, int(record.LastCompactCertificate))
			}
		}
	}

	test(registry)
	registry.Flush()

	// Re-initialize
	registry.initializeCache()
	test(registry)
}

// Test that attempting to record an invalid action generates an error.
func TestParticipation_RecordInvalidActionAndOutOfRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := Participation{
		FirstValid:  0,
		LastValid:   3000000,
		KeyDilution: 1,
	}
	p.Parent[0] = 1
	id, err := registry.Insert(p)
	a.NoError(err)
	err = registry.Register(id, 0)
	a.NoError(err)

	err = registry.Record(p.Parent, 0, ParticipationAction(9000))
	a.EqualError(err, ErrUnknownParticipationAction.Error())

	err = registry.Record(p.Parent, 3000000, ParticipationAction(9000))
	a.EqualError(err, ErrUnknownParticipationAction.Error())

	err = registry.Record(p.Parent, 3000001, ParticipationAction(9000))
	a.EqualError(err, ErrActiveKeyNotFound.Error())
}

func TestParticipation_RecordNoKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	err := registry.Record(basics.Address{}, 0, Vote)
	a.EqualError(err, ErrActiveKeyNotFound.Error())
}

// Test that an error is generated if the record function updates multiple records.
// This would only happen if the DB was in an inconsistent state.
func TestParticipation_RecordMultipleUpdates(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	// We'll test that recording at this round fails because both keys are active
	testRound := basics.Round(5000)

	p := Participation{
		FirstValid:  0,
		LastValid:   3000000,
		KeyDilution: 1,
	}
	p.Parent[0] = 1
	p2 := Participation{
		FirstValid:  1,
		LastValid:   3000000,
		KeyDilution: 1,
	}
	p2.Parent = p.Parent

	_, err := registry.Insert(p)
	a.NoError(err)
	_, err = registry.Insert(p2)
	a.NoError(err)
	err = registry.Register(p.ParticipationID(), p.FirstValid)
	a.NoError(err)

	// Force the DB to have 2 active keys for one account by tampering with the private cache variable
	recordCopy := registry.cache[p2.ParticipationID()]
	recordCopy.FirstValid = p2.FirstValid
	recordCopy.LastValid = p2.LastValid
	registry.cache[p2.ParticipationID()] = recordCopy
	registry.dirty[p2.ParticipationID()] = struct{}{}
	registry.Flush()
	registry.initializeCache()

	// Verify bad state - both records are valid until round 3 million
	recordTest := make([]ParticipationRecord, 0)
	recordP, err := registry.Get(p.ParticipationID())
	a.NoError(err)
	recordTest = append(recordTest, recordP)
	recordP2, err := registry.Get(p2.ParticipationID())
	a.NoError(err)
	recordTest = append(recordTest, recordP2)

	// Make sure both accounts are active for the test round
	for _, record := range recordTest {
		a.LessOrEqual(uint64(record.FirstValid), uint64(testRound))
		a.GreaterOrEqual(uint64(record.LastValid), uint64(testRound))
	}

	err = registry.Record(p.Parent, testRound, Vote)
	a.EqualError(err, ErrMultipleValidKeys.Error())
}

func TestParticipation_MultipleInsertError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := Participation{
		FirstValid:  1,
		LastValid:   2,
		KeyDilution: 3,
	}
	p.Parent[0] = 1

	_, err := registry.Insert(p)
	a.NoError(err)
	_, err = registry.Insert(p)
	a.Error(err, ErrAlreadyInserted.Error())
}

// This is a contrived test on every level. To workaround errors we setup the
// DB and cache in ways that are impossible with public methods.
//
// Basically multiple records with the same ParticipationID are a big no-no and
// it should be detected as quickly as possible.
func TestParticipation_RecordMultipleUpdates_DB(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := Participation{
		FirstValid:  1,
		LastValid:   2000000,
		KeyDilution: 3,
	}
	p.Parent[0] = 1
	id := p.ParticipationID()

	// Insert the same record twice
	// Pretty much copied from the Insert function without error checking.
	err := registry.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for i := 0; i < 2; i++ {
			record := p
			_, err := tx.Exec(
				insertKeysetQuery,
				id[:],
				record.Parent[:],
				record.FirstValid,
				record.LastValid,
				record.KeyDilution)
			if err != nil {
				return fmt.Errorf("unable to insert keyset: %w", err)
			}

			// Fetch primary key
			var pk int
			row := tx.QueryRow(selectLastPK, id[:])
			err = row.Scan(&pk)
			if err != nil {
				return fmt.Errorf("unable to scan pk: %w", err)
			}

			// Create Rolling entry
			_, err = tx.Exec(`INSERT INTO Rolling (pk, registeredFirstRound, registeredLastRound) VALUES (?, ?, ?)`, pk, 1, 2000000)
			if err != nil {
				return fmt.Errorf("unable insert rolling: %w", err)
			}

			var num int
			row = tx.QueryRow(`SELECT COUNT(*) FROM Keysets WHERE participationID=?`, id[:])
			err = row.Scan(&num)
			if err != nil {
				return fmt.Errorf("unable to scan pk: %w", err)
			}
		}

		return nil
	})

	a.NoError(err)
	// Detect multiple keys while initializing the cache
	err = registry.initializeCache()
	a.EqualError(err, ErrMultipleKeysForID.Error())

	// manually initialize the cache
	registry.cache[id] = ParticipationRecord{
		ParticipationID: id,
		Account:         p.Parent,
		FirstValid:      p.FirstValid,
		LastValid:       p.LastValid,
		KeyDilution:     p.KeyDilution,
		RegisteredFirst: p.FirstValid,
		RegisteredLast:  p.LastValid,
	}

	// Fail to register because there are multiple rows for the ID
	err = registry.Register(id, 1)
	a.Error(err)
	a.Contains(err.Error(), "unable to registering key with id")
	a.EqualError(errors.Unwrap(err), ErrMultipleKeysForID.Error())

	// Fail to flush dirty record because there are multiple rows for the ID
	registry.dirty[id] = struct{}{}
	err = registry.Flush()
	a.EqualError(err, ErrMultipleKeysForID.Error())
}
