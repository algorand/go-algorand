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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func getRegistry(t *testing.T) *participationDB {
	rootDB, err := db.OpenPair(t.Name(), true)
	require.NoError(t, err)

	registry, err := makeParticipationRegistry(rootDB, logging.TestingLog(t))
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

func makeTestParticipation(addrID byte, first, last basics.Round, dilution uint64) Participation {
	p := Participation{
		FirstValid:  first,
		LastValid:   last,
		KeyDilution: dilution,
		Voting:      &crypto.OneTimeSignatureSecrets{},
		VRF:         &crypto.VRFSecrets{},
	}
	p.Parent[0] = addrID
	return p
}

// Insert participation records and make sure they can be fetched.
func TestParticipation_InsertGet(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := makeTestParticipation(1, 1, 2, 3)
	p2 := makeTestParticipation(2, 4, 5, 6)

	insertAndVerify := func(part Participation) {
		id, err := registry.Insert(part)
		a.NoError(err)
		a.Equal(part.ParticipationID(), id)

		record := registry.Get(part.ParticipationID())
		a.False(record.IsZero())
		assertParticipation(t, part, record)
	}

	// Verify inserting some records.
	insertAndVerify(p)
	insertAndVerify(p2)

	// Data should be persisted immediately, re-initialize cache and verify GetAll.
	registry.initializeCache()
	results := registry.GetAll()
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

	p := makeTestParticipation(1, 1, 2, 3)
	p2 := makeTestParticipation(2, 4, 5, 6)

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
	results := registry.GetAll()
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
	p := makeTestParticipation(1, 250000, 3000000, 1)
	p2 := makeTestParticipation(1, 200000, 4000000, 2)

	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ParticipationID(), id)

	id, err = registry.Insert(p2)
	a.NoError(err)
	a.Equal(p2.ParticipationID(), id)

	verifyEffectiveRound := func(id ParticipationID, first, last int) {
		record := registry.Get(id)
		a.False(record.IsZero())
		require.Equal(t, first, int(record.EffectiveFirst))
		require.Equal(t, last, int(record.EffectiveLast))
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

	p := makeTestParticipation(0, 250000, 3000000, 1)

	err := registry.Register(p.ParticipationID(), 10000000)
	a.EqualError(err, ErrParticipationIDNotFound.Error())
}

// Test error attempting to register a key with an invalid range.
func TestParticipation_RegisterInvalidRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := makeTestParticipation(0, 250000, 3000000, 1)

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
	p := makeTestParticipation(1, 0, 3000000, 1)
	// Setup some other keys to make sure they are not updated.
	p2 := makeTestParticipation(2, 0, 3000000, 1)
	p3 := makeTestParticipation(3, 0, 3000000, 1)

	// Install and register all of the keys
	for _, part := range []Participation{p, p2, p3} {
		id, err := registry.Insert(part)
		a.NoError(err)
		a.Equal(part.ParticipationID(), id)
		err = registry.Register(part.ParticipationID(), 0)
		a.NoError(err)
	}

	all := registry.GetAll()
	a.NotNil(all)

	err := registry.Record(p.Parent, 1000, Vote)
	a.NoError(err)
	err = registry.Record(p.Parent, 2000, BlockProposal)
	a.NoError(err)
	err = registry.Record(p.Parent, 3000, CompactCertificate)
	a.NoError(err)

	// Verify that one and only one key was updated.
	test := func(registry ParticipationRegistry) {
		records := registry.GetAll()
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
	a.Len(registry.dirty, 0)

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

	p := makeTestParticipation(1, 0, 3000000, 1)
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

	p := makeTestParticipation(1, 0, 3000000, 1)
	p2 := makeTestParticipation(1, 1, 3000000, 1)

	_, err := registry.Insert(p)
	a.NoError(err)
	_, err = registry.Insert(p2)
	a.NoError(err)
	err = registry.Register(p.ParticipationID(), p.FirstValid)
	a.NoError(err)

	// Force the DB to have 2 active keys for one account by tampering with the private cache variable
	recordCopy := registry.cache[p2.ParticipationID()]
	recordCopy.EffectiveFirst = p2.FirstValid
	recordCopy.EffectiveLast = p2.LastValid
	registry.cache[p2.ParticipationID()] = recordCopy
	registry.dirty[p2.ParticipationID()] = struct{}{}
	registry.Flush()
	a.Len(registry.dirty, 0)
	registry.initializeCache()

	// Verify bad state - both records are valid until round 3 million
	a.NotEqual(p.ParticipationID(), p2.ParticipationID())
	recordTest := make([]ParticipationRecord, 0)

	recordP := registry.Get(p.ParticipationID())
	a.False(recordP.IsZero())
	recordTest = append(recordTest, recordP)

	recordP2 := registry.Get(p2.ParticipationID())
	a.False(recordP2.IsZero())
	recordTest = append(recordTest, recordP2)

	// Make sure both accounts are active for the test round
	for _, record := range recordTest {
		a.True(recordActive(record, testRound), "both records should be active")
	}

	err = registry.Record(p.Parent, testRound, Vote)
	a.EqualError(err, ErrMultipleValidKeys.Error())
}

func TestParticipation_MultipleInsertError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	p := makeTestParticipation(1, 1, 2, 3)

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

	p := makeTestParticipation(1, 1, 2000000, 3)
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
			_, err = tx.Exec(`INSERT INTO Rolling (pk, effectiveFirstRound, effectiveLastRound) VALUES (?, ?, ?)`, pk, 1, 200000)
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

	// Now that the DB has multiple records for one participation ID, check that all the methods notice.

	// Initializing the cache
	err = registry.initializeCache()
	a.EqualError(err, ErrMultipleKeysForID.Error())

	// Registering the ID - No error because it is already registered so we don't try to re-register.
	registry.cache[id] = ParticipationRecord{
		ParticipationID: id,
		Account:         p.Parent,
		FirstValid:      p.FirstValid,
		LastValid:       p.LastValid,
		KeyDilution:     p.KeyDilution,
		EffectiveFirst:  p.FirstValid,
		EffectiveLast:   p.LastValid,
	}
	err = registry.Register(id, 1)
	a.NoError(err)

	// Clear the first/last so that the no-op registration can't be detected
	record := registry.cache[id]
	record.EffectiveFirst = 0
	record.EffectiveLast = 0
	registry.cache[id] = record

	err = registry.Register(id, 1)
	a.Error(err)
	a.Contains(err.Error(), "unable to registering key with id")
	a.EqualError(errors.Unwrap(err), ErrMultipleKeysForID.Error())

	// Flushing changes detects that multiple records are updated
	registry.dirty[id] = struct{}{}
	err = registry.Flush()
	a.Len(registry.dirty, 1)
	a.EqualError(err, ErrMultipleKeysForID.Error())

	err = registry.Flush()
	a.EqualError(err, ErrMultipleKeysForID.Error())

	// Make sure the error message is logged when closing the registry.
	var logOutput strings.Builder
	registry.log.SetOutput(&logOutput)
	registry.Close()
	a.Contains(logOutput.String(), "participationDB unhandled error during Close/Flush")
	a.Contains(logOutput.String(), ErrMultipleKeysForID.Error())
}

func TestParticipation_NoKeyToUpdate(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry := getRegistry(t)
	defer registry.Close()

	registry.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		record := ParticipationRecord{
			ParticipationID: ParticipationID{},
			Account:         basics.Address{},
			FirstValid:      1,
			LastValid:       2,
			KeyDilution:     3,
			EffectiveFirst:  4,
			EffectiveLast:   5,
		}
		err := registry.updateRollingFields(ctx, tx, record)
		a.EqualError(err, ErrNoKeyForID.Error())
		return nil
	})
}
