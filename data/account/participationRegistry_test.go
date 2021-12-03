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
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
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

func makeTestParticipation(addrID int, first, last basics.Round, dilution uint64) Participation {
	p := Participation{
		FirstValid:  first,
		LastValid:   last,
		KeyDilution: dilution,
		Voting:      &crypto.OneTimeSignatureSecrets{},
		VRF:         &crypto.VRFSecrets{},
	}
	binary.LittleEndian.PutUint32(p.Parent[:], uint32(addrID))
	return p
}

func registryCloseTest(t *testing.T, registry *participationDB) {
	start := time.Now()
	registry.Close()
	duration := time.Since(start)
	assert.Less(t, uint64(duration), uint64(defaultTimeout))
}

// Insert participation records and make sure they can be fetched.
func TestParticipation_InsertGet(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	p := makeTestParticipation(1, 1, 2, 3)
	p2 := makeTestParticipation(2, 4, 5, 6)

	insertAndVerify := func(part Participation) {
		id, err := registry.Insert(part)
		a.NoError(err)
		a.Equal(part.ID(), id)

		record := registry.Get(part.ID())
		a.False(record.IsZero())
		assertParticipation(t, part, record)
	}

	// Verify inserting some records.
	insertAndVerify(p)
	insertAndVerify(p2)

	// Data should be available immediately
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

	// Check that Flush works, re-initialize cache and verify GetAll.
	a.NoError(registry.Flush(defaultTimeout))
	a.NoError(registry.initializeCache())
	results = registry.GetAll()
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
	defer registryCloseTest(t, registry)

	p := makeTestParticipation(1, 1, 2, 3)
	p2 := makeTestParticipation(2, 4, 5, 6)

	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	id, err = registry.Insert(p2)
	a.NoError(err)
	a.Equal(p2.ID(), id)

	err = registry.Delete(p.ID())
	a.NoError(err)

	results := registry.GetAll()
	a.Len(results, 1)
	assertParticipation(t, p2, results[0])

	// Check that result was persisted.
	a.NoError(registry.Flush(defaultTimeout))
	a.NoError(registry.initializeCache())
	results = registry.GetAll()
	a.Len(results, 1)
	assertParticipation(t, p2, results[0])
}

func TestParticipation_DeleteExpired(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	for i := 10; i < 20; i++ {
		p := makeTestParticipation(i, 1, basics.Round(i), 1)
		id, err := registry.Insert(p)
		a.NoError(err)
		a.Equal(p.ID(), id)
	}

	err := registry.DeleteExpired(15)
	a.NoError(err)

	a.Len(registry.GetAll(), 5, "The first 5 should be deleted.")

	// Check persisting. Verify by re-initializing the cache.
	a.NoError(registry.Flush(defaultTimeout))
	a.NoError(registry.initializeCache())
	a.Len(registry.GetAll(), 5, "The first 5 should be deleted.")
}

// Make sure the register function properly sets effective first/last for all effected records.
func TestParticipation_Register(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	// Overlapping keys.
	p := makeTestParticipation(1, 250000, 3000000, 1)
	p2 := makeTestParticipation(1, 200000, 4000000, 2)

	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	id, err = registry.Insert(p2)
	a.NoError(err)
	a.Equal(p2.ID(), id)

	verifyEffectiveRound := func(id ParticipationID, first, last int) {
		record := registry.Get(id)
		a.False(record.IsZero())
		require.Equal(t, first, int(record.EffectiveFirst))
		require.Equal(t, last, int(record.EffectiveLast))
	}

	// Register the first key.
	err = registry.Register(p.ID(), 500000)
	a.NoError(err)
	verifyEffectiveRound(p.ID(), 500000, int(p.LastValid))

	// Register second key.
	err = registry.Register(p2.ID(), 2500000)
	a.NoError(err)
	verifyEffectiveRound(p.ID(), 500000, 2499999)
	verifyEffectiveRound(p2.ID(), 2500000, int(p2.LastValid))
}

// Test error when registering a non-existing participation ID.
func TestParticipation_RegisterInvalidID(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	p := makeTestParticipation(0, 250000, 3000000, 1)

	err := registry.Register(p.ID(), 10000000)
	a.EqualError(err, ErrParticipationIDNotFound.Error())
}

// Test error attempting to register a key with an invalid range.
func TestParticipation_RegisterInvalidRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	p := makeTestParticipation(0, 250000, 3000000, 1)

	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	// Register the first key.
	err = registry.Register(p.ID(), 1000000000)
	a.EqualError(err, ErrInvalidRegisterRange.Error())
}

// Test the recording function.
func TestParticipation_Record(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	// Setup p
	p := makeTestParticipation(1, 0, 3000000, 1)
	// Setup some other keys to make sure they are not updated.
	p2 := makeTestParticipation(2, 0, 3000000, 1)
	p3 := makeTestParticipation(3, 0, 3000000, 1)

	// Install and register all of the keys
	for _, part := range []Participation{p, p2, p3} {
		id, err := registry.Insert(part)
		a.NoError(err)
		a.Equal(part.ID(), id)
		err = registry.Register(part.ID(), 0)
		a.NoError(err)
	}

	a.NotNil(registry.GetAll())

	a.NoError(registry.Record(p.Parent, 1000, Vote))
	a.NoError(registry.Record(p.Parent, 2000, BlockProposal))
	a.NoError(registry.Record(p.Parent, 3000, StateProof))

	// Verify that one and only one key was updated.
	test := func(registry ParticipationRegistry) {
		records := registry.GetAll()
		a.Len(records, 3)
		for _, record := range records {
			if record.ParticipationID == p.ID() {
				require.Equal(t, 1000, int(record.LastVote))
				require.Equal(t, 2000, int(record.LastBlockProposal))
				require.Equal(t, 3000, int(record.LastStateProof))
			} else {
				require.Equal(t, 0, int(record.LastVote))
				require.Equal(t, 0, int(record.LastBlockProposal))
				require.Equal(t, 0, int(record.LastStateProof))
			}
		}
	}

	test(registry)
	a.NoError(registry.Flush(defaultTimeout))
	a.Len(registry.dirty, 0)

	// Re-initialize
	a.NoError(registry.initializeCache())
	test(registry)
}

// Test that attempting to record an invalid action generates an error.
func TestParticipation_RecordInvalidActionAndOutOfRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

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
	defer registryCloseTest(t, registry)

	err := registry.Record(basics.Address{}, 0, Vote)
	a.EqualError(err, ErrActiveKeyNotFound.Error())
}

// Test that an error is generated if the record function updates multiple records.
// This would only happen if the DB was in an inconsistent state.
func TestParticipation_RecordMultipleUpdates(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	// We'll test that recording at this round fails because both keys are active
	testRound := basics.Round(5000)

	p := makeTestParticipation(1, 0, 3000000, 1)
	p2 := makeTestParticipation(1, 1, 3000000, 1)

	_, err := registry.Insert(p)
	a.NoError(err)
	_, err = registry.Insert(p2)
	a.NoError(err)
	err = registry.Register(p.ID(), p.FirstValid)
	a.NoError(err)

	// Force the DB to have 2 active keys for one account by tampering with the private cache variable
	recordCopy := registry.cache[p2.ID()]
	recordCopy.EffectiveFirst = p2.FirstValid
	recordCopy.EffectiveLast = p2.LastValid
	registry.cache[p2.ID()] = recordCopy
	registry.dirty[p2.ID()] = struct{}{}
	a.NoError(registry.Flush(defaultTimeout))
	a.Len(registry.dirty, 0)
	a.NoError(registry.initializeCache())

	// Verify bad state - both records are valid until round 3 million
	a.NotEqual(p.ID(), p2.ID())
	recordTest := make([]ParticipationRecord, 0)

	recordP := registry.Get(p.ID())
	a.False(recordP.IsZero())
	recordTest = append(recordTest, recordP)

	recordP2 := registry.Get(p2.ID())
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
	defer registryCloseTest(t, registry)

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
	id := p.ID()

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
				record.KeyDilution,
				nil,
				nil)
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
	a.NoError(err)
	err = registry.Flush(defaultTimeout)
	a.Error(err)
	a.Contains(err.Error(), "unable to disable old key")
	a.EqualError(errors.Unwrap(err), ErrMultipleKeysForID.Error())

	// Flushing changes detects that multiple records are updated
	registry.dirty[id] = struct{}{}
	err = registry.Flush(defaultTimeout)
	a.EqualError(err, ErrMultipleKeysForID.Error())
	a.Len(registry.dirty, 1)

	err = registry.Flush(defaultTimeout)
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
	defer registryCloseTest(t, registry)

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
		err := updateRollingFields(ctx, tx, record)
		a.EqualError(err, ErrNoKeyForID.Error())
		return nil
	})
}

// TestParticipion_Blobs adds some secrets to the registry and makes sure the same ones are returned.
func TestParticipion_Blobs(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	access, err := db.MakeAccessor("writetest_root", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	access.Close()
	a.NoError(err)

	access, err = db.MakeAccessor("writetest", false, true)
	if err != nil {
		panic(err)
	}
	part, err := FillDBWithParticipationKeys(access, root.Address(), 0, 101, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	access.Close()
	a.NoError(err)

	check := func(id ParticipationID) {
		record := registry.Get(id)
		a.NotEqual(ParticipationRecord{}, record)
		a.Equal(id, record.ParticipationID)
		a.Equal(part.VRF, record.VRF)
		a.Equal(part.Voting.Snapshot(), record.Voting.Snapshot())
	}

	id, err := registry.Insert(part.Participation)
	a.NoError(err)
	a.NoError(registry.Flush(defaultTimeout))
	a.Equal(id, part.ID())
	// check the initial caching
	check(id)

	// check the re-initialized object
	a.NoError(registry.initializeCache())
	check(id)
}

// TestParticipion_EmptyBlobs makes sure empty blobs are set to nil
func TestParticipion_EmptyBlobs(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	access, err := db.MakeAccessor("writetest_root", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	access.Close()
	a.NoError(err)

	access, err = db.MakeAccessor("writetest", false, true)
	if err != nil {
		panic(err)
	}
	part, err := FillDBWithParticipationKeys(access, root.Address(), 0, 101, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	access.Close()
	a.NoError(err)
	part.VRF = nil
	part.Voting = nil

	check := func(id ParticipationID) {
		record := registry.Get(id)
		a.NotEqual(ParticipationRecord{}, record)
		a.Equal(id, record.ParticipationID)
		a.True(record.VRF.MsgIsZero())
		a.True(record.Voting.MsgIsZero())
	}

	id, err := registry.Insert(part.Participation)
	a.NoError(err)
	a.NoError(registry.Flush(defaultTimeout))
	a.Equal(id, part.ID())
	// check the initial caching
	check(id)

	// check the re-initialized object
	a.NoError(registry.initializeCache())
	check(id)
}

func TestRegisterUpdatedEvent(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	p := makeTestParticipation(1, 1, 2, 3)
	p2 := makeTestParticipation(2, 4, 5, 6)

	id1, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id1)

	id2, err := registry.Insert(p2)
	a.NoError(err)
	a.Equal(p2.ID(), id2)

	record1 := registry.Get(id1)
	a.False(record1.IsZero())
	record2 := registry.Get(id2)
	a.False(record2.IsZero())

	// Delete the second one to make sure it can't be updated.
	a.NoError(registry.Delete(id2))
	a.NoError(registry.Flush(defaultTimeout))

	// Ignore optional error
	updates := make(map[ParticipationID]updatingParticipationRecord)
	updates[id1] = updatingParticipationRecord{
		ParticipationRecord: record1,
		required:            true,
	}
	updates[id2] = updatingParticipationRecord{
		ParticipationRecord: record2,
		required:            false,
	}

	registry.writeQueue <- partDBWriteRecord{
		registerUpdated: updates,
	}

	a.NoError(registry.Flush(defaultTimeout))

	// This time, make it required and we should have an error
	updates[id2] = updatingParticipationRecord{
		ParticipationRecord: record2,
		required:            true,
	}

	registry.writeQueue <- partDBWriteRecord{
		registerUpdated: updates,
	}

	err = registry.Flush(defaultTimeout)
	a.Contains(err.Error(), "unable to disable old key when registering")
	a.Contains(err.Error(), ErrNoKeyForID.Error())
}

// TestFlushDeadlock reproduced a deadlock when calling Flush repeatedly. This test reproduced the deadlock and
// verifies the fix.
func TestFlushDeadlock(t *testing.T) {
	var wg sync.WaitGroup

	partitiontest.PartitionTest(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	spam := func() {
		defer wg.Done()
		timeout := time.After(time.Second)
		for {
			select {
			case <-timeout:
				return
			default:
				// If there is a deadlock, this timeout will trigger.
				assert.NoError(t, registry.Flush(2*time.Second))
			}
		}
	}

	// Start spammers.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go spam()
	}

	wg.Wait()
}

func TestAddStateProofKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	// Install a key to add StateProof keys.
	max := uint64(1000)
	p := makeTestParticipation(1, 0, basics.Round(max), 3)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	// Wait for async DB operations to finish.
	err = registry.Flush(10 * time.Second)
	a.NoError(err)

	// Initialize keys array.
	keys := make(map[uint64]StateProofKey)
	for i := uint64(0); i <= max; i++ {
		bs := make([]byte, 8)
		binary.LittleEndian.PutUint64(bs, i)
		keys[i] = bs
	}

	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	// Wait for async DB operations to finish.
	err = registry.Flush(10 * time.Second)
	a.NoError(err)

	// Make sure we're able to fetch the same data that was put in.
	for i := uint64(0); i <= max; i++ {
		r, err := registry.GetForRound(id, basics.Round(i))
		a.NoError(err)
		a.Equal(keys[i], r.StateProof)
		number := binary.LittleEndian.Uint64(r.StateProof)
		a.Equal(i, number)
	}
}

func TestSecretNotFound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	// Install a key for testing
	p := makeTestParticipation(1, 0, 2, 3)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	r, err := registry.GetForRound(id, basics.Round(100))

	a.True(r.IsZero())
	a.Error(err)
	a.ErrorIs(err, ErrSecretNotFound)
}

func TestAddingSecretTwice(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry := getRegistry(t)
	defer registryCloseTest(t, registry)

	// Install a key for testing
	p := makeTestParticipation(1, 0, 2, 3)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	// Append key
	keys := make(map[uint64]StateProofKey)
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, 10)
	keys[0] = bs

	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	// The error doesn't happen until the data persists.
	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	err = registry.Flush(10 * time.Second)
	a.Error(err)
	a.EqualError(err, "unable to execute append keys: UNIQUE constraint failed: StateProofKeys.pk, StateProofKeys.round")
}
