// Copyright (C) 2019-2024 Algorand, Inc.
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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

var stateProofIntervalForTests = config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval

func getRegistry(t testing.TB) (registry *participationDB, dbfile string) {
	return getRegistryImpl(t, true, false)
}

func getRegistryImpl(t testing.TB, inMem bool, erasable bool) (registry *participationDB, dbName string) {
	var rootDB db.Pair
	var err error
	dbName = strings.Replace(t.Name(), "/", "_", -1)
	if erasable {
		require.False(t, inMem, "erasable registry can't be in-memory")
		rootDB, err = db.OpenErasablePair(dbName)
	} else {
		rootDB, err = db.OpenPair(dbName, inMem)
	}
	require.NoError(t, err)

	registry, err = makeParticipationRegistry(rootDB, logging.TestingLog(t))
	require.NoError(t, err)
	require.NotNil(t, registry)

	if inMem { // no files to clean up
		dbName = ""
	}
	return registry, dbName
}

func assertParticipation(t testing.TB, p Participation, pr ParticipationRecord) {
	require.Equal(t, p.FirstValid, pr.FirstValid)
	require.Equal(t, p.LastValid, pr.LastValid)
	require.Equal(t, p.KeyDilution, pr.KeyDilution)
	require.Equal(t, p.Parent, pr.Account)
	if p.StateProofSecrets != nil {
		require.Equal(t, p.StateProofSecrets.GetVerifier().Commitment[:], pr.StateProof.Commitment[:])
		require.Equal(t, p.StateProofSecrets.GetVerifier().KeyLifetime, pr.StateProof.KeyLifetime)
	}

}

func makeTestParticipation(a *require.Assertions, addrID int, first, last basics.Round, dilution uint64) Participation {
	return makeTestParticipationWithLifetime(a, addrID, first, last, dilution, uint64((last+1)/2))
}

func makeTestParticipationWithLifetime(a *require.Assertions, addrID int, first, last basics.Round, dilution uint64, keyLifetime uint64) Participation {
	a.True(first < last)

	// Generate sample of stateproof keys. because it might take time we will reduce the number always to get 2 keys
	stateProofSecrets, err := merklesignature.New(uint64(first), uint64(last), keyLifetime)
	a.NoError(err)

	// Generate part keys like in partGenerateCmd and FillDBWithParticipationKeys
	if dilution == 0 {
		dilution = DefaultKeyDilution(first, last)
	}

	// Compute how many distinct participation keys we should generate
	firstID := basics.OneTimeIDForRound(first, dilution)
	lastID := basics.OneTimeIDForRound(last, dilution)
	numBatches := lastID.Batch - firstID.Batch + 1

	// Generate them
	votingSecrets := crypto.GenerateOneTimeSignatureSecrets(firstID.Batch, numBatches)

	// Generate a new VRF key, which lives in the participation keys db
	vrf := crypto.GenerateVRFSecrets()

	p := Participation{
		FirstValid:        first,
		LastValid:         last,
		KeyDilution:       dilution,
		Voting:            votingSecrets,
		VRF:               vrf,
		StateProofSecrets: stateProofSecrets,
	}

	binary.LittleEndian.PutUint32(p.Parent[:], uint32(addrID))
	return p
}

func registryCloseTest(t testing.TB, registry *participationDB, dbfilePrefix string) {
	start := time.Now()
	registry.Close()
	duration := time.Since(start)
	assert.Less(t, uint64(duration), uint64(defaultTimeout))
	// clean up DB files
	if dbfilePrefix != "" {
		dbfiles, err := filepath.Glob(dbfilePrefix + "*")
		require.NoError(t, err)
		for _, f := range dbfiles {
			t.Log("removing", f)
			require.NoError(t, os.Remove(f))
		}
	}
}

// Insert participation records and make sure they can be fetched.
func TestParticipation_InsertGet(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 1, 1, 2, 3)
	p2 := makeTestParticipation(a, 2, 4, 5, 6)

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

// Insert participation records and make sure they can be fetched.
func TestParticipation_InsertGetWithoutEmptyStateproof(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := Participation{
		FirstValid:  1,
		LastValid:   3,
		KeyDilution: 1,
		Voting:      &crypto.OneTimeSignatureSecrets{},
		VRF:         &crypto.VRFSecrets{},
	}

	binary.LittleEndian.PutUint32(p.Parent[:], uint32(1))

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

	// Data should be available immediately
	results := registry.GetAll()
	if results[0].Account == p.Parent {
		assertParticipation(t, p, results[0])
		a.Nil(results[0].StateProof)
	} else {
		a.Fail("unexpected account")
	}
}

// Make sure a record can be deleted by id.
func TestParticipation_Delete(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistryImpl(t, false, true) // inMem=false, erasable=true
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 1, 1, 2, 3)
	p2 := makeTestParticipation(a, 2, 4, 5, 6)

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

type testMessage string

func (m testMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, []byte(m)
}

func TestParticipation_DeleteExpired(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistryImpl(t, false, true) // inMem=false, erasable=true
	defer registryCloseTest(t, registry, dbfile)

	keyDilution := 1
	for i := 10; i < 20; i++ {
		p := makeTestParticipation(a, i, 1, basics.Round(i), uint64(keyDilution))
		id, err := registry.Insert(p)
		a.NoError(err)
		a.Equal(p.ID(), id)
	}

	latestRound := basics.Round(15)
	err := registry.DeleteExpired(latestRound, config.Consensus[protocol.ConsensusCurrentVersion])
	a.NoError(err)

	checkExpired := func(getAll []ParticipationRecord) {
		a.Len(getAll, 5, "The first 5 should be deleted.")

		proto := config.Consensus[protocol.ConsensusCurrentVersion]
		for _, p := range getAll {
			// like in loadRoundParticipationKeys
			prfr := ParticipationRecordForRound{p}
			voting := prfr.VotingSigner()

			// count remaining batches (with keyDilution = 1)
			keysLeft := len(p.Voting.Offsets) + len(p.Voting.Batches)*keyDilution
			a.Equal(int(p.LastValid-latestRound), keysLeft)

			// attempt to sign old rounds (will log warning)
			ephID := basics.OneTimeIDForRound(basics.Round(latestRound), voting.KeyDilution(proto.DefaultKeyDilution))
			sig := voting.Sign(ephID, testMessage("hello"))
			a.Empty(sig)
		}
	}
	checkExpired(registry.GetAll())

	// Check persisting. Verify by re-initializing the cache.
	a.NoError(registry.Flush(defaultTimeout))
	a.NoError(registry.initializeCache())
	checkExpired(registry.GetAll())
}

func TestParticipation_CleanupTablesAfterDeleteExpired(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistryImpl(t, false, true) // inMem=false, erasable=true
	defer registryCloseTest(t, registry, dbfile)

	keyDilution := 1
	for i := 10; i < 20; i++ {
		p := makeTestParticipation(a, i, 1, basics.Round(i), uint64(keyDilution))
		id, err := registry.Insert(p)
		a.NoError(err)
		a.Equal(p.ID(), id)

		err = registry.AppendKeys(id, p.StateProofSecrets.GetAllKeys())
		a.NoError(err)
	}

	a.NoError(registry.Flush(defaultTimeout))

	latestRound := basics.Round(50)
	err := registry.DeleteExpired(latestRound, config.Consensus[protocol.ConsensusCurrentVersion])
	a.NoError(err)

	a.NoError(registry.Flush(defaultTimeout))
	var numOfRecords int
	// make sure tables are clean
	err = registry.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow(`select count(*) from Keysets`)
		err = row.Scan(&numOfRecords)
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}
		return nil
	})

	a.NoError(err)
	a.Equal(0, numOfRecords)

	err = registry.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow(`select count(*) from Rolling`)
		err = row.Scan(&numOfRecords)
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}
		return nil
	})
	a.NoError(err)
	a.Equal(0, numOfRecords)

	err = registry.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow(`select count(*) from stateproofkeys`)
		err = row.Scan(&numOfRecords)
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}
		return nil
	})
	a.NoError(err)
	a.Equal(0, numOfRecords)
}

// Make sure the register function properly sets effective first/last for all effected records.
func TestParticipation_Register(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	// Overlapping keys.
	p := makeTestParticipation(a, 1, 250000, 3000000, 0)
	p2 := makeTestParticipation(a, 1, 200000, 4000000, 0)

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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 0, 250000, 3000000, 0)

	err := registry.Register(p.ID(), 10000000)
	a.EqualError(err, ErrParticipationIDNotFound.Error())
}

// Test error attempting to register a key with an invalid range.
func TestParticipation_RegisterInvalidRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 0, 250000, 3000000, 0)

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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	// Setup p
	p := makeTestParticipation(a, 1, 0, 3000000, 0)
	// Setup some other keys to make sure they are not updated.
	p2 := makeTestParticipation(a, 2, 0, 3000000, 0)
	p3 := makeTestParticipation(a, 3, 0, 3000000, 0)

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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 1, 0, 3000000, 0)
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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	err := registry.Record(basics.Address{}, 0, Vote)
	a.EqualError(err, ErrActiveKeyNotFound.Error())
}

// Test that an error is generated if the record function updates multiple records.
// This would only happen if the DB was in an inconsistent state.
func TestParticipation_RecordMultipleUpdates(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	// We'll test that recording at this round fails because both keys are active
	testRound := basics.Round(5000)

	p := makeTestParticipation(a, 1, 0, 3000000, 0)
	p2 := makeTestParticipation(a, 1, 1, 3000000, 0)

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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 1, 1, 2, 3)

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
	registry, _ := getRegistry(t)

	p := makeTestParticipation(a, 1, 1, 2000000, 0)
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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	access, err := db.MakeAccessor(t.Name()+"_writetest_root", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	access.Close()
	a.NoError(err)

	access, err = db.MakeAccessor(t.Name()+"_writetest", false, true)
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
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	access, err := db.MakeAccessor(t.Name()+"_writetest_root", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	access.Close()
	a.NoError(err)

	access, err = db.MakeAccessor(t.Name()+"_writetest", false, true)
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
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	p := makeTestParticipation(a, 1, 1, 2, 3)
	p2 := makeTestParticipation(a, 2, 4, 5, 6)

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

	registry.writeQueue <- makeOpRequest(&registerOp{updates})

	a.NoError(registry.Flush(defaultTimeout))

	// This time, make it required and we should have an error
	updates[id2] = updatingParticipationRecord{
		ParticipationRecord: record2,
		required:            true,
	}

	registry.writeQueue <- makeOpRequest(&registerOp{updates})

	err = registry.Flush(defaultTimeout)
	a.Contains(err.Error(), "unable to disable old key when registering")
	a.Contains(err.Error(), ErrNoKeyForID.Error())
}

// TestFlushDeadlock reproduced a deadlock when calling Flush repeatedly. This test reproduced the deadlock and
// verifies the fix.
func TestFlushDeadlock(t *testing.T) {
	var wg sync.WaitGroup

	partitiontest.PartitionTest(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

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
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	// Install a key to add StateProof keys.
	max := uint64(20)
	p := makeTestParticipationWithLifetime(a, 1, 0, basics.Round(max), 3, 3)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	// Wait for async DB operations to finish.
	err = registry.Flush(10 * time.Second)
	a.NoError(err)

	signer, err := merklesignature.New(1, max, 3)
	a.NoError(err)
	// Initialize keys array.
	keys := signer.GetAllKeys()

	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	// Wait for async DB operations to finish.
	err = registry.Flush(10 * time.Second)
	a.NoError(err)

	_, err = registry.GetStateProofSecretsForRound(id, basics.Round(1))
	a.Error(err)
	_, err = registry.GetStateProofSecretsForRound(id, basics.Round(2))
	a.Error(err)

	// Make sure we're able to fetch the same data that was put in.
	for i := uint64(3); i < max; i++ {
		r, err := registry.GetStateProofSecretsForRound(id, basics.Round(i))
		a.NoError(err)

		if r.StateProofSecrets != nil {
			j := i/3 - 1 // idx in keys array

			a.Equal(*keys[j].Key, *r.StateProofSecrets.SigningKey)

			keyFirstValidRound, err := r.StateProofSecrets.FirstRoundInKeyLifetime()
			a.NoError(err)

			a.Equal(keys[j].Round, keyFirstValidRound)
		}
	}
}

func TestGetRoundSecretsWithNilStateProofVerifier(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	access, err := db.MakeAccessor(t.Name()+"_stateprooftest", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	p, err := FillDBWithParticipationKeys(access, root.Address(), 0, basics.Round(stateProofIntervalForTests*2), 3)
	access.Close()
	a.NoError(err)

	// Install a key for testing
	id, err := registry.Insert(p.Participation)
	a.NoError(err)

	// ensuring that GetStateProof will receive from cache a participationRecord without StateProof field.
	prt := registry.cache[id]
	prt.StateProof = nil
	registry.cache[id] = prt

	a.NoError(registry.Flush(defaultTimeout))

	_, err = registry.GetStateProofSecretsForRound(id, basics.Round(stateProofIntervalForTests)-1)
	a.ErrorIs(err, ErrStateProofVerifierNotFound)
}

func TestSecretNotFound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	// Install a key for testing
	p := makeTestParticipation(a, 1, 0, 2, 3)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	_, err = registry.GetForRound(id, basics.Round(2))
	a.NoError(err)

	_, err = registry.GetForRound(id, basics.Round(100))
	a.ErrorIs(err, ErrRequestedRoundOutOfRange)
}

func TestAddingSecretTwice(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	access, err := db.MakeAccessor(t.Name()+"_stateprooftest", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	p, err := FillDBWithParticipationKeys(access, root.Address(), 0, basics.Round(stateProofIntervalForTests*2), 3)
	access.Close()
	a.NoError(err)

	// Install a key for testing
	id, err := registry.Insert(p.Participation)
	a.NoError(err)
	a.Equal(p.ID(), id)

	// Append key
	var keys StateProofKeys

	keysRound := merklesignature.KeyRoundPair{Round: stateProofIntervalForTests, Key: p.StateProofSecrets.GetKey(stateProofIntervalForTests)}
	keys = append(keys, keysRound)

	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	// The error doesn't happen until the data persists.
	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	err = registry.Flush(10 * time.Second)
	a.Error(err)
	a.EqualError(err, "unable to execute append keys: UNIQUE constraint failed: StateProofKeys.pk, StateProofKeys.round")
}

func TestGetRoundSecretsWithoutStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	access, err := db.MakeAccessor(t.Name()+"_stateprooftest", false, true)
	if err != nil {
		panic(err)
	}
	root, err := GenerateRoot(access)
	p, err := FillDBWithParticipationKeys(access, root.Address(), 0, basics.Round(stateProofIntervalForTests*2), 3)
	access.Close()
	a.NoError(err)

	// Install a key for testing
	id, err := registry.Insert(p.Participation)
	a.NoError(err)

	a.NoError(registry.Flush(defaultTimeout))

	partPerRound, err := registry.GetStateProofSecretsForRound(id, 1)
	a.Error(err)

	partPerRound, err = registry.GetStateProofSecretsForRound(id, basics.Round(stateProofIntervalForTests))
	a.Error(err)

	// Append key
	keys := make(StateProofKeys, 1)
	keys[0] = merklesignature.KeyRoundPair{Round: stateProofIntervalForTests, Key: p.StateProofSecrets.GetKey(stateProofIntervalForTests)}

	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	a.NoError(registry.Flush(defaultTimeout))

	partPerRound, err = registry.GetStateProofSecretsForRound(id, basics.Round(stateProofIntervalForTests)-1)
	a.Error(err)

	partPerRound, err = registry.GetStateProofSecretsForRound(id, basics.Round(stateProofIntervalForTests))
	a.NoError(err)
	a.NotNil(partPerRound.StateProofSecrets)

	a.Equal(*partPerRound.StateProofSecrets.SigningKey, *keys[0].Key)
	a.Equal(stateProofIntervalForTests, keys[0].Round)
}

type keypairs []merklesignature.KeyRoundPair

func (k keypairs) findPairForSpecificRound(round uint64) merklesignature.KeyRoundPair {
	for _, pair := range k {
		if pair.Round == round {
			return pair
		}
	}
	return merklesignature.KeyRoundPair{}
}

func TestDeleteStateProofKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	// Install a key to add StateProof keys.
	maxRound := uint64(20)
	p := makeTestParticipationWithLifetime(a, 1, 0, basics.Round(maxRound), 3, 4)
	id, err := registry.Insert(p)
	a.NoError(err)
	a.Equal(p.ID(), id)

	// Wait for async DB operations to finish.
	a.NoError(registry.Flush(10 * time.Second))

	keys := keypairs(p.StateProofSecrets.GetAllKeys())

	a.NoError(registry.AppendKeys(id, StateProofKeys(keys)))

	// Wait for async DB operations to finish.
	a.NoError(registry.Flush(10 * time.Second))

	// Make sure we're able to fetch the same data that was put in.
	for i := uint64(4); i < maxRound; i += 4 {
		r, err := registry.GetStateProofSecretsForRound(id, basics.Round(i))
		a.NoError(err)

		a.Equal(keys.findPairForSpecificRound(i).Key, r.StateProofSecrets.SigningKey)
	}

	removeKeysRound := basics.Round(maxRound / 2)
	a.NoError(registry.DeleteStateProofKeys(id, removeKeysRound))

	a.NoError(registry.Flush(10 * time.Second))

	// verify that the db does not contain any state proof key with round less than 10

	registry.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var pk int
		a.NoError(tx.QueryRow(selectPK, id[:]).Scan(&pk))

		// make certain keys below the cutting round do not exist in the db.
		var num int
		a.NoError(
			tx.QueryRow(
				"SELECT COUNT(*) FROM StateProofKeys where pk=? AND round <=?",
				pk,
				removeKeysRound,
			).Scan(&num),
		)
		a.Zero(num)

		// make certain keys above the cutting round exist in the db.
		a.NoError(
			tx.QueryRow(
				"SELECT COUNT(*) FROM StateProofKeys where pk=? AND round >?",
				pk,
				removeKeysRound,
			).Scan(&num),
		)

		// includes removeKeysRound
		a.Equal(int(maxRound)/4-int(removeKeysRound)/4, num) // 1 DELETED 1 NOT
		return nil
	})
}

// test that sets up an error that should come up while flushing, and ensures that flush resets the last error
func TestFlushResetsLastError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := assert.New(t)
	registry, dbfile := getRegistry(t)
	defer registryCloseTest(t, registry, dbfile)

	access, err := db.MakeAccessor(t.Name()+"_stateprooftest", false, true)
	a.NoError(err)

	root, err := GenerateRoot(access)
	p, err := FillDBWithParticipationKeys(access, root.Address(), 0, basics.Round(stateProofIntervalForTests*2), 3)
	access.Close()
	a.NoError(err)

	// Install a key for testing
	id, err := registry.Insert(p.Participation)
	a.NoError(err)
	a.Equal(p.ID(), id)

	// Append key
	var keys StateProofKeys

	keysRound := merklesignature.KeyRoundPair{Round: stateProofIntervalForTests, Key: p.StateProofSecrets.GetKey(stateProofIntervalForTests)}
	keys = append(keys, keysRound)

	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	// The error doesn't happen until the data persists.
	err = registry.AppendKeys(id, keys)
	a.NoError(err)

	a.Error(registry.Flush(10 * time.Second))
	a.NoError(registry.Flush(10 * time.Second))
}

// TestParticipationDB_Locking tries fetching StateProof keys from the DB while the Rolling table is being updated.
// Makes sure the table is not locked for reading while a different one is locked for writing.
func TestParticipationDB_Locking(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	dbName := strings.Replace(t.Name(), "/", "_", -1)

	dbpair, err := db.OpenErasablePair(dbName + ".sqlite3")
	a.NoError(err)

	var bufNewLogger bytes.Buffer
	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	log.SetOutput(&bufNewLogger)
	dbpair.Rdb.SetLogger(log)

	registry, err := makeParticipationRegistry(dbpair, logging.TestingLog(t))
	require.NoError(t, err)
	require.NotNil(t, registry)

	defer registryCloseTest(t, registry, dbName)

	var id2 ParticipationID
	for i := 0; i < 3; i++ {
		part := makeTestParticipation(a, 1, 0, 511, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		id, err := registry.Insert(part)
		if i == 0 {
			id2 = id
		}
		a.NoError(err)
		a.NoError(registry.AppendKeys(id, part.StateProofSecrets.GetAllKeys()))
		a.NoError(registry.Flush(defaultTimeout))
		a.Equal(id, part.ID())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var flushCount int32
	const targetFlushes = 5
	go func() {
		for i := 0; i < 25; i++ {
			registry.DeleteExpired(basics.Round(i), config.Consensus[protocol.ConsensusCurrentVersion])
			registry.Flush(defaultTimeout)
			if atomic.LoadInt32(&flushCount) < targetFlushes {
				atomic.AddInt32(&flushCount, 1)
			}
		}
		wg.Done()
	}()

	for i := 0; i < 25; i++ {
	repeat:
		// to not start lookup until deleted some keys
		if atomic.LoadInt32(&flushCount) < targetFlushes {
			time.Sleep(time.Second)
			goto repeat
		}
		_, err = registry.GetStateProofSecretsForRound(id2, basics.Round(256))
		// The error we're trying to avoid is "database is locked", since we're reading from StateProofKeys table,
		// while the main thread is updating the Rolling table.
		a.NoError(err)
		time.Sleep(100 * time.Millisecond)
	}

	warnings := bufNewLogger.String()
	deadlineCount := strings.Count(warnings, "tx surpassed expected deadline")
	a.Empty(deadlineCount, fmt.Sprintf("found %d messages 'tx surpassed expected deadline' but expected 0", deadlineCount))
	wg.Wait()
}

func TestParticipationDBInstallWhileReading(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	if testing.Short() {
		t.Skip()
	}

	dbName := strings.Replace(t.Name(), "/", "_", -1)

	dbpair, err := db.OpenErasablePair(dbName + ".sqlite3")
	a.NoError(err)

	registry, err := makeParticipationRegistry(dbpair, logging.TestingLog(t))
	require.NoError(t, err)
	require.NotNil(t, registry)
	defer registryCloseTest(t, registry, dbName)

	var sampledPartID ParticipationID
	for i := 0; i < 3; i++ {
		part := makeTestParticipation(a, 1, 0, 511, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		id, err := registry.Insert(part)
		if i == 0 {
			sampledPartID = id
		}
		a.NoError(err)
		a.NoError(registry.AppendKeys(id, part.StateProofSecrets.GetAllKeys()))
		a.NoError(registry.Flush(defaultTimeout))
		a.Equal(id, part.ID())
	}

	appendedKeys := make(chan struct{})
	newPart := makeTestParticipationWithLifetime(a, 1, 0, 3000000, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution, merklesignature.KeyLifetimeDefault)
	go func() {
		id, err := registry.Insert(newPart)
		a.NoError(err)
		a.NoError(registry.AppendKeys(id, newPart.StateProofSecrets.GetAllKeys()))
		appendedKeys <- struct{}{}
		a.NoError(registry.Flush(defaultTimeout))
		a.Equal(id, newPart.ID())
	}()

	<-appendedKeys // Makes sure we start fetching keys after the append keys operation has already started
	for i := 0; i < 50; i++ {
		_, err = registry.GetStateProofSecretsForRound(sampledPartID, basics.Round(256))
		// The error we're trying to avoid is "database is locked", since we're reading from StateProofKeys table,
		// while a different go routine is installing new keys.
		a.NoError(err)
	}
}

// based on BenchmarkOldKeysDeletion
func BenchmarkDeleteExpired(b *testing.B) {
	for _, erasable := range []bool{true, false} {
		b.Run(fmt.Sprintf("erasable=%v", erasable), func(b *testing.B) {
			a := require.New(b)

			registry, dbfile := getRegistryImpl(b, false, erasable) // set inMem=false
			defer func() {
				registryCloseTest(b, registry, dbfile)
			}()

			// make participation key
			lastValid := 3000000
			keyDilution := 10000
			if kd, err := strconv.Atoi(os.Getenv("DILUTION")); err == nil { // allow setting key dilution via env var
				keyDilution = kd
			}
			if lv, err := strconv.Atoi(os.Getenv("LASTVALID")); err == nil { // allow setting last valid via env var
				lastValid = lv
			}
			var part Participation

			numKeys := 1
			if nk, err := strconv.Atoi(os.Getenv("NUMKEYS")); err == nil { // allow setting numKeys via env var
				numKeys = nk
			}
			for i := 0; i < numKeys; i++ {
				if os.Getenv("SLOWKEYS") == "" {
					// makeTestParticipation makes small state proof secrets to save time
					b.Log("making fast part key", i, "for firstValid 0 lastValid", lastValid, "dilution", keyDilution)
					part = makeTestParticipation(a, i+1, 0, basics.Round(lastValid), uint64(keyDilution))
					a.NotNil(part)
				} else {
					// generate key the same way as BenchmarkOldKeysDeletion
					var rootAddr basics.Address
					crypto.RandBytes(rootAddr[:])

					ppartDB, err := db.MakeErasableAccessor("bench_part")
					a.NoError(err)
					a.NotNil(ppartDB)
					defer func() {
						os.Remove("bench_part")
					}()

					b.Log("making part key", i, "for firstValid 0 lastValid", lastValid, "dilution", keyDilution)
					ppart, err := FillDBWithParticipationKeys(ppartDB, rootAddr, 0, basics.Round(lastValid), uint64(keyDilution))
					ppartDB.Close()
					a.NoError(err)
					part = ppart.Participation
				}

				// insertAndVerify new registry key
				id, err := registry.Insert(part)
				a.NoError(err)
				a.Equal(part.ID(), id)
				record := registry.Get(part.ID())
				a.False(record.IsZero())
				assertParticipation(b, part, record)
			}

			results := registry.GetAll()
			a.Len(results, numKeys, "registry.GetAll() should return %d keys, but instead returned %v", numKeys, len(results))

			// run N rounds of DeleteExpired + Flush
			var err error
			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			b.Log("starting DeleteExpired benchmark up to round", b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err = registry.DeleteExpired(basics.Round(i), proto)
				if err != nil {
					break
				}
				err = registry.Flush(defaultTimeout)
				if err != nil {
					break
				}
			}
			b.StopTimer()
			a.NoError(err)
		})
	}
}
