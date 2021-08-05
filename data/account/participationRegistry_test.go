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
	"fmt"
	"github.com/algorand/go-algorand/data/basics"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func getRegistry(t *testing.T) ParticipationRegistry {
	rootDB, err := db.OpenPair(t.Name(), true)
	require.NoError(t, err)

	registry, err := MakeParticipationRegistry(rootDB)
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

func TestParticipation_InsertGet(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)

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

	// Verify GetAll.
	results, err := registry.GetAll()
	a.NoError(err)
	a.Len(results, 2)
	assertParticipation(t, p, results[0])
	assertParticipation(t, p2, results[1])
}

func TestParticipation_Delete(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)

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

	// Verify p removed in GetAll.
	results, err := registry.GetAll()
	a.NoError(err)
	a.Len(results, 1)
	assertParticipation(t, p2, results[0])
}

func TestParticipation_Register(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)

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
		require.Equal(t, first, int(record.EffectiveFirst))
		require.Equal(t, last, int(record.EffectiveLast))
	}

	// Register the first key.
	err = registry.Register(p.ParticipationID(), 500000)
	a.NoError(err)
	verifyEffectiveRound(p.ParticipationID(), 500320, int(p.LastValid))

	// Register second key.
	err = registry.Register(p2.ParticipationID(), 2500000)
	a.NoError(err)
	verifyEffectiveRound(p.ParticipationID(), 500320, 2500320)
	verifyEffectiveRound(p2.ParticipationID(), 2500320, int(p2.LastValid))
}

func TestParticipation_RegisterInvalidID(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)

	p := Participation{
		FirstValid:  250000,
		LastValid:   3000000,
		KeyDilution: 1,
	}

	err := registry.Register(p.ParticipationID(), 10000000)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "unable to lookup id"))
}

func TestParticipation_RegisterInvalidRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)

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

func TestParticipation_Record(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)

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

func TestParticipation_RecordInvalidType(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	registry := getRegistry(t)

	err := registry.Record(basics.Address{}, 0, ParticipationAction(9000))
	a.EqualError(err, ErrUnknownParticipationAction.Error())
}

func TestParticipation_RecordMultipleUpdates(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	rootDB, err := db.OpenPair(t.Name(), true)
	require.NoError(t, err)
	registry, err := MakeParticipationRegistry(rootDB)
	require.NoError(t, err)
	require.NotNil(t, registry)

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

	_, err = registry.Insert(p)
	a.NoError(err)
	_, err = registry.Insert(p2)
	a.NoError(err)
	err = registry.Register(p.ParticipationID(), 1000)
	a.NoError(err)

	// Force the DB into a bad state (2 active keys for one account).
	rootDB.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		id := p2.ParticipationID()
		_, err = tx.Exec(setRegistered, 1000+maxBalLookback, p2.LastValid, id[:])
		if err != nil {
			return fmt.Errorf("unable to update registered key: %w", err)
		}
		return nil
	})

	err = registry.Record(p.Parent, 5000, Vote)
	a.EqualError(err, "too many rows effected: 2")
}
