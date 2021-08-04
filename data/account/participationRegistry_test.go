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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func getRegistry(t *testing.T) (db.Accessor, ParticipationRegistry) {
	rootDB, err := db.MakeAccessor(t.Name(), false, true)
	require.NoError(t, err)

	registry, err := MakeParticipationRegistry(rootDB)
	require.NoError(t, err)
	require.NotNil(t, registry)

	return rootDB, registry
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

	_, registry := getRegistry(t)

	// Create first record.
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
