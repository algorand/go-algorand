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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

func TestParticipation_NewDB(t *testing.T) {
	a := require.New(t)

	rootDB, err := db.MakeAccessor(t.Name(), false, true)
	a.NoError(err)
	a.NotNil(rootDB)
	root, err := GenerateRoot(rootDB)
	a.NoError(err)
	a.NotNil(root)

	partDB, err := db.MakeAccessor(t.Name()+"_part", false, true)
	a.NoError(err)
	a.NotNil(partDB)

	part, err := FillDBWithParticipationKeys(partDB, root.Address(), 0, 0, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	a.NoError(err)
	a.NotNil(part)

	versions, err := getSchemaVersions(partDB)
	a.NoError(err)
	a.Equal(versions[PartTableSchemaName], PartTableSchemaVersion)
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
