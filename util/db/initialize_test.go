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

package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A few migrations functions to mix and match in tests.
var (
	createFoo = func(ctx context.Context, tx *sql.Tx, newDatabase bool) error {
		_, err := tx.Exec(`CREATE TABLE foo (field INTEGER)`)
		return err
	}

	addToFoo = func(amount int) Migration {
		return func(ctx context.Context, tx *sql.Tx, newDatabase bool) error {
			_, err := tx.Exec(`INSERT INTO foo (field) VALUES(?)`, amount)
			return err
		}
	}

	returnError = func(err error) Migration {
		return func(ctx context.Context, tx *sql.Tx, newDatabase bool) error {
			return err
		}
	}

	// Check the sum of the field column.
	verifyFoo = func(expected int) func(t *testing.T, ctx context.Context, tx *sql.Tx) {
		return func(t *testing.T, ctx context.Context, tx *sql.Tx) {
			var field int
			err := tx.QueryRow(`SELECT COALESCE(SUM(field), 0) FROM foo`).Scan(&field)
			assert.NoError(t, err)
			assert.Equal(t, expected, field)
		}
	}
)

func TestInitialize(t *testing.T) {
	partitiontest.PartitionTest(t)

	testcases := []struct {
		name            string
		migrations      []Migration
		expectedVersion int32
		verify          func(t *testing.T, ctx context.Context, tx *sql.Tx)
		expectedError   error
	}{
		{
			name: "Simple",
			migrations: []Migration{
				createFoo,
			},
			expectedVersion: 1,
			verify:          verifyFoo(0),
		},
		{
			name: "Multiple",
			migrations: []Migration{
				createFoo,
				addToFoo(1),
				addToFoo(10),
				addToFoo(100),
				addToFoo(1000),
			},
			expectedVersion: 5,
			verify:          verifyFoo(1111),
		},
		{
			name: "Error + rollback",
			migrations: []Migration{
				createFoo,
				addToFoo(1),
				returnError(errors.New("did not finish")),
				addToFoo(10),
			},
			expectedVersion: 0,
			verify:          nil,
			expectedError:   MakeErrUpgradeFailure(0, 2),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			// Setup
			accessor, err := MakeAccessor("test_"+testcase.name, false, true)
			require.NoError(t, err)
			defer accessor.Close()

			err = Initialize(accessor, testcase.migrations)

			// Check error.
			if testcase.expectedError == nil {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, testcase.expectedError.Error())
			}

			// Check results.
			accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				version, err := GetUserVersion(ctx, tx)
				assert.NoError(t, err)
				assert.Equal(t, testcase.expectedVersion, version)

				if testcase.verify != nil {
					testcase.verify(t, ctx, tx)
				}
				return nil
			})
		})
	}
}

func TestReadOnlyError(t *testing.T) {
	partitiontest.PartitionTest(t)

	expiredContext, expiredContextCancelFunc := context.WithCancel(context.Background())
	expiredContextCancelFunc()
	err := InitializeWithContext(expiredContext, nil, []Migration{createFoo})

	require.EqualError(t, err, ErrUnableToRead.Error())
}

func TestUnknownVersionError(t *testing.T) {
	partitiontest.PartitionTest(t)

	accessor, err := MakeAccessor("test-unknown-version", false, true)
	require.NoError(t, err)
	defer accessor.Close()

	migrations := []Migration{
		createFoo,
		addToFoo(1),
	}

	// Initialize to version 2
	err = Initialize(accessor, migrations)
	require.NoError(t, err)

	// Initialize with only version 1
	err = Initialize(accessor, []Migration{createFoo})
	require.EqualError(t, err, MakeErrUnknownVersion(2, 1).Error())
}

func TestNewDBFlag(t *testing.T) {
	partitiontest.PartitionTest(t)

	var captureNewDB bool
	newDBCheck := func(ctx context.Context, tx *sql.Tx, newDatabase bool) error {
		captureNewDB = newDatabase
		return nil
	}

	testcases := []struct {
		name          string
		migrations    []Migration
		expectedNewDB bool
	}{
		{
			name: "no-op-migration-0",
			migrations: []Migration{
				returnError(ErrNoOpMigration),
				newDBCheck,
			},
			expectedNewDB: false,
		},
		{
			name: "regular-migration",
			migrations: []Migration{
				newDBCheck,
				newDBCheck,
			},
			expectedNewDB: true,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			accessor, err := MakeAccessor("test_"+testcase.name, false, true)
			require.NoError(t, err)
			defer accessor.Close()

			err = Initialize(accessor, testcase.migrations)
			require.NoError(t, err)

			require.Equal(t, testcase.expectedNewDB, captureNewDB)
		})
	}
}

func TestResumeUpgrading(t *testing.T) {
	partitiontest.PartitionTest(t)

	accessor, err := MakeAccessor("test-resume", false, true)
	require.NoError(t, err)
	defer accessor.Close()

	// Initialize to version 2
	migrations := []Migration{
		createFoo,
		addToFoo(1),
	}
	err = Initialize(accessor, migrations)
	require.NoError(t, err)

	// Re-initialize and upgrade to version 4
	migrations = []Migration{
		createFoo,
		addToFoo(1),
		addToFoo(10),
		addToFoo(100),
	}
	err = Initialize(accessor, migrations)
	require.NoError(t, err)

	accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		verifyFoo(111)(t, ctx, tx)
		return nil
	})
}
