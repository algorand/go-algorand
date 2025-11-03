// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"

	"github.com/mattn/go-sqlite3"
)

// Migration is used to upgrade a database from one version to the next.
// The Migration slice is ordered and must contain all prior migrations
// in order to determine which need to be called.
type Migration func(ctx context.Context, tx *sql.Tx, newDatabase bool) error

// Initialize creates or upgrades a DB accessor in a new atomic context.
// The Migration slice is ordered and must contain all prior migrations
// in order to determine which need to be called.
func Initialize(accessor Accessor, migrations []Migration) error {
	err := accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return InitializeWithContext(ctx, tx, migrations)
	})

	var sqlError sqlite3.Error
	if errors.As(err, &sqlError) {
		return fmt.Errorf("%w.  Sql error - Code: %d, Extended Code: %d", err, sqlError.Code, sqlError.ExtendedCode)
	}

	return err

}

// InitializeWithContext creates or upgrades a DB accessor.
func InitializeWithContext(ctx context.Context, tx *sql.Tx, migrations []Migration) error {
	// check current database version
	dbVersion, err := GetUserVersion(ctx, tx)
	if err != nil {
		return ErrUnableToRead
	}

	version := int32(len(migrations))

	// if database version is greater than supported by current binary, write a warning. This would keep the existing
	// fallback behavior where we could use an older binary iff the schema happen to be backward compatible.
	if dbVersion > version {
		return MakeErrUnknownVersion(dbVersion, version)
	}

	// if database is not up to date run migration functions.
	if dbVersion < version {
		var newDatabase bool
		for i := dbVersion; i < version; i++ {
			err = migrations[i](ctx, tx, newDatabase)
			if err != nil && err != ErrNoOpMigration {
				return MakeErrUpgradeFailure(dbVersion, i)
			}

			// Something like this is used by the account DB to conditionally skip things.
			if i == 0 && err != ErrNoOpMigration {
				newDatabase = true
			}

			// update version
			_, err = SetUserVersion(ctx, tx, i+1)
			if err != nil {
				return MakeErrUpgradeFailure(dbVersion, i)
			}
		}
	}

	return nil
}

// ErrUnableToRead is returned when the accessor cannot be read.
var ErrUnableToRead = errors.New("unable to read database")

// ErrNoOpMigration is returned when there was no work for the migration to perform.
var ErrNoOpMigration = errors.New("migration no-op")

// ErrUnknownVersion is returned when a migration to the current version is not available.
type ErrUnknownVersion struct {
	CurrentVersion   int32
	SupportedVersion int32
}

// Error implements the error interface.
func (err *ErrUnknownVersion) Error() string {
	return fmt.Sprintf("database schema version is %d, but algod only supports up to %d", err.CurrentVersion, err.SupportedVersion)
}

// MakeErrUnknownVersion makes an ErrUnknownVersion.
func MakeErrUnknownVersion(currentVersion, supportedVersion int32) *ErrUnknownVersion {
	return &ErrUnknownVersion{
		CurrentVersion:   currentVersion,
		SupportedVersion: supportedVersion,
	}
}

// ErrUpgradeFailure is returned when a migration returns an error.
type ErrUpgradeFailure struct {
	SchemaVersionFrom int32
	SchemaVersionTo   int32
}

// Error implements the error interface.
func (err *ErrUpgradeFailure) Error() string {
	return fmt.Sprintf("failed to upgrade database from schema %d to %d", err.SchemaVersionFrom, err.SchemaVersionTo)
}

// MakeErrUpgradeFailure makes an ErrUpgradeFailure.
func MakeErrUpgradeFailure(from, to int32) *ErrUpgradeFailure {
	return &ErrUpgradeFailure{
		SchemaVersionFrom: from,
		SchemaVersionTo:   to,
	}
}
