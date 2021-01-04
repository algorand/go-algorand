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

package db

import (
	"context"
	"database/sql"
	"fmt"
)

// this file contains database versioning that can be applied to any sqlite database.

// GetUserVersion returns the user version field stored in the sqlite database
// if the database was never initiliazed with a version, it would return 0 as the version.
func GetUserVersion(ctx context.Context, tx *sql.Tx) (userVersion int32, err error) {

	err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion)
	// it's not really supposed to happen with a user_version, since the above would always succeed, but
	// we want to have it so that we can align with the SQL statements "correct handling practices".
	if err == sql.ErrNoRows {
		err = nil
		userVersion = 0
	}
	return
}

// SetUserVersion sets the userVersion as the new user version, and return the old version.
func SetUserVersion(ctx context.Context, tx *sql.Tx, userVersion int32) (previousUserVersion int32, err error) {
	previousUserVersion, err = GetUserVersion(ctx, tx)
	if err != nil {
		return
	}
	if previousUserVersion == userVersion {
		return
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", userVersion))
	if err != nil {
		// if we're aborting due to an error, clear the previousUserVersion so that
		// on all error cases we'll be returning zero.
		previousUserVersion = 0
		return
	}
	return
}
