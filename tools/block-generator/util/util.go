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

package util

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/algorand/go-algorand/data/basics"

	// import postgres driver
	_ "github.com/lib/pq"
)

// ErrorNotInitialized is returned when the database is not initialized.
var ErrorNotInitialized error = errors.New("database not initialized")

// MaybeFail exits if there was an error.
func MaybeFail(err error, errfmt string, params ...interface{}) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, errfmt, params...)
	fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
	os.Exit(1)
}

// GetNextRound returns the next account round from the metastate table.
func GetNextRound(postgresConnectionString string) (basics.Round, error) {
	conn, err := sql.Open("postgres", postgresConnectionString)
	if err != nil {
		return 0, fmt.Errorf("postgres connection string did not work: %w", err)
	}
	defer conn.Close()
	query := `SELECT v FROM metastate WHERE k='state';`
	var state []uint8
	if err = conn.QueryRow(query).Scan(&state); err != nil {
		if strings.Contains(err.Error(), `relation "metastate" does not exist`) {
			return 0, ErrorNotInitialized
		}
		return 0, fmt.Errorf("unable to get next db round: %w", err)
	}
	kv := make(map[string]basics.Round)
	err = json.Unmarshal(state, &kv)
	if err != nil {
		return 0, fmt.Errorf("unable to get next account round: %w", err)
	}
	return kv["next_account_round"], nil
}

// EmptyDB empties the database.
func EmptyDB(postgresConnectionString string) error {
	conn, err := sql.Open("postgres", postgresConnectionString)
	if err != nil {
		return fmt.Errorf("postgres connection string did not work: %w", err)
	}
	defer conn.Close()
	query := `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`
	if _, err = conn.Exec(query); err != nil {
		return fmt.Errorf("unable to reset postgres DB: %w", err)
	}
	return nil
}
