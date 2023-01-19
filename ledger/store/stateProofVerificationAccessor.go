// Copyright (C) 2019-2023 Algorand, Inc.
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

package store

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// StateProofVerificationDbQueries is used to cache a prepared SQL statement to look up
// state proof verification contexts
type StateProofVerificationDbQueries struct {
	lookupStateProofVerificationContext *sql.Stmt
}

// StateProofVerificationInitDbQueries initializes queries that are being used to interact with
// the stateproof verification table
func StateProofVerificationInitDbQueries(r db.Queryable) (*StateProofVerificationDbQueries, error) {
	var err error
	qs := &StateProofVerificationDbQueries{}

	qs.lookupStateProofVerificationContext, err = r.Prepare("SELECT verificationcontext FROM stateproofverification WHERE lastattestedround=?")
	if err != nil {
		return nil, err
	}

	return qs, nil
}

// LookupContext retrieves stateproof verification context from the database.
func (qs *StateProofVerificationDbQueries) LookupContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	verificationContext := ledgercore.StateProofVerificationContext{}
	queryFunc := func() error {
		row := qs.lookupStateProofVerificationContext.QueryRow(stateProofLastAttestedRound)
		var buf []byte
		err := row.Scan(&buf)
		if err != nil {
			return err
		}
		err = protocol.Decode(buf, &verificationContext)
		if err != nil {
			return err
		}
		return nil
	}

	err := db.Retry(queryFunc)
	return &verificationContext, err
}

// Close release all resources related to StateProofVerificationDbQueries.
func (qs *StateProofVerificationDbQueries) Close() {
	if qs.lookupStateProofVerificationContext != nil {
		qs.lookupStateProofVerificationContext.Close()
		qs.lookupStateProofVerificationContext = nil
	}
}

// DeleteOldStateProofVerificationContext removes a single state proof verification data from the database.
func DeleteOldStateProofVerificationContext(ctx context.Context, tx *sql.Tx, earliestLastAttestedRound basics.Round) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM stateproofverification WHERE lastattestedround < ?", earliestLastAttestedRound)
	return err
}

// stateProofVerificationTable returns all verification data currently committed to the given table.
func stateProofVerificationTable(ctx context.Context, tx *sql.Tx, tableName string) ([]ledgercore.StateProofVerificationContext, error) {
	var result []ledgercore.StateProofVerificationContext
	queryFunc := func() error {
		selectQuery := fmt.Sprintf("SELECT verificationContext FROM %s ORDER BY lastattestedround", tableName)
		rows, err := tx.QueryContext(ctx, selectQuery)

		if err != nil {
			return err
		}

		defer rows.Close()

		// Clear `res` in case this function is repeated.
		result = result[:0]
		for rows.Next() {
			var rawData []byte
			err = rows.Scan(&rawData)
			if err != nil {
				return err
			}

			var record ledgercore.StateProofVerificationContext
			err = protocol.Decode(rawData, &record)
			if err != nil {
				return err
			}

			result = append(result, record)
		}

		return nil
	}

	err := db.Retry(queryFunc)
	return result, err
}

// GetAllStateProofVerificationContexts returns all contexts needed to verify state proofs.
func GetAllStateProofVerificationContexts(ctx context.Context, tx *sql.Tx) ([]ledgercore.StateProofVerificationContext, error) {
	return stateProofVerificationTable(ctx, tx, "stateProofVerification")
}

// GetAllCatchpointStateProofVerification returns all state proof verification data from the catchpointStateProofVerification table.
func GetAllCatchpointStateProofVerification(ctx context.Context, tx *sql.Tx) ([]ledgercore.StateProofVerificationContext, error) {
	return stateProofVerificationTable(ctx, tx, "catchpointStateProofVerification")
}

type stateProofVerificationWriter struct {
	spWriteStmt *sql.Stmt
	ctx         context.Context
}

// MakeStateProofVerificationWriter creates a writer that can be used to write state proof verification context to the database.
func MakeStateProofVerificationWriter(ctx context.Context, tx *sql.Tx) (*stateProofVerificationWriter, error) {
	return makeSpInsertStatement(ctx, tx, "stateproofverification")
}

// MakeStateProofVerificationWriterToCatchpoint creates a writer that can be used to write state proof verification context to the catchpoint database.
func MakeStateProofVerificationWriterToCatchpoint(ctx context.Context, tx *sql.Tx) (*stateProofVerificationWriter, error) {
	return makeSpInsertStatement(ctx, tx, "catchpointstateproofverification")
}

func makeSpInsertStatement(ctx context.Context, tx *sql.Tx, tableName string) (*stateProofVerificationWriter, error) {
	writer := &stateProofVerificationWriter{}
	var err error

	insertQuery := fmt.Sprintf("INSERT INTO %s(lastattestedround, verificationContext) VALUES(?, ?)", tableName)
	writer.spWriteStmt, err = tx.PrepareContext(ctx, insertQuery)
	if err != nil {
		return nil, err
	}

	writer.ctx = ctx
	return writer, nil
}

// WriteStateProofVerificationContext writes a single state proof verification context to the database.
func (spw *stateProofVerificationWriter) WriteStateProofVerificationContext(verificationContext *ledgercore.StateProofVerificationContext) error {
	_, err := spw.spWriteStmt.ExecContext(spw.ctx, verificationContext.LastAttestedRound, protocol.Encode(verificationContext))
	return err
}

// Close release all resources related to stateProofVerificationWriter.
func (spw *stateProofVerificationWriter) Close() {
	spw.spWriteStmt.Close()
}
