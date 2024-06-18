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

package sqlitedriver

import (
	"context"
	"database/sql"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type stateProofVerificationReader struct {
	q db.Queryable
}

type stateProofVerificationWriter struct {
	e db.Executable
}

type stateProofVerificationReaderWriter struct {
	stateProofVerificationReader
	stateProofVerificationWriter
}

func makeStateProofVerificationReader(q db.Queryable) *stateProofVerificationReader {
	return &stateProofVerificationReader{q: q}
}

func makeStateProofVerificationWriter(e db.Executable) *stateProofVerificationWriter {
	return &stateProofVerificationWriter{e: e}
}

func makeStateProofVerificationReaderWriter(q db.Queryable, e db.Executable) *stateProofVerificationReaderWriter {
	return &stateProofVerificationReaderWriter{
		stateProofVerificationReader{q: q},
		stateProofVerificationWriter{e: e},
	}
}

// MakeStateProofVerificationReader returns SpVerificationCtxReader for accessing from outside of ledger
func MakeStateProofVerificationReader(q db.Queryable) trackerdb.SpVerificationCtxReader {
	return makeStateProofVerificationReader(q)
}

// LookupSPContext retrieves stateproof verification context from the database.
func (spa *stateProofVerificationReader) LookupSPContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	verificationContext := ledgercore.StateProofVerificationContext{}
	queryFunc := func() error {
		row := spa.q.QueryRow("SELECT verificationcontext FROM stateproofverification WHERE lastattestedround=?", stateProofLastAttestedRound)
		var buf []byte
		err := row.Scan(&buf)
		if err == sql.ErrNoRows {
			return trackerdb.ErrNotFound
		} else if err != nil {
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

// DeleteOldSPContexts removes a single state proof verification data from the database.
func (spa *stateProofVerificationWriter) DeleteOldSPContexts(ctx context.Context, earliestLastAttestedRound basics.Round) error {
	_, err := spa.e.ExecContext(ctx, "DELETE FROM stateproofverification WHERE lastattestedround < ?", earliestLastAttestedRound)
	return err
}

// StoreSPContexts stores a single state proof verification context to database
func (spa *stateProofVerificationWriter) StoreSPContexts(ctx context.Context, verificationContext []*ledgercore.StateProofVerificationContext) error {
	spWriteStmt, err := spa.e.PrepareContext(ctx, "INSERT INTO stateProofVerification(lastattestedround, verificationContext) VALUES(?, ?)")
	if err != nil {
		return err
	}
	for i := range verificationContext {
		_, err = spWriteStmt.ExecContext(ctx, verificationContext[i].LastAttestedRound, protocol.Encode(verificationContext[i]))
		if err != nil {
			return err
		}
	}

	return nil
}

// StoreSPContextsToCatchpointTbl stores state proof verification contexts to catchpoint staging table
func (spa *stateProofVerificationWriter) StoreSPContextsToCatchpointTbl(ctx context.Context, verificationContexts []ledgercore.StateProofVerificationContext) error {
	spWriteStmt, err := spa.e.PrepareContext(ctx, "INSERT INTO catchpointstateproofverification(lastattestedround, verificationContext) VALUES(?, ?)")
	if err != nil {
		return err
	}

	for i := range verificationContexts {
		_, err = spWriteStmt.ExecContext(ctx, verificationContexts[i].LastAttestedRound, protocol.Encode(&verificationContexts[i]))
		if err != nil {
			return err
		}
	}
	return nil
}

// GetAllSPContexts returns all contexts needed to verify state proofs.
func (spa *stateProofVerificationReader) GetAllSPContexts(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	return spa.getAllSPContextsInternal(ctx, "SELECT verificationContext FROM stateProofVerification ORDER BY lastattestedround")
}

// GetAllSPContextsFromCatchpointTbl returns all state proof verification data from the catchpointStateProofVerification table.
func (spa *stateProofVerificationReader) GetAllSPContextsFromCatchpointTbl(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	return spa.getAllSPContextsInternal(ctx, "SELECT verificationContext FROM catchpointStateProofVerification ORDER BY lastattestedround")
}

func (spa *stateProofVerificationReader) getAllSPContextsInternal(ctx context.Context, query string) ([]ledgercore.StateProofVerificationContext, error) {
	var result []ledgercore.StateProofVerificationContext
	queryFunc := func() error {
		rows, err := spa.q.QueryContext(ctx, query)
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
