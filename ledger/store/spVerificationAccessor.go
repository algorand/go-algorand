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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// SPVerificationAccessor is used to read and write state proof verification contexts
type SPVerificationAccessor struct {
	e db.Executable
}

// MakeSPVerificationAccessor returns accessor that allows reading and writing of state proof verification
// contexts
func MakeSPVerificationAccessor(e db.Executable) *SPVerificationAccessor {
	return &SPVerificationAccessor{e: e}
}

// LookupSPContext retrieves stateproof verification context from the database.
func (spa *SPVerificationAccessor) LookupSPContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	verificationContext := ledgercore.StateProofVerificationContext{}
	queryFunc := func() error {
		row := spa.e.QueryRow("SELECT verificationcontext FROM stateproofverification WHERE lastattestedround=?", stateProofLastAttestedRound)
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

// DeleteOldSPContexts removes a single state proof verification data from the database.
func (spa *SPVerificationAccessor) DeleteOldSPContexts(ctx context.Context, earliestLastAttestedRound basics.Round) error {
	_, err := spa.e.ExecContext(ctx, "DELETE FROM stateproofverification WHERE lastattestedround < ?", earliestLastAttestedRound)
	return err
}

// StoreSPContexts stores a single state proof verification context to database
func (spa *SPVerificationAccessor) StoreSPContexts(ctx context.Context, verificationContext []*ledgercore.StateProofVerificationContext) error {
	spWriteStmt, err := spa.e.PrepareContext(ctx, "INSERT INTO stateProofVerification(lastattestedround, verificationContext) VALUES(?, ?)")
	if err != nil {
		return err
	}
	for _, e := range verificationContext {
		_, err = spWriteStmt.ExecContext(ctx, e.LastAttestedRound, protocol.Encode(e))
		if err != nil {
			return err
		}
	}

	return nil
}

// StoreSPContextsToCatchpointTbl stores state proof verification contexts to catchpoint staging table
func (spa *SPVerificationAccessor) StoreSPContextsToCatchpointTbl(ctx context.Context, verificationContexts []ledgercore.StateProofVerificationContext) error {
	spWriteStmt, err := spa.e.PrepareContext(ctx, "INSERT INTO catchpointstateproofverification(lastattestedround, verificationContext) VALUES(?, ?)")
	if err != nil {
		return err
	}

	for _, data := range verificationContexts {
		_, err = spWriteStmt.ExecContext(ctx, data.LastAttestedRound, protocol.Encode(&data))
		if err != nil {
			return err
		}
	}
	return nil
}

// GetAllSPContexts returns all contexts needed to verify state proofs.
func (spa *SPVerificationAccessor) GetAllSPContexts(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	return spa.getAllSPContextsInternal(ctx, "SELECT verificationContext FROM stateProofVerification ORDER BY lastattestedround")
}

// GetAllSPContextsFromCatchpointTbl returns all state proof verification data from the catchpointStateProofVerification table.
func (spa *SPVerificationAccessor) GetAllSPContextsFromCatchpointTbl(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	return spa.getAllSPContextsInternal(ctx, "SELECT verificationContext FROM catchpointStateProofVerification ORDER BY lastattestedround")
}

func (spa *SPVerificationAccessor) getAllSPContextsInternal(ctx context.Context, query string) ([]ledgercore.StateProofVerificationContext, error) {
	var result []ledgercore.StateProofVerificationContext
	queryFunc := func() error {
		rows, err := spa.e.QueryContext(ctx, query)
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
