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

type StateProofVerificationDbQueries struct {
	lookupStateProofVerificationContext *sql.Stmt
}

// StateProofVerificationInitDbQueries initializes queries that are being used to interact with
//  the stateproof verification table
func StateProofVerificationInitDbQueries(r db.Queryable) (*StateProofVerificationDbQueries, error) {
	var err error
	qs := &StateProofVerificationDbQueries{}

	qs.lookupStateProofVerificationContext, err = r.Prepare("SELECT verificationcontext FROM stateproofverification WHERE lastattestedround=?")
	if err != nil {
		return nil, err
	}

	return qs, nil
}

// WriteCatchpointStateProofVerificationContext inserts all the state proof verification data in the provided array into
// the catchpointstateproofverification table.
func WriteCatchpointStateProofVerificationContext(ctx context.Context, tx *sql.Tx, verificationContext *ledgercore.StateProofVerificationContext) error {
	insertStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointstateproofverification(lastattestedround, verificationContext) VALUES(?, ?)")

	if err != nil {
		return err
	}

	defer insertStmt.Close()

	_, err = insertStmt.ExecContext(ctx, verificationContext.LastAttestedRound, protocol.Encode(verificationContext))
	return err
}

func DeleteOldStateProofVerificationContext(ctx context.Context, tx *sql.Tx, earliestLastAttestedRound basics.Round) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM stateproofverification WHERE lastattestedround < ?", earliestLastAttestedRound)
	return err
}

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

func (qs *StateProofVerificationDbQueries) Close() {
	if qs.lookupStateProofVerificationContext != nil {
		qs.lookupStateProofVerificationContext.Close()
		qs.lookupStateProofVerificationContext = nil
	}
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

// StateProofVerification returns all state proof verification data from the stateProofVerification table.
func StateProofVerification(ctx context.Context, tx *sql.Tx) ([]ledgercore.StateProofVerificationContext, error) {
	return stateProofVerificationTable(ctx, tx, "stateProofVerification")
}

// CatchpointStateProofVerification returns all state proof verification data from the catchpointStateProofVerification table.
func CatchpointStateProofVerification(ctx context.Context, tx *sql.Tx) ([]ledgercore.StateProofVerificationContext, error) {
	return stateProofVerificationTable(ctx, tx, "catchpointStateProofVerification")
}
