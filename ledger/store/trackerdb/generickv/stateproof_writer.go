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

package generickv

import (
	"context"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

type stateproofWriter struct {
	kvw KvWrite
}

// MakeStateproofWriter returns a trackerdb.SpVerificationCtxWriter for a KV
func MakeStateproofWriter(kvw KvWrite) trackerdb.SpVerificationCtxWriter {
	return &stateproofWriter{kvw}
}

// StoreSPContexts implements trackerdb.SpVerificationCtxWriter
func (w *stateproofWriter) StoreSPContexts(ctx context.Context, verificationContext []*ledgercore.StateProofVerificationContext) error {
	// SQL at the time of writing:
	//
	// INSERT INTO stateProofVerification
	//		(lastattestedround, verificationContext)
	// VALUES
	//		(?, ?)

	for i := range verificationContext {
		// write stateproof entry
		vc := verificationContext[i]
		raw := protocol.Encode(vc)
		key := stateproofKey(vc.LastAttestedRound)
		err := w.kvw.Set(key[:], raw)
		if err != nil {
			return err
		}
	}

	return nil
}

// DeleteOldSPContexts implements trackerdb.SpVerificationCtxWriter
func (w *stateproofWriter) DeleteOldSPContexts(ctx context.Context, earliestLastAttestedRound basics.Round) error {
	// SQL at the time of writing:
	//
	// DELETE FROM stateproofverification
	// WHERE lastattestedround < ?

	start, end := stateproofRoundRangePrefix(earliestLastAttestedRound)
	return w.kvw.DeleteRange(start[:], end[:])
}

// StoreSPContextsToCatchpointTbl implements trackerdb.SpVerificationCtxWriter
func (w *stateproofWriter) StoreSPContextsToCatchpointTbl(ctx context.Context, verificationContexts []ledgercore.StateProofVerificationContext) error {
	// TODO: catchpoint
	return nil
}
