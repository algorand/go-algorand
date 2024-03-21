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

package dualdriver

import (
	"context"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/google/go-cmp/cmp"
)

type stateproofReader struct {
	primary   trackerdb.SpVerificationCtxReader
	secondary trackerdb.SpVerificationCtxReader
}

// LookupSPContext implements trackerdb.SpVerificationCtxReader
func (r *stateproofReader) LookupSPContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	vcP, errP := r.primary.LookupSPContext(stateProofLastAttestedRound)
	vcS, errS := r.secondary.LookupSPContext(stateProofLastAttestedRound)
	// coalesce errors
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	// check results match
	if !cmp.Equal(vcP, vcS, allowAllUnexported) {
		err = ErrInconsistentResult
		return nil, err
	}
	// return primary results
	return vcP, nil
}

// GetAllSPContexts implements trackerdb.SpVerificationCtxReader
func (r *stateproofReader) GetAllSPContexts(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	resultsP, errP := r.primary.GetAllSPContexts(ctx)
	resultsS, errS := r.secondary.GetAllSPContexts(ctx)
	// coalesce errors
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	// check results match
	if !cmp.Equal(resultsP, resultsS, allowAllUnexported) {
		err = ErrInconsistentResult
		return nil, err
	}
	// return primary results
	return resultsP, nil
}

// GetAllSPContextsFromCatchpointTbl implements trackerdb.SpVerificationCtxReader
func (r *stateproofReader) GetAllSPContextsFromCatchpointTbl(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	resultsP, errP := r.primary.GetAllSPContextsFromCatchpointTbl(ctx)
	resultsS, errS := r.secondary.GetAllSPContextsFromCatchpointTbl(ctx)
	// coalesce errors
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	// check results match
	if !cmp.Equal(resultsP, resultsS, allowAllUnexported) {
		err = ErrInconsistentResult
		return nil, err
	}
	// return primary results
	return resultsP, nil
}
