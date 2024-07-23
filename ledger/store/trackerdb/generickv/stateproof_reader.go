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

type stateproofReader struct {
	kvr KvRead
}

// MakeStateproofReader returns a trackerdb.SpVerificationCtxReader for a KV
func MakeStateproofReader(kvr KvRead) trackerdb.SpVerificationCtxReader {
	return &stateproofReader{kvr}
}

// LookupSPContext implements trackerdb.SpVerificationCtxReader
func (r *stateproofReader) LookupSPContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	// SQL at the time of writing:
	//
	// SELECT
	//		verificationcontext
	// FROM stateproofverification
	// WHERE lastattestedround=?

	key := stateproofKey(stateProofLastAttestedRound)
	value, closer, err := r.kvr.Get(key[:])
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	var vc ledgercore.StateProofVerificationContext
	err = protocol.Decode(value, &vc)
	if err != nil {
		return nil, err
	}

	return &vc, nil
}

// GetAllSPContexts implements trackerdb.SpVerificationCtxReader
func (r *stateproofReader) GetAllSPContexts(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	// SQL at the time of writing:
	//
	// SELECT
	// 		verificationContext
	// FROM stateProofVerification
	// ORDER BY lastattestedround

	low, high := stateproofFullRangePrefix()
	iter := r.kvr.NewIter(low[:], high[:], false)
	defer iter.Close()

	results := make([]ledgercore.StateProofVerificationContext, 0)

	var value []byte
	var err error
	for iter.Next() {
		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return nil, err
		}

		// decode the value
		vc := ledgercore.StateProofVerificationContext{}
		err = protocol.Decode(value, &vc)
		if err != nil {
			return nil, err
		}

		// add the item to the results
		results = append(results, vc)
	}

	return results, nil
}

// GetAllSPContextsFromCatchpointTbl implements trackerdb.SpVerificationCtxReader
func (r *stateproofReader) GetAllSPContextsFromCatchpointTbl(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error) {
	// TODO: catchpoint
	return nil, nil
}
