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

package testsuite

import (
	"context"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/stretchr/testify/require"
)

func init() {
	// register tests that will run on each KV implementation
	registerTest("stateproofs-crud", CustomTestStateproofsReadWrite)
	registerTest("stateproofs-query-all", CustomTestStateproofsQueryAll)
}

func CustomTestStateproofsReadWrite(t *customT) {
	spw := t.db.MakeSpVerificationCtxWriter()
	spr := t.db.MakeSpVerificationCtxReader()

	//
	// test
	//

	// store no items
	err := spw.StoreSPContexts(context.Background(), []*ledgercore.StateProofVerificationContext{})
	require.NoError(t, err)

	// store some items
	vcs := []*ledgercore.StateProofVerificationContext{
		{
			LastAttestedRound: basics.Round(0),
			OnlineTotalWeight: basics.MicroAlgos{Raw: 42},
		},
		{
			LastAttestedRound: basics.Round(1),
			OnlineTotalWeight: basics.MicroAlgos{Raw: 100},
		},
		{
			LastAttestedRound: basics.Round(2),
			OnlineTotalWeight: basics.MicroAlgos{Raw: 200},
		},
	}
	err = spw.StoreSPContexts(context.Background(), vcs)
	require.NoError(t, err)

	// read non-existing item
	vc, err := spr.LookupSPContext(basics.Round(9000))
	require.Error(t, err)
	require.Equal(t, trackerdb.ErrNotFound, err)

	// read back a single item
	vc, err = spr.LookupSPContext(basics.Round(0))
	require.NoError(t, err)
	require.Equal(t, basics.Round(0), vc.LastAttestedRound)            // check round is set
	require.Equal(t, basics.MicroAlgos{Raw: 42}, vc.OnlineTotalWeight) // check payload is read

	// delete some items
	err = spw.DeleteOldSPContexts(context.Background(), basics.Round(1))
	require.NoError(t, err)

	// read delete items
	vc, err = spr.LookupSPContext(basics.Round(0))
	require.Error(t, err)
	require.Equal(t, trackerdb.ErrNotFound, err)

	// read back remaining items
	vc, err = spr.LookupSPContext(basics.Round(1))
	require.NoError(t, err)
	require.Equal(t, basics.Round(1), vc.LastAttestedRound)             // check round is set
	require.Equal(t, basics.MicroAlgos{Raw: 100}, vc.OnlineTotalWeight) // check payload is read

	// read back remaining items
	vc, err = spr.LookupSPContext(basics.Round(2))
	require.NoError(t, err)
	require.Equal(t, basics.Round(2), vc.LastAttestedRound)             // check round is set
	require.Equal(t, basics.MicroAlgos{Raw: 200}, vc.OnlineTotalWeight) // check payload is read
}

func CustomTestStateproofsQueryAll(t *customT) {
	spw := t.db.MakeSpVerificationCtxWriter()
	spr := t.db.MakeSpVerificationCtxReader()

	// prepare the test with some data
	// store some items
	vcs := []*ledgercore.StateProofVerificationContext{
		{
			LastAttestedRound: basics.Round(0),
			OnlineTotalWeight: basics.MicroAlgos{Raw: 42},
		},
		{
			LastAttestedRound: basics.Round(1),
			OnlineTotalWeight: basics.MicroAlgos{Raw: 100},
		},
		{
			LastAttestedRound: basics.Round(2),
			OnlineTotalWeight: basics.MicroAlgos{Raw: 200},
		},
	}
	err := spw.StoreSPContexts(context.Background(), vcs)
	require.NoError(t, err)

	//
	// test
	//

	// read all data
	result, err := spr.GetAllSPContexts(context.Background())
	require.NoError(t, err)
	require.Len(t, result, 3)                                      // check all items are present
	require.Equal(t, basics.Round(0), result[0].LastAttestedRound) // check first item
	require.Equal(t, basics.Round(2), result[2].LastAttestedRound) // check last item
}
