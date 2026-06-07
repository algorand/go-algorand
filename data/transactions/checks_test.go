// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package transactions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestCheckTxnGroupApplicationBoxIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	malformed := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			Boxes: []BoxRef{{Index: 1}},
		},
	}
	require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedApplicationBoxIndex)

	currentApp := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			Boxes: []BoxRef{{Index: 0}},
		},
	}
	require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: currentApp}}))

	foreignApp := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			ForeignApps: []basics.AppIndex{1},
			Boxes:       []BoxRef{{Index: 1}},
		},
	}
	require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: foreignApp}}))
}

func TestCheckPaysetApplicationBoxIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	malformed := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			Boxes: []BoxRef{{Index: 1}},
		},
	}
	payset := Payset{
		{SignedTxnWithAD: SignedTxn{Txn: malformed}.WithAD()},
	}
	require.ErrorIs(t, CheckPayset(payset), errMalformedApplicationBoxIndex)
}

func TestCheckTxnGroupUnknownType(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// A lone unknown transaction type does NOT crash today: nothing triggers the group-wide
	// computeAvailability, so resources.fill is never called on it (WellFormed / applyTransaction's
	// default reject it). The screen rejects it anyway, since an unknown type is always invalid.
	bogus := Transaction{Type: protocol.TxType("bogus")}
	require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: bogus}}), errMalformedTxType)

	// The crash case: the unknown type grouped *after* an app call. The app call triggers the
	// whole-group computeAvailability, whose fill walks the unknown member before its WellFormed
	// runs (and outside the eval() recover) and hits resources.fill's default. Caught as a group
	// and as a flat payset.
	appcall := Transaction{Type: protocol.ApplicationCallTx}
	require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: appcall}, {Txn: bogus}}), errMalformedTxType)
	require.ErrorIs(t, CheckPayset(Payset{
		{SignedTxnWithAD: SignedTxn{Txn: appcall}.WithAD()},
		{SignedTxnWithAD: SignedTxn{Txn: bogus}.WithAD()},
	}), errMalformedTxType)

	// Every known type that fill handles must still be accepted (guard against over-rejection).
	// Heartbeat is excluded here because it independently requires its fields (tested elsewhere).
	for _, tt := range []protocol.TxType{
		protocol.PaymentTx, protocol.KeyRegistrationTx, protocol.AssetConfigTx,
		protocol.AssetTransferTx, protocol.AssetFreezeTx, protocol.ApplicationCallTx,
		protocol.StateProofTx,
	} {
		require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: Transaction{Type: tt}}}), "type %q must be accepted", tt)
	}
}
