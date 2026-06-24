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

package v2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestCheckPQSimulatePolicySchemeOnlyPlaceholder(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, proto.EnablePQSchemeFalcon1024)

	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
		},
		PQSig: transactions.PQSig{Scheme: protocol.PQSchemeFalcon1024},
	}

	require.NoError(t, checkPQSimulatePolicy(proto, stxn, true, false))
	require.NoError(t, checkPQSimulatePolicy(proto, stxn, true, true))

	unknownScheme := stxn
	unknownScheme.PQSig.Scheme = protocol.PQScheme("x1")
	require.ErrorIs(t, checkPQSimulatePolicy(proto, unknownScheme, true, false), basics.ErrPQSchemeNotSupported)

	disabledProto := proto
	disabledProto.EnablePQSchemeFalcon1024 = false
	require.ErrorIs(t, checkPQSimulatePolicy(disabledProto, stxn, true, false), basics.ErrPQSchemeNotEnabled)
}

func TestCheckPQSimulatePolicyRejectsMismatchedFullPlaceholder(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusFuture]
	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
		},
		PQSig: transactions.PQSig{
			Scheme:    protocol.PQSchemeFalcon1024,
			PublicKey: []byte{1},
		},
	}

	err := checkPQSimulatePolicy(proto, stxn, true, false)
	require.ErrorContains(t, err, "pq signature authorizer mismatch")
}
