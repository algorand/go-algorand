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

package eval

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestCheckGroupFeesDelegatedPQLogicSigSurcharge(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Fee: proto.MinFee(),
			},
		},
		Lsig: transactions.LogicSig{
			Logic: []byte{1},
			PQsig: transactions.PQSig{
				Scheme: protocol.PQSchemeFalcon1024,
			},
		},
	}

	group := transactions.WrapSignedTxnsWithAD([]transactions.SignedTxn{stxn})
	usage, paid := transactions.SummarizeFees(group, proto)
	require.Equal(t, basics.Micros(3e6), usage)
	require.ErrorContains(t, CheckGroupFees(paid, usage, proto.MinFee()), "txgroup with")

	requiredFee, _, overflow := proto.MinFee().FeeForUsage(usage, 1e6, 0)
	require.False(t, overflow)
	stxn.Txn.Fee = requiredFee

	group = transactions.WrapSignedTxnsWithAD([]transactions.SignedTxn{stxn})
	usage, paid = transactions.SummarizeFees(group, proto)
	require.NoError(t, CheckGroupFees(paid, usage, proto.MinFee()))
}
