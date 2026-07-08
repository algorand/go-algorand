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

package simulation

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPopulateFeeUsageIncludesBigLogicSigProgram(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	extraProgramBytes := 10
	fee := basics.MicroAlgos{Raw: proto.MinTxnFee}

	result := Result{
		TxnGroups: []TxnGroupResult{
			{
				Txns: []TxnResult{
					{
						Txn: transactions.SignedTxnWithAD{
							SignedTxn: transactions.SignedTxn{
								Txn: transactions.Transaction{
									Type: protocol.PaymentTx,
									Header: transactions.Header{
										Fee: fee,
									},
								},
								Lsig: transactions.LogicSig{
									Logic: make([]byte, int(proto.LogicSigMaxSize)+extraProgramBytes),
								},
							},
						},
					},
				},
			},
		},
	}

	populateFeeUsage(&result, proto)

	surcharge, overflow := proto.PerByteTxnSurcharge.MulInt(extraProgramBytes)
	require.False(t, overflow)
	require.Equal(t, basics.AddSaturate(basics.Micros(1e6), surcharge), result.TxnGroups[0].GroupUsage)
	require.Equal(t, fee, result.TxnGroups[0].GroupFeesPaid)
	require.Equal(t, fee, result.TxnGroups[0].Txns[0].FeesPaid)
}
