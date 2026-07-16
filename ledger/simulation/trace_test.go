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
	fee := basics.MicroAlgos{Raw: proto.MinTxnFee}

	makeTxnResult := func(programSize int) TxnResult {
		return TxnResult{
			Txn: transactions.SignedTxnWithAD{
				SignedTxn: transactions.SignedTxn{
					Txn: transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Fee: fee,
						},
					},
					Lsig: transactions.LogicSig{
						Logic: make([]byte, programSize),
					},
				},
			},
		}
	}

	surcharge, overflow := proto.PerByteTxnSurcharge.MulInt(10)
	require.False(t, overflow)

	tests := []struct {
		name          string
		txns          []TxnResult
		expectedUsage basics.Micros
	}{
		{
			name: "singleton big LogicSig program increases group usage",
			txns: []TxnResult{
				makeTxnResult(int(proto.LogicSigMaxSize) + 10),
			},
			expectedUsage: basics.AddSaturate(basics.Micros(1e6), surcharge),
		},
		{
			name: "group pool covers big LogicSig program",
			txns: []TxnResult{
				makeTxnResult(int(proto.LogicSigMaxSize) + 500),
				makeTxnResult(0),
			},
			expectedUsage: basics.Micros(2e6),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Result{
				TxnGroups: []TxnGroupResult{
					{
						Txns: test.txns,
					},
				},
			}

			populateFeeUsage(&result, proto)

			expectedFeesPaid := basics.MicroAlgos{Raw: uint64(len(test.txns)) * fee.Raw}
			require.Equal(t, test.expectedUsage, result.TxnGroups[0].GroupUsage)
			require.Equal(t, expectedFeesPaid, result.TxnGroups[0].GroupFeesPaid)
			for i := range test.txns {
				require.Equal(t, fee, result.TxnGroups[0].Txns[i].FeesPaid)
			}
		})
	}
}

func TestPopulateFeeUsageIncludesBigLogicSigArgs(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	argsSize := int(proto.LogicSigMaxSize) + 10
	fee := basics.MicroAlgos{Raw: proto.MinTxnFee}
	result := Result{
		TxnGroups: []TxnGroupResult{
			{
				Txns: []TxnResult{
					{
						Txn: transactions.SignedTxnWithAD{
							SignedTxn: transactions.SignedTxn{
								Txn: transactions.Transaction{
									Header: transactions.Header{
										Fee:                      fee,
										MaxLogicSigArgsTotalSize: uint64(argsSize + 100),
									},
								},
								Lsig: transactions.LogicSig{
									Args: [][]byte{make([]byte, argsSize)},
								},
							},
						},
					},
				},
			},
		},
	}

	populateFeeUsage(&result, proto)

	surcharge, overflow := proto.PerByteTxnSurcharge.MulInt(10)
	require.False(t, overflow)
	require.Equal(t, basics.AddSaturate(basics.Micros(1e6), surcharge), result.TxnGroups[0].GroupUsage)
	require.Equal(t, fee, result.TxnGroups[0].GroupFeesPaid)
	require.Equal(t, fee, result.TxnGroups[0].Txns[0].FeesPaid)
}
