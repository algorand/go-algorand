// Copyright (C) 2019-2021 Algorand, Inc.
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

package logic_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestNewEvalParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	params := []config.ConsensusParams{
		{Application: true, MaxAppProgramCost: 700},
		config.Consensus[protocol.ConsensusV29],
		config.Consensus[protocol.ConsensusFuture],
	}

	// Create some sample transactions. The main reason this a blackbox test
	// (_test package) is to have access to txntest.
	payment := txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   basics.Address{1, 2, 3, 4},
		Receiver: basics.Address{4, 3, 2, 1},
		Amount:   100,
	}.SignedTxnWithAD()

	appcall1 := txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        basics.Address{1, 2, 3, 4},
		ApplicationID: basics.AppIndex(1),
	}.SignedTxnWithAD()

	appcall2 := appcall1
	appcall2.Txn.ApplicationID = basics.AppIndex(2)

	type evalTestCase struct {
		group []transactions.SignedTxnWithAD

		// indicates if prepareAppEvaluators should return a non-nil
		// EvalParams for the txn at index i
		expected []bool

		numAppCalls int
		// Used for checking transitive pointer equality in app calls
		// If there are no app calls in the group, it is set to -1
		firstAppCallIndex int
	}

	// Create some groups with these transactions
	cases := []evalTestCase{
		{[]transactions.SignedTxnWithAD{payment}, []bool{false}, 0, -1},
		{[]transactions.SignedTxnWithAD{appcall1}, []bool{true}, 1, 0},
		{[]transactions.SignedTxnWithAD{payment, payment}, []bool{false, false}, 0, -1},
		{[]transactions.SignedTxnWithAD{appcall1, payment}, []bool{true, false}, 1, 0},
		{[]transactions.SignedTxnWithAD{payment, appcall1}, []bool{false, true}, 1, 1},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2}, []bool{true, true}, 2, 0},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2, appcall1}, []bool{true, true, true}, 3, 0},
		{[]transactions.SignedTxnWithAD{payment, appcall1, payment}, []bool{false, true, false}, 1, 1},
		{[]transactions.SignedTxnWithAD{appcall1, payment, appcall2}, []bool{true, false, true}, 2, 0},
	}

	for i, param := range params {
		for j, testCase := range cases {
			t.Run(fmt.Sprintf("i=%d,j=%d", i, j), func(t *testing.T) {
				res := logic.NewEvalParams(testCase.group, &param, nil, nil)
				require.Equal(t, len(res), len(testCase.group))

				// Compute the expected transaction group without ApplyData for
				// the test case
				expGroupNoAD := make([]transactions.SignedTxn, len(testCase.group))
				for k := range testCase.group {
					expGroupNoAD[k] = testCase.group[k].SignedTxn
				}

				// Ensure non app calls have a nil evaluator, and that non-nil
				// evaluators point to the right transactions and values
				for k, present := range testCase.expected {
					if present {
						require.NotNil(t, res[k])
						require.NotNil(t, res[k].PastSideEffects)
						require.Equal(t, res[k].GroupIndex, uint64(k))
						require.Equal(t, res[k].TxnGroup, expGroupNoAD)
						require.Equal(t, *res[k].Proto, param)
						require.Equal(t, *res[k].Txn, testCase.group[k].SignedTxn)
						require.Equal(t, res[k].MinTealVersion, res[testCase.firstAppCallIndex].MinTealVersion)
						require.Equal(t, res[k].PooledApplicationBudget, res[testCase.firstAppCallIndex].PooledApplicationBudget)
						if reflect.DeepEqual(param, config.Consensus[protocol.ConsensusV29]) {
							require.Equal(t, *res[k].PooledApplicationBudget, uint64(param.MaxAppProgramCost))
						} else if reflect.DeepEqual(param, config.Consensus[protocol.ConsensusFuture]) {
							require.Equal(t, *res[k].PooledApplicationBudget, uint64(param.MaxAppProgramCost*testCase.numAppCalls))
						}
					} else {
						require.Nil(t, res[k])
					}
				}
			})
		}
	}
}
