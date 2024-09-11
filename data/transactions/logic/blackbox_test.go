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

func TestNewAppEvalParams(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
		group       []transactions.SignedTxnWithAD
		numAppCalls int
	}

	// Create some groups with these transactions
	cases := []evalTestCase{
		{[]transactions.SignedTxnWithAD{payment}, 0},
		{[]transactions.SignedTxnWithAD{appcall1}, 1},
		{[]transactions.SignedTxnWithAD{payment, payment}, 0},
		{[]transactions.SignedTxnWithAD{appcall1, payment}, 1},
		{[]transactions.SignedTxnWithAD{payment, appcall1}, 1},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2}, 2},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2, appcall1}, 3},
		{[]transactions.SignedTxnWithAD{payment, appcall1, payment}, 1},
		{[]transactions.SignedTxnWithAD{appcall1, payment, appcall2}, 2},
	}

	params := []config.ConsensusParams{
		{Application: true, MaxAppProgramCost: 700},
		config.Consensus[protocol.ConsensusV29],
		config.Consensus[protocol.ConsensusFuture],
	}
	for i, param := range params {
		param := param
		for j, testCase := range cases {
			i, j, param, testCase := i, j, param, testCase
			t.Run(fmt.Sprintf("i=%d,j=%d", i, j), func(t *testing.T) {
				t.Parallel()
				ep := logic.NewAppEvalParams(testCase.group, &param, nil)
				require.NotNil(t, ep)
				require.Equal(t, ep.TxnGroup, testCase.group)
				require.Equal(t, *ep.Proto, param)
				if reflect.DeepEqual(param, config.Consensus[protocol.ConsensusV29]) || testCase.numAppCalls == 0 {
					require.Nil(t, ep.PooledApplicationBudget)
				} else if reflect.DeepEqual(param, config.Consensus[protocol.ConsensusFuture]) {
					require.Equal(t, *ep.PooledApplicationBudget, param.MaxAppProgramCost*testCase.numAppCalls)
				}
			})
		}
	}
}
