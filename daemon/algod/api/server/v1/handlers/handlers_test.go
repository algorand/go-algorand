// Copyright (C) 2019 Algorand, Inc.
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

package handlers

import (
	"errors"
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func TestMakeDetailedUnknownTransactionType(t *testing.T) {
	type TestCase struct {
		err             error
		tx              transactions.Transaction
		round           basics.Round
		expectedOutcome error
	}

	paymentTx := transactions.Transaction{Type: protocol.PaymentTx}
	keyregTx := transactions.Transaction{Type: protocol.KeyRegistrationTx}
	testCases := []TestCase{
		TestCase{
			err:             errors.New(errBlockHashBeenDeletedArchival),
			expectedOutcome: errors.New(errBlockHashBeenDeletedArchival),
		},
		TestCase{
			err:             errors.New(errUnknownTransactionType),
			round:           basics.Round(12345),
			tx:              paymentTx,
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypeLedger, paymentTx.Type, paymentTx.ID().String(), basics.Round(12345)),
		},
		TestCase{
			err:             errors.New(errUnknownTransactionType),
			round:           basics.Round(5678),
			tx:              keyregTx,
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypeLedger, keyregTx.Type, keyregTx.ID().String(), basics.Round(5678)),
		},
		TestCase{
			err:             errors.New(errUnknownTransactionType),
			tx:              paymentTx,
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypePending, paymentTx.Type, paymentTx.ID().String()),
		},
		TestCase{
			err:             errors.New(errUnknownTransactionType),
			tx:              keyregTx,
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypePending, keyregTx.Type, keyregTx.ID().String()),
		},
	}
	for _, testCase := range testCases {
		outcome := makeDetailedUnknownTransactionType(testCase.err, testCase.tx, testCase.round)
		require.Equal(t, outcome.Error(), testCase.expectedOutcome.Error())
	}
}
