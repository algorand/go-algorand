// Copyright (C) 2019-2020 Algorand, Inc.
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
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func TestDecorateUnknownTransactionTypeError(t *testing.T) {
	type TestCase struct {
		err             error
		txn             node.TxnWithStatus
		expectedOutcome error
	}

	paymentTx := transactions.Transaction{Type: protocol.PaymentTx}
	keyregTx := transactions.Transaction{Type: protocol.KeyRegistrationTx}
	signedPaymentTx := transactions.SignedTxn{Txn: paymentTx}
	signedKeyregTx := transactions.SignedTxn{Txn: keyregTx}

	testCases := []TestCase{
		{
			err:             errors.New(errBlockHashBeenDeletedArchival),
			expectedOutcome: errors.New(errBlockHashBeenDeletedArchival),
		},
		{
			err:             errors.New(errUnknownTransactionType),
			txn:             node.TxnWithStatus{Txn: signedPaymentTx, ConfirmedRound: basics.Round(12345)},
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypeLedger, paymentTx.Type, paymentTx.ID().String(), basics.Round(12345)),
		},
		{
			err:             errors.New(errUnknownTransactionType),
			txn:             node.TxnWithStatus{Txn: signedKeyregTx, ConfirmedRound: basics.Round(5678)},
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypeLedger, keyregTx.Type, keyregTx.ID().String(), basics.Round(5678)),
		},
		{
			err:             errors.New(errUnknownTransactionType),
			txn:             node.TxnWithStatus{Txn: signedPaymentTx},
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypePending, paymentTx.Type, paymentTx.ID().String()),
		},
		{
			err:             errors.New(errUnknownTransactionType),
			txn:             node.TxnWithStatus{Txn: signedKeyregTx},
			expectedOutcome: fmt.Errorf(errInvalidTransactionTypePending, keyregTx.Type, keyregTx.ID().String()),
		},
	}
	for _, testCase := range testCases {
		outcome := decorateUnknownTransactionTypeError(testCase.err, testCase.txn)
		require.Equal(t, outcome.Error(), testCase.expectedOutcome.Error())
	}
}
