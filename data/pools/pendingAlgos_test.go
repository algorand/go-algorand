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

package pools

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestPendingDups(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	pendingSpend := make(accountsToPendingTransactions)

	secretSnd := keypair()
	sender := basics.Address(secretSnd.SignatureVerifier)

	secretRcv := keypair()
	receiver := basics.Address(secretRcv.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: 5 + proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 0),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 1},
		},
	}

	algos, err := pendingSpend.deductionsWithTransaction(tx)
	require.Equal(t, 5+proto.MinTxnFee+1, algos.amount.Raw)
	require.NoError(t, err)
	pendingSpend.accountForTransactionDeductions(tx, algos)

	_, err = pendingSpend.deductionsWithTransaction(tx)
	require.Error(t, err)

	require.NoError(t, pendingSpend.remove(tx))
}

func TestPendingOverflow(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	pendingSpend := make(accountsToPendingTransactions)

	secretSnd := keypair()
	sender := basics.Address(secretSnd.SignatureVerifier)

	secretRcv := keypair()
	receiver := basics.Address(secretRcv.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 0),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 1},
		},
	}

	manyAlgos := basics.MicroAlgos{Raw: 0xfffffffffffffffe}
	pending := pendingSpend[sender]
	pending.deductions.amount = manyAlgos
	pendingSpend[sender] = pending

	_, err := pendingSpend.deductionsWithTransaction(tx)
	require.Error(t, err)
}

func TestRemoveOverflow(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	pendingSpend := make(accountsToPendingTransactions)

	secretSnd := keypair()
	sender := basics.Address(secretSnd.SignatureVerifier)

	secretRcv := keypair()
	receiver := basics.Address(secretRcv.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: 5 + proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 0),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 1},
		},
	}

	algos, err := pendingSpend.deductionsWithTransaction(tx)
	require.Equal(t, 5+proto.MinTxnFee+1, algos.amount.Raw)
	require.NoError(t, err)
	pendingSpend.accountForTransactionDeductions(tx, algos)

	pending := pendingSpend[sender]
	pending.deductions.amount.Raw--
	pendingSpend[sender] = pending
	require.Error(t, pendingSpend.remove(tx))
}
