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
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestFeeTracker_ProcessBlock(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	r := rand.New(rand.NewSource(99))

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ft, err := MakeFeeTracker()
	require.NoError(t, err)
	var block bookkeeping.Block
	block.Payset = make(transactions.Payset, 0)

	proto := config.Consensus[protocol.ConsensusV7]
	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				for k := 0; k < 1000; k++ {
					tx := transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Sender:     sender,
							Fee:        basics.MicroAlgos{Raw: uint64(r.Int()%10000) + proto.MinTxnFee},
							FirstValid: 0,
							LastValid:  basics.Round(proto.MaxTxnLife),
							Note:       make([]byte, 2),
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: receiver,
							Amount:   basics.MicroAlgos{Raw: 1},
						},
					}
					tx.Note[0] = byte(i)
					tx.Note[1] = byte(j)
					signedTx := tx.Sign(secrets[i])
					txib, err := block.EncodeSignedTxn(signedTx, transactions.ApplyData{})
					require.NoError(t, err)
					block.Payset = append(block.Payset, txib)
				}
			}
		}
	}
	ft.ProcessBlock(block)
	require.Equal(t, uint64(0x1f), ft.EstimateFee().Raw)
}
