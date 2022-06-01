// Copyright (C) 2019-2022 Algorand, Inc.
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

package stateproof

import (
	"errors"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// ErrNoStateProofForRound returned when a state proof transaction could not be found
var ErrNoStateProofForRound = errors.New("no state proof can be found for that round")

// GetStateProofTransactionForRound searches for a state proof transaction that can be used to prove on the given round (i.e the round is within the
// attestation period). the latestRound should be provided as an upper bound for the search
func GetStateProofTransactionForRound(txnFetcher TransactionFetcher, round basics.Round, latestRound basics.Round) (transactions.Transaction, error) {
	for i := round + 1; i < latestRound; i++ {
		txns, err := txnFetcher.AddressTxns(transactions.StateProofSender, i)
		if err != nil {
			return transactions.Transaction{}, err
		}
		for _, txn := range txns {
			if txn.Txn.Type != protocol.StateProofTx {
				continue
			}

			if txn.Txn.StateProofTxnFields.Message.FirstAttestedRound <= uint64(round) &&
				uint64(round) <= txn.Txn.StateProofTxnFields.Message.LastAttestedRound {
				return txn.Txn, nil
			}
		}
	}
	return transactions.Transaction{}, ErrNoStateProofForRound
}
