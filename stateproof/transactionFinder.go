package stateproof

import (
	"errors"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var ErrNoStateProofForRound = errors.New("no state proof for that round")

func GetStateproofTransactionForRound(txnFetcher TransactionFetcher, round basics.Round, latestRound basics.Round) (transactions.Transaction, error) {
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
