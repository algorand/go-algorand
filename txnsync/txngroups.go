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

package txnsync

import (
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func encodeTransactionGroupsOld(inTxnGroups []transactions.SignedTxGroup) []byte {
	stub := txGroupsEncodingStub{
		TxnGroups: make([]txnGroups, len(inTxnGroups)),
	}
	for i := range inTxnGroups {
		stub.TxnGroups[i] = inTxnGroups[i].Transactions
	}

	return stub.MarshalMsg(protocol.GetEncodingBuf()[:0])
}

func encodeTransactionGroups(inTxnGroups []transactions.SignedTxGroup) []byte {
	txnCount := 0
	for _, txGroup := range inTxnGroups {
		txnCount += len(txGroup.Transactions)
	}
	stub := txGroupsEncodingStub{
		TotalTransactionsCount: uint64(txnCount),
		TransactionGroupCount:  uint64(len(inTxnGroups)),
		TransactionGroupSizes:  make([]byte, 0, len(inTxnGroups)), // TODO compress this later to use 2 per byte
	}

	index := 0
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) > 1 {
			for _, txn := range txGroup.Transactions {
				deconstructSignedTransactions(&stub, index, txn)
				index++
			}
			stub.TransactionGroupSizes = append(stub.TransactionGroupSizes, byte(len(txGroup.Transactions)-1))
		}
	}
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) == 1 {
			for _, txn := range txGroup.Transactions {
				deconstructSignedTransactions(&stub, index, txn)
				index++
			}
		}
	}
	finishDeconstructSignedTransactions(&stub)

	return stub.MarshalMsg(protocol.GetEncodingBuf()[:0])
}

func decodeTransactionGroupsOld(bytes []byte) (txnGroups []transactions.SignedTxGroup, err error) {
	if len(bytes) == 0 {
		return nil, nil
	}
	var stub txGroupsEncodingStub
	_, err = stub.UnmarshalMsg(bytes)
	if err != nil {
		return nil, err
	}
	txnGroups = make([]transactions.SignedTxGroup, len(stub.TxnGroups))
	for i := range stub.TxnGroups {
		txnGroups[i].Transactions = stub.TxnGroups[i]
	}
	return txnGroups, nil
}

func decodeTransactionGroups(bytes []byte) (txnGroups []transactions.SignedTxGroup, err error) {
	if len(bytes) == 0 {
		return nil, nil
	}
	var stub txGroupsEncodingStub
	_, err = stub.UnmarshalMsg(bytes)
	if err != nil {
		return nil, err
	}

	stub.SignedTxns = make([]transactions.SignedTxn, stub.TotalTransactionsCount)

	err = reconstructSignedTransactions(&stub)
	if err != nil {
		return nil, err
	}

	txnGroups = make([]transactions.SignedTxGroup, stub.TransactionGroupCount)
	for txnCounter, txnGroupIndex := 0, 0; txnCounter < int(stub.TotalTransactionsCount); txnGroupIndex++ {
		size := 1
		if txnGroupIndex < len(stub.TransactionGroupSizes) {
			size = int(stub.TransactionGroupSizes[txnGroupIndex]) + 1
		}
		txnGroups[txnGroupIndex].Transactions = stub.SignedTxns[txnCounter : txnCounter+size]
		txnCounter += size
	}

	addGroupHashes(txnGroups, int(stub.TotalTransactionsCount), stub.BitmaskGroup)

	return txnGroups, nil
}
