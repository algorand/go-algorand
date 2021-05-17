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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

//msgp:allocbound txnGroups maxEncodedTransactionGroupEntries
type txnGroups []transactions.SignedTxn

type txGroupsEncodingStubOld struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TxnGroups []txnGroups `codec:"t,allocbound=maxEncodedTransactionGroup"`
}

func encodeTransactionGroupsOld(inTxnGroups []transactions.SignedTxGroup) []byte {
	stub := txGroupsEncodingStubOld{
		TxnGroups: make([]txnGroups, len(inTxnGroups)),
	}
	for i := range inTxnGroups {
		stub.TxnGroups[i] = inTxnGroups[i].Transactions
	}

	return stub.MarshalMsg(protocol.GetEncodingBuf()[:0])
}

func encodeTransactionGroups(inTxnGroups []transactions.SignedTxGroup) ([]byte, error) {
	txnCount := 0
	for _, txGroup := range inTxnGroups {
		txnCount += len(txGroup.Transactions)
	}
	stub := txGroupsEncodingStub{
		TotalTransactionsCount: uint64(txnCount),
		TransactionGroupCount:  uint64(len(inTxnGroups)),
		TransactionGroupSizes:  make([]byte, 0, len(inTxnGroups)),
	}

	index := 0
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) > 1 {
			for _, txn := range txGroup.Transactions {
				if err := stub.deconstructSignedTransactions(index, txn); err != nil {
					return nil, fmt.Errorf("failed to encodeTransactionGroups: %v", err)
				}
				index++
			}
			stub.TransactionGroupSizes = append(stub.TransactionGroupSizes, byte(len(txGroup.Transactions)-1))
		}
	}
	stub.TransactionGroupSizes = squeezeByteArray(stub.TransactionGroupSizes)
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) == 1 {
			for _, txn := range txGroup.Transactions {
				if err := stub.deconstructSignedTransactions(index, txn); err != nil {
					return nil, fmt.Errorf("failed to encodeTransactionGroups: %v", err)
				}
				index++
			}
		}
	}
	stub.finishDeconstructSignedTransactions()

	return stub.MarshalMsg(protocol.GetEncodingBuf()[:0]), nil
}

func decodeTransactionGroupsOld(bytes []byte) (txnGroups []transactions.SignedTxGroup, err error) {
	if len(bytes) == 0 {
		return nil, nil
	}
	var stub txGroupsEncodingStubOld
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

func decodeTransactionGroups(bytes []byte, genesisID string, genesisHash crypto.Digest) (txnGroups []transactions.SignedTxGroup, err error) {
	if len(bytes) == 0 {
		return nil, nil
	}
	var stub txGroupsEncodingStub
	_, err = stub.UnmarshalMsg(bytes)
	if err != nil {
		return nil, err
	}

	stx := make([]transactions.SignedTxn, stub.TotalTransactionsCount)

	err = stub.reconstructSignedTransactions(stx, genesisID, genesisHash)
	if err != nil {
		return nil, err
	}

	txnGroups = make([]transactions.SignedTxGroup, stub.TransactionGroupCount)
	for txnCounter, txnGroupIndex := 0, 0; txnCounter < int(stub.TotalTransactionsCount); txnGroupIndex++ {
		size := 1
		if txnGroupIndex < len(stub.TransactionGroupSizes)*2 {
			nibble, err := getNibble(stub.TransactionGroupSizes, txnGroupIndex)
			if err != nil {
				return nil, err
			}
			size = int(nibble) + 1
		}
		txnGroups[txnGroupIndex].Transactions = stx[txnCounter : txnCounter+size]
		txnCounter += size
	}

	addGroupHashes(txnGroups, int(stub.TotalTransactionsCount), stub.BitmaskGroup)

	return txnGroups, nil
}

func releaseEncodedTransactionGroups(buffer []byte) {
	if buffer == nil {
		return
	}

	protocol.PutEncodingBuf(buffer[:0])
}
