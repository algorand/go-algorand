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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const maxEncodedTransactionGroup = 10000
const maxEncodedTransactionGroupEntries = 10000

//msgp:allocbound txnGroups maxEncodedTransactionGroupEntries
type txnGroups []transactions.SignedTxn

type txGroupsEncodingStub struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TotalTransactionsCount uint64 // how many transactions in total do we have?
	TransactionGroupCount uint64 // how many txgroups in total do we have?
	TransactionGroupSizes []byte `codec:"tgs,allocbound=maxEncodedTransactionGroup"`

	SignedTxns []transactions.SignedTxn `codec:"st,allocbound=maxEncodedTransactionGroup"`

	encodedSignedTxns
}

type encodedSignedTxns struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sig      []crypto.Signature   `codec:"sig,allocbound=maxEncodedTransactionGroup"`
	BitmaskSig bitmask `codec:"sigbm,allocbound=maxEncodedTransactionGroup"`
	Msig     []crypto.MultisigSig `codec:"msig,allocbound=maxEncodedTransactionGroup"`
	BitmaskMsig bitmask `codec:"msigbm,allocbound=maxEncodedTransactionGroup"`
	Lsig     []transactions.LogicSig           `codec:"lsig,allocbound=maxEncodedTransactionGroup"`
	BitmaskLsig bitmask     `codec:"lsigb,allocbound=maxEncodedTransactionGroupm"`
	AuthAddr []basics.Address     `codec:"sgnr,allocbound=maxEncodedTransactionGroup"`
	BitmaskAuthAddr bitmask   `codec:"sgnrbm,allocbound=maxEncodedTransactionGroup"`

	encodedTxns
}

type encodedTxns struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	TxType []protocol.TxType `codec:"type,allocbound=maxEncodedTransactionGroup"`
}

type encodedTxnHeaders struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type encodedKeyregTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type encodedPaymentTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type encodedAssetConfigTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type encodedAssetTransferTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type encodedAssetFreezeTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type encodedApplicationCallTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type encodedCompactCertTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`


}

type bitmask []byte

// assumed to be in mode 0, sets bit at index to 1
func (b bitmask) SetBit(index int) {
	byteIndex := index / 8 + 1
	b[byteIndex] |= 1<<(index%8)
}

func (b bitmask) EntryExists(index int, hint int) (bool, int) {
	switch b[0] {
	case 0: // if we have the bit 1 then we have an entry at the corresponding bit index.
		byteIndex := index / 8 + 1
		return byteIndex < len(b) && (b[byteIndex] & (1<<(index%8)) != 0), 0
	case 1: // if we have the bit 0 then we have an entry at the corresponding bit index.
		byteIndex := index / 8 + 1
		return byteIndex >= len(b) || (b[byteIndex] & (1<<(index%8)) == 0), 0
	case 2: // contains a list of bytes designating the transaction bit index
		for hint < len(b) && index <= int(b[index]) {
			if index == int(b[index]) {
				return true, hint
			}
			hint ++
		}
		return false, hint
	case 3: // contain a list of bytes designating the negative transaction bit index
		for hint < len(b) && index <= int(b[index]) {
			if index == int(b[index]) {
				return false, hint
			}
			hint ++
		}
		return true, hint
	}
	return false, 0 // need error message isntead
}

func encodeTransactionGroups(inTxnGroups []transactions.SignedTxGroup) []byte {
	txnCount := 0
	for _, txGroup := range inTxnGroups {
		txnCount += len(txGroup.Transactions)
	}
	stub := txGroupsEncodingStub{
		TotalTransactionsCount: uint64(txnCount),
		TransactionGroupCount: uint64(len(inTxnGroups)),
		TransactionGroupSizes: make([]byte, 0, len(inTxnGroups)), // compress this later to use 2 per byte
		SignedTxns: make([]transactions.SignedTxn, 0, txnCount),
	}
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) > 1 {
			for _, txn := range txGroup.Transactions {
				stub.SignedTxns = append(stub.SignedTxns, txn)
			}
			stub.TransactionGroupSizes = append(stub.TransactionGroupSizes, byte(len(txGroup.Transactions)-1))
		}
	}
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) == 1 {
			for _, txn := range txGroup.Transactions {
				stub.SignedTxns = append(stub.SignedTxns, txn)
			}
		}
	}
	for i := range stub.SignedTxns {
		stub.SignedTxns[i].Txn.Group = crypto.Digest{}
	}

	deconstructSignedTransactions(&stub)

	//newStub := txGroupsEncodingStub{
	//	SignedTxns: stub.SignedTxns,
	//}
	//
	//return newStub.MarshalMsg([]byte{})
	return stub.MarshalMsg([]byte{})
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

	reconstructSignedTransactions(&stub)

	txnGroups = make([]transactions.SignedTxGroup, stub.TransactionGroupCount)
	for index, i := 0, 0; index < int(stub.TotalTransactionsCount); i++ {
		size := 1
		if i < len(stub.TransactionGroupSizes) {
			size = int(stub.TransactionGroupSizes[i]) + 1
		}
		txnGroups[i].Transactions = stub.SignedTxns[index:index+size]
		index += size
	}

	for _, txns := range txnGroups {
		var txGroup transactions.TxGroup
		txGroup.TxGroupHashes = make([]crypto.Digest, len(txns.Transactions))
		for i, tx := range txns.Transactions {
			txGroup.TxGroupHashes[i] = crypto.HashObj(tx.Txn)
		}
	}
	return txnGroups, nil
}

// deconstructs SignedTxn's into lists of fields and bitmasks
func deconstructSignedTransactions(stub *txGroupsEncodingStub) {
	stub.BitmaskAuthAddr = make(bitmask, (len(stub.SignedTxns) + 7)/8+1)
	stub.BitmaskLsig = make(bitmask, (len(stub.SignedTxns) + 7)/8+1)
	stub.BitmaskMsig = make(bitmask, (len(stub.SignedTxns) + 7)/8+1)
	stub.BitmaskSig = make(bitmask, (len(stub.SignedTxns) + 7)/8+1)
	for i, txn := range stub.SignedTxns {
		if !txn.Sig.MsgIsZero() {
			stub.BitmaskSig.SetBit(i)
			stub.Sig = append(stub.Sig, txn.Sig)
			stub.SignedTxns[i].Sig = crypto.Signature{}
		}
		if !txn.Msig.MsgIsZero() {
			stub.BitmaskMsig.SetBit(i)
			stub.Msig = append(stub.Msig, txn.Msig)
			stub.SignedTxns[i].Msig = crypto.MultisigSig{}
		}
		if !txn.Lsig.MsgIsZero() {
			stub.BitmaskLsig.SetBit(i)
			stub.Lsig = append(stub.Lsig, txn.Lsig)
			stub.SignedTxns[i].Lsig = transactions.LogicSig{}
		}
		if !txn.AuthAddr.MsgIsZero() {
			stub.BitmaskAuthAddr.SetBit(i)
			stub.AuthAddr = append(stub.AuthAddr, txn.AuthAddr)
			stub.SignedTxns[i].AuthAddr = basics.Address{}
		}
	}
	deconstructTransactions(stub)
}

func deconstructTransactions(stub *txGroupsEncodingStub) {
	for i, txn := range stub.SignedTxns {
		stub.TxType = append(stub.TxType, txn.Txn.Type)
		stub.SignedTxns[i].Txn.Type = ""
	}
	deconstructTxnHeader(stub)
	deconstructKeyregTxnFields(stub)
	deconstructPaymentTxnFields(stub)
	deconstructAssetConfigTxnFields(stub)
	deconstructAssetTransferTxnFields(stub)
	deconstructAssetFreezeTxnFields(stub)
	deconstructApplicationCallTxnFields(stub)
	deconstructCompactCertTxnFields(stub)
}

func deconstructTxnHeader(stub *txGroupsEncodingStub) {

}

func deconstructKeyregTxnFields(stub *txGroupsEncodingStub) {

}

func deconstructPaymentTxnFields(stub *txGroupsEncodingStub) {

}

func deconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) {

}

func deconstructAssetTransferTxnFields(stub *txGroupsEncodingStub) {

}

func deconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) {

}

func deconstructApplicationCallTxnFields(stub *txGroupsEncodingStub) {

}

func deconstructCompactCertTxnFields(stub *txGroupsEncodingStub) {

}

func reconstructSignedTransactions(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskSig.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Sig = stub.Sig[index]
			index ++
		}
	}

	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskMsig.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Msig = stub.Msig[index]
			index ++
		}
	}

	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskLsig.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Lsig = stub.Lsig[index]
			index ++
		}
	}

	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskAuthAddr.EntryExists(i, 0); exists {
			stub.SignedTxns[i].AuthAddr = stub.AuthAddr[index]
			index ++
		}
	}

	reconstructTransactions(stub)
}

func reconstructTransactions(stub *txGroupsEncodingStub) {
	for i := range stub.SignedTxns {
		stub.SignedTxns[i].Txn.Type = stub.TxType[i]
	}

	reconstructTxnHeader(stub)
	reconstructKeyregTxnFields(stub)
	reconstructPaymentTxnFields(stub)
	reconstructAssetConfigTxnFields(stub)
	reconstructAssetTransferTxnFields(stub)
	reconstructAssetFreezeTxnFields(stub)
	reconstructApplicationCallTxnFields(stub)
	reconstructCompactCertTxnFields(stub)
}

func reconstructTxnHeader(stub *txGroupsEncodingStub) {

}

func reconstructKeyregTxnFields(stub *txGroupsEncodingStub) {

}

func reconstructPaymentTxnFields(stub *txGroupsEncodingStub) {

}

func reconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) {

}

func reconstructAssetTransferTxnFields(stub *txGroupsEncodingStub) {

}

func reconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) {

}

func reconstructApplicationCallTxnFields(stub *txGroupsEncodingStub) {

}

func reconstructCompactCertTxnFields(stub *txGroupsEncodingStub) {

}