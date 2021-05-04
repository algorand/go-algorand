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
	"bytes"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const maxEncodedTransactionGroup = 30000
const maxEncodedTransactionGroupEntries = 30000
const maxBitmaskSize = (maxEncodedTransactionGroupEntries+7)/8 + 1
const signatureSize = 64
const maxSignatureBytes = maxEncodedTransactionGroupEntries * signatureSize
const addressSize = 32
const maxAddressBytes = maxEncodedTransactionGroupEntries * addressSize

//msgp:allocbound txnGroups maxEncodedTransactionGroupEntries
type txnGroups []transactions.SignedTxn

type txGroupsEncodingStub struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TotalTransactionsCount uint64 `codec:"ttc"`
	TransactionGroupCount  uint64 `codec:"tgc"`
	TransactionGroupSizes  []byte `codec:"tgs,allocbound=maxEncodedTransactionGroup"`

	SignedTxns []transactions.SignedTxn `codec:"st,allocbound=maxEncodedTransactionGroup"`

	encodedSignedTxns

	TxnGroups []txnGroups `codec:"t,allocbound=maxEncodedTransactionGroup"`
}

type encodedSignedTxns struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sig             []byte      `codec:"sig,allocbound=maxSignatureBytes"`
	BitmaskSig      bitmask                 `codec:"sigbm"`
	Msig            []crypto.MultisigSig    `codec:"msig,allocbound=maxEncodedTransactionGroup"`
	BitmaskMsig     bitmask                 `codec:"msigbm"`
	Lsig            []transactions.LogicSig `codec:"lsig,allocbound=maxEncodedTransactionGroup"`
	BitmaskLsig     bitmask                 `codec:"lsigbm"`
	AuthAddr        []byte        `codec:"sgnr,allocbound=maxAddressBytes"`
	BitmaskAuthAddr bitmask                 `codec:"sgnrbm"`

	encodedTxns
}

type encodedTxns struct {
	_struct       struct{} `codec:",omitempty,omitemptyarray"`
	TxType        []byte   `codec:"type,allocbound=maxEncodedTransactionGroup"`
	BitmaskTxType bitmask  `codec:"typebm"`

	encodedTxnHeaders
	encodedKeyregTxnFields
	encodedPaymentTxnFields
	encodedAssetConfigTxnFields
	encodedAssetTransferTxnFields
	encodedAssetFreezeTxnFields
	encodedApplicationCallTxnFields
	encodedCompactCertTxnFields
}

type encodedTxnHeaders struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender             []byte    `codec:"snd,allocbound=maxAddressBytes"`
	BitmaskSender      bitmask             `codec:"sndbm"`
	Fee                []basics.MicroAlgos `codec:"fee,allocbound=maxEncodedTransactionGroup"`
	BitmaskFee         bitmask             `codec:"feebm"`
	FirstValid         []basics.Round      `codec:"fv,allocbound=maxEncodedTransactionGroup"`
	BitmaskFirstValid  bitmask             `codec:"fvbm"`
	LastValid          []basics.Round      `codec:"lv,allocbound=maxEncodedTransactionGroup"`
	BitmaskLastValid   bitmask             `codec:"lvbm"`
	Note               [][]byte            `codec:"note,allocbound=maxEncodedTransactionGroup"` // TODO whats the correct allocbound?
	BitmaskNote        bitmask             `codec:"notebm"`
	GenesisID          string              `codec:"gen"`
	BitmaskGenesisID   bitmask             `codec:"genbm"`
	GenesisHash        crypto.Digest       `codec:"gh"`
	BitmaskGenesisHash bitmask             `codec:"ghbm"`

	BitmaskGroup bitmask                 `codec:"grpbm"`

	// Lease enforces mutual exclusion of transactions.  If this field is
	// nonzero, then once the transaction is confirmed, it acquires the
	// lease identified by the (Sender, Lease) pair of the transaction until
	// the LastValid round passes.  While this transaction possesses the
	// lease, no other transaction specifying this lease can be confirmed.
	Lease        []byte `codec:"lx,allocbound=maxAddressBytes"`
	BitmaskLease bitmask    `codec:"lxbm"`

	// RekeyTo, if nonzero, sets the sender's AuthAddr to the given address
	// If the RekeyTo address is the sender's actual address, the AuthAddr is set to zero
	// This allows "re-keying" a long-lived account -- rotating the signing key, changing
	// membership of a multisig account, etc.
	RekeyTo        []byte `codec:"rekey,allocbound=maxAddressBytes"`
	BitmaskRekeyTo bitmask          `codec:"rekeybm"`
}

type encodedKeyregTxnFields struct {
	_struct                 struct{}                          `codec:",omitempty,omitemptyarray"`
	VotePK                  []byte `codec:"votekey,allocbound=maxAddressBytes"`
	BitmaskVotePK           bitmask                           `codec:"votekeybm"`
	SelectionPK             []byte              `codec:"selkey,allocbound=maxAddressBytes"`
	BitmaskSelectionPK      bitmask                           `codec:"selkeybm"`
	VoteFirst               []basics.Round                    `codec:"votefst,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteFirst        bitmask                           `codec:"votefstbm"`
	VoteLast                []basics.Round                    `codec:"votelst,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteLast         bitmask                           `codec:"votelstbm"`
	VoteKeyDilution         []uint64                          `codec:"votekd,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteKeyDilution  bitmask                           `codec:"votekdbm"`
	Nonparticipation        []bool                            `codec:"nonpart,allocbound=maxEncodedTransactionGroup"`
	BitmaskNonparticipation bitmask                           `codec:"nonpartbm"`
}

type encodedPaymentTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Receiver        []byte    `codec:"rcv,allocbound=maxAddressBytes"`
	BitmaskReceiver bitmask             `codec:"rcvbm"`
	Amount          []basics.MicroAlgos `codec:"amt,allocbound=maxEncodedTransactionGroup"`
	BitmaskAmount   bitmask             `codec:"amtbm"`

	CloseRemainderTo        []byte `codec:"close,allocbound=maxAddressBytes"`
	BitmaskCloseRemainderTo bitmask          `codec:"closebm"`
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

type TxType byte

const (
	PaymentTx = iota
	KeyRegistrationTx
	AssetConfigTx
	AssetTransferTx
	AssetFreezeTx
	ApplicationCallTx
	CompactCertTx
	UnknownTx
)

// TxTypeToByte converts a TxType to byte encoding
func TxTypeToByte(t protocol.TxType) byte {
	switch t {
	case protocol.PaymentTx:
		return PaymentTx
	case protocol.KeyRegistrationTx:
		return KeyRegistrationTx
	case protocol.AssetConfigTx:
		return AssetConfigTx
	case protocol.AssetTransferTx:
		return AssetTransferTx
	case protocol.AssetFreezeTx:
		return AssetFreezeTx
	case protocol.ApplicationCallTx:
		return ApplicationCallTx
	case protocol.CompactCertTx:
		return CompactCertTx
	default:
		return UnknownTx
	}
}

// ByteToTxType converts a byte encoding to TxType
func ByteToTxType(b byte) protocol.TxType {
	txTypes := []protocol.TxType{
		protocol.PaymentTx,
		protocol.KeyRegistrationTx,
		protocol.AssetConfigTx,
		protocol.AssetTransferTx,
		protocol.AssetFreezeTx,
		protocol.ApplicationCallTx,
		protocol.CompactCertTx,
		protocol.UnknownTx,
	}
	return txTypes[b]
}

//msgp:allocbound bitmask maxBitmaskSize
type bitmask []byte

// assumed to be in mode 0, sets bit at index to 1
func (b bitmask) SetBit(index int) {
	byteIndex := index/8 + 1
	b[byteIndex] |= 1 << (index % 8)
}

func (b bitmask) EntryExists(index int, hint int) (bool, int) {
	option := 0
	if len(b) > 0 {
		option = int(b[0])
	} else {
		return false, 0
	}
	switch option {
	case 0: // if we have the bit 1 then we have an entry at the corresponding bit index.
		byteIndex := index/8 + 1
		return byteIndex < len(b) && (b[byteIndex]&(1<<(index%8)) != 0), 0
	case 1: // if we have the bit 0 then we have an entry at the corresponding bit index.
		byteIndex := index/8 + 1
		return byteIndex >= len(b) || (b[byteIndex]&(1<<(index%8)) == 0), 0
	case 2: // contains a list of bytes designating the transaction bit index
		for hint*2+2 < len(b) && index >= int(b[hint*2+1]) * 256 + int(b[hint*2+2]) {
			if index == int(b[hint*2+1]) * 256 + int(b[hint*2+2])  {
				return true, hint
			}
			hint++
		}
		return false, hint
	case 3: // contain a list of bytes designating the negative transaction bit index
		for hint*2+2 < len(b) && index >= int(b[hint*2+1]) * 256 + int(b[hint*2+2]) {
			if index == int(b[hint*2+1]) * 256 + int(b[hint*2+2]) {
				return false, hint
			}
			hint++
		}
		return true, hint
	}
	return false, 0 // need error message isntead
}

func (b *bitmask) trimBitmask(entries int) {
	lastExists := 0
	lastNotExists := 0
	numExists := 0
	for i := 0; i < entries; i++ {
		byteIndex := i/8 + 1
		if (*b)[byteIndex] & (1 << (i % 8)) != 0 {
			lastExists = i
			numExists++
		} else {
			lastNotExists = i
		}
	}
	bitmaskType := 0
	bestSize := bytesNeededBitmask(lastExists)
	if bestSize > bytesNeededBitmask(lastNotExists) {
		bitmaskType = 1
		bestSize = bytesNeededBitmask(lastNotExists)
	}
	if bestSize > numExists * 2 + 1 {
		bitmaskType = 2
		bestSize = numExists * 2 + 1
	}
	if bestSize > (entries - numExists) * 2 + 1 {
		bitmaskType = 3
		bestSize = (entries - numExists) * 2 + 1
	}
	switch bitmaskType {
	case 1:
		(*b)[0] = 1
		for i := range *b {
			if i != 0 {
				(*b)[i] = 255 -(*b)[i] // invert bits
			}
		}
	case 2:
		newBitmask := make(bitmask, 1, bestSize)
		newBitmask[0] = 2
		for i := 0; i < entries; i++ {
			byteIndex := i/8 + 1
			if (*b)[byteIndex] & (1 << (i % 8)) != 0 {
				newBitmask = append(newBitmask, byte(i / 256), byte(i % 256))
			}
		}
		*b = newBitmask
		return
	case 3:
		newBitmask := make(bitmask, 1, bestSize)
		newBitmask[0] = 3
		for i := 0; i < entries; i++ {
			byteIndex := i/8 + 1
			if (*b)[byteIndex] & (1 << (i % 8)) == 0 {
				newBitmask = append(newBitmask, byte(i / 256), byte(i % 256))
			}
		}
		*b = newBitmask
		return
	default:
	}

	*b = bytes.TrimRight(*b, string(0))
}

func bytesNeededBitmask(elements int) int {
	return (elements+7)/8 + 1
}

func getSlice(b []byte, index int, size int) []byte {
	if index * size + size > len(b) {
		return nil
	}
	return b[index*size:index*size+size]
}

func encodeTransactionGroupsOld(inTxnGroups []transactions.SignedTxGroup) []byte {
	stub := txGroupsEncodingStub{
		TxnGroups: make([]txnGroups, len(inTxnGroups)),
	}
	for i := range inTxnGroups {
		stub.TxnGroups[i] = inTxnGroups[i].Transactions
	}

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

func encodeTransactionGroups(inTxnGroups []transactions.SignedTxGroup) []byte {
	txnCount := 0
	for _, txGroup := range inTxnGroups {
		txnCount += len(txGroup.Transactions)
	}
	stub := txGroupsEncodingStub{
		TotalTransactionsCount: uint64(txnCount),
		TransactionGroupCount:  uint64(len(inTxnGroups)),
		TransactionGroupSizes:  make([]byte, 0, len(inTxnGroups)), // compress this later to use 2 per byte
		SignedTxns:             make([]transactions.SignedTxn, 0, txnCount),
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

	bitmaskLen := bytesNeededBitmask(len(stub.SignedTxns))
	stub.BitmaskGroup = make(bitmask, bitmaskLen)
	for i := range stub.SignedTxns {
		if !stub.SignedTxns[i].Txn.Group.MsgIsZero() {
			stub.BitmaskGroup.SetBit(i)
		}
		stub.SignedTxns[i].Txn.Group = crypto.Digest{}
	}

	deconstructSignedTransactions(&stub)

	//return []byte{}

	return stub.MarshalMsg(protocol.GetEncodingBuf()[:0])
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
		txnGroups[i].Transactions = stub.SignedTxns[index : index+size]
		index += size
	}

	addGroupHashes(txnGroups, stub.BitmaskGroup)

	return txnGroups, nil
}

func addGroupHashes(txnGroups []transactions.SignedTxGroup, b bitmask) {
	index := 0
	for _, txns := range txnGroups {
		var txGroup transactions.TxGroup
		txGroup.TxGroupHashes = make([]crypto.Digest, len(txns.Transactions))
		for i, tx := range txns.Transactions {
			txGroup.TxGroupHashes[i] = crypto.HashObj(tx.Txn)
		}
		groupHash := crypto.HashObj(txGroup)
		for i := range txns.Transactions {
			if exists, _ := b.EntryExists(index, 0); exists {
				txns.Transactions[i].Txn.Group = groupHash
			}
			index++
		}
	}
}

// deconstructs SignedTxn's into lists of fields and bitmasks
func deconstructSignedTransactions(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(len(stub.SignedTxns))
	stub.BitmaskAuthAddr = make(bitmask, bitmaskLen)
	stub.AuthAddr = make([]byte, 0, len(stub.SignedTxns)*addressSize)
	stub.BitmaskLsig = make(bitmask, bitmaskLen)
	stub.Lsig = make([]transactions.LogicSig, 0, len(stub.SignedTxns))
	stub.BitmaskMsig = make(bitmask, bitmaskLen)
	stub.Msig = make([]crypto.MultisigSig, 0, len(stub.SignedTxns))
	stub.BitmaskSig = make(bitmask, bitmaskLen)
	stub.Sig = make([]byte, 0, len(stub.SignedTxns)*signatureSize)
	for i, txn := range stub.SignedTxns {
		if !txn.Sig.MsgIsZero() {
			stub.BitmaskSig.SetBit(i)
			stub.Sig = append(stub.Sig, txn.Sig[:]...)
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
			stub.AuthAddr = append(stub.AuthAddr, txn.AuthAddr[:]...)
			stub.SignedTxns[i].AuthAddr = basics.Address{}
		}
	}
	stub.BitmaskAuthAddr.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskLsig.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskMsig.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskSig.trimBitmask(len(stub.SignedTxns))
	deconstructTransactions(stub)
}

func deconstructTransactions(stub *txGroupsEncodingStub) {
	deconstructTxnHeader(stub)
	deconstructKeyregTxnFields(stub)
	deconstructPaymentTxnFields(stub)
	deconstructAssetConfigTxnFields(stub)
	deconstructAssetTransferTxnFields(stub)
	deconstructAssetFreezeTxnFields(stub)
	deconstructApplicationCallTxnFields(stub)
	deconstructCompactCertTxnFields(stub)

	bitmaskLen := bytesNeededBitmask(len(stub.SignedTxns))
	stub.BitmaskTxType = make(bitmask, bitmaskLen)
	stub.TxType = make([]byte, 0, len(stub.SignedTxns))
	for i, txn := range stub.SignedTxns {
		txTypeByte := TxTypeToByte(txn.Txn.Type)
		if txTypeByte != 0 {
			stub.BitmaskTxType.SetBit(i)
			stub.TxType = append(stub.TxType, txTypeByte)
		}
		stub.SignedTxns[i].Txn.Type = ""
	}
	stub.BitmaskTxType.trimBitmask(len(stub.SignedTxns))
}

func deconstructTxnHeader(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(len(stub.SignedTxns))
	stub.BitmaskSender = make(bitmask, bitmaskLen)
	stub.Sender = make([]byte, 0, len(stub.SignedTxns)*addressSize)
	stub.BitmaskFee = make(bitmask, bitmaskLen)
	stub.Fee = make([]basics.MicroAlgos, 0, len(stub.SignedTxns))
	stub.BitmaskFirstValid = make(bitmask, bitmaskLen)
	stub.FirstValid = make([]basics.Round, 0, len(stub.SignedTxns))
	stub.BitmaskLastValid = make(bitmask, bitmaskLen)
	stub.LastValid = make([]basics.Round, 0, len(stub.SignedTxns))
	stub.BitmaskNote = make(bitmask, bitmaskLen)
	stub.Note = make([][]byte, 0, len(stub.SignedTxns))
	stub.BitmaskGenesisID = make(bitmask, bitmaskLen)
	stub.BitmaskGenesisHash = make(bitmask, bitmaskLen)
	stub.BitmaskLease = make(bitmask, bitmaskLen)
	stub.Lease = make([]byte, 0, len(stub.SignedTxns)*addressSize)
	stub.BitmaskRekeyTo = make(bitmask, bitmaskLen)
	stub.RekeyTo = make([]byte, 0, len(stub.SignedTxns)*addressSize)
	for i, txn := range stub.SignedTxns {
		if !txn.Txn.Sender.MsgIsZero() {
			stub.BitmaskSender.SetBit(i)
			stub.Sender = append(stub.Sender, txn.Txn.Sender[:]...)
			stub.SignedTxns[i].Txn.Sender = basics.Address{}
		}
		if !txn.Txn.Fee.MsgIsZero() {
			stub.BitmaskFee.SetBit(i)
			stub.Fee = append(stub.Fee, txn.Txn.Fee)
			stub.SignedTxns[i].Txn.Fee = basics.MicroAlgos{}
		}
		if !txn.Txn.FirstValid.MsgIsZero() {
			stub.BitmaskFirstValid.SetBit(i)
			stub.FirstValid = append(stub.FirstValid, txn.Txn.FirstValid)
			stub.SignedTxns[i].Txn.FirstValid = 0
		}
		if !txn.Txn.LastValid.MsgIsZero() {
			stub.BitmaskLastValid.SetBit(i)
			stub.LastValid = append(stub.LastValid, txn.Txn.LastValid)
			stub.SignedTxns[i].Txn.LastValid = 0
		}
		if txn.Txn.Note != nil && len(txn.Txn.Note) > 0 {
			stub.BitmaskNote.SetBit(i)
			stub.Note = append(stub.Note, txn.Txn.Note)
			stub.SignedTxns[i].Txn.Note = nil
		}
		if txn.Txn.GenesisID != "" {
			stub.BitmaskGenesisID.SetBit(i)
			stub.GenesisID = txn.Txn.GenesisID
			stub.SignedTxns[i].Txn.GenesisID = ""
		}
		if !txn.Txn.GenesisHash.MsgIsZero() {
			stub.BitmaskGenesisHash.SetBit(i)
			stub.GenesisHash = txn.Txn.GenesisHash
			stub.SignedTxns[i].Txn.GenesisHash = crypto.Digest{}
		}
		if txn.Txn.Lease != ([32]byte{}) {
			stub.BitmaskLease.SetBit(i)
			stub.Lease = append(stub.Lease, txn.Txn.Lease[:]...)
			stub.SignedTxns[i].Txn.Lease = [32]byte{}
		}
		if !txn.Txn.RekeyTo.MsgIsZero() {
			stub.BitmaskRekeyTo.SetBit(i)
			stub.RekeyTo = append(stub.RekeyTo, txn.Txn.RekeyTo[:]...)
			stub.SignedTxns[i].Txn.RekeyTo = basics.Address{}
		}
	}

	stub.BitmaskSender.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskFee.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskFirstValid.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskLastValid.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskNote.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskGenesisID.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskGenesisHash.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskLease.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskRekeyTo.trimBitmask(len(stub.SignedTxns))
}

func deconstructKeyregTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(len(stub.SignedTxns))
	stub.BitmaskVotePK = make(bitmask, bitmaskLen)
	stub.BitmaskSelectionPK = make(bitmask, bitmaskLen)
	stub.BitmaskVoteFirst = make(bitmask, bitmaskLen)
	stub.BitmaskVoteLast = make(bitmask, bitmaskLen)
	stub.BitmaskVoteKeyDilution = make(bitmask, bitmaskLen)
	stub.BitmaskNonparticipation = make(bitmask, bitmaskLen)
	for i, txn := range stub.SignedTxns {
		if txn.Txn.Type == protocol.KeyRegistrationTx {
			if !txn.Txn.VotePK.MsgIsZero() {
				stub.BitmaskVotePK.SetBit(i)
				stub.VotePK = append(stub.VotePK, txn.Txn.VotePK[:]...)
				stub.SignedTxns[i].Txn.VotePK = crypto.OneTimeSignatureVerifier{}
			}
			if !txn.Txn.SelectionPK.MsgIsZero() {
				stub.BitmaskSelectionPK.SetBit(i)
				stub.SelectionPK = append(stub.SelectionPK, txn.Txn.SelectionPK[:]...)
				stub.SignedTxns[i].Txn.SelectionPK = crypto.VRFVerifier{}
			}
			if !txn.Txn.VoteFirst.MsgIsZero() {
				stub.BitmaskVoteFirst.SetBit(i)
				stub.VoteFirst = append(stub.VoteFirst, txn.Txn.VoteFirst)
				stub.SignedTxns[i].Txn.VoteFirst = 0
			}
			if !txn.Txn.VoteLast.MsgIsZero() {
				stub.BitmaskVoteLast.SetBit(i)
				stub.VoteLast = append(stub.VoteLast, txn.Txn.VoteLast)
				stub.SignedTxns[i].Txn.VoteLast = 0
			}
			if txn.Txn.VoteKeyDilution > 0 {
				stub.BitmaskVoteKeyDilution.SetBit(i)
				stub.VoteKeyDilution = append(stub.VoteKeyDilution, txn.Txn.VoteKeyDilution)
				stub.SignedTxns[i].Txn.VoteKeyDilution = 0
			}
			if txn.Txn.Nonparticipation {
				stub.BitmaskNonparticipation.SetBit(i)
				stub.Nonparticipation = append(stub.Nonparticipation, txn.Txn.Nonparticipation) // can probably get rid of this
				stub.SignedTxns[i].Txn.Nonparticipation = false
			}
		}
	}

	stub.BitmaskVotePK.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskSelectionPK.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskVoteFirst.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskVoteLast.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskVoteKeyDilution.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskNonparticipation.trimBitmask(len(stub.SignedTxns))
}

func deconstructPaymentTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(len(stub.SignedTxns))
	stub.BitmaskReceiver = make(bitmask, bitmaskLen)
	stub.Receiver = make([]byte, 0, len(stub.SignedTxns)*addressSize)
	stub.BitmaskAmount = make(bitmask, bitmaskLen)
	stub.Amount = make([]basics.MicroAlgos, 0, len(stub.SignedTxns))
	stub.BitmaskCloseRemainderTo = make(bitmask, bitmaskLen)
	stub.CloseRemainderTo = make([]byte, 0, len(stub.SignedTxns)*addressSize)
	for i, txn := range stub.SignedTxns {
		if txn.Txn.Type == protocol.PaymentTx {
			if !txn.Txn.Receiver.MsgIsZero() {
				stub.BitmaskReceiver.SetBit(i)
				stub.Receiver = append(stub.Receiver, txn.Txn.Receiver[:]...)
				stub.SignedTxns[i].Txn.Receiver = basics.Address{}
			}
			if !txn.Txn.Amount.MsgIsZero() {
				stub.BitmaskAmount.SetBit(i)
				stub.Amount = append(stub.Amount, txn.Txn.Amount)
				stub.SignedTxns[i].Txn.Amount = basics.MicroAlgos{}
			}
			if !txn.Txn.CloseRemainderTo.MsgIsZero() {
				stub.BitmaskCloseRemainderTo.SetBit(i)
				stub.CloseRemainderTo = append(stub.CloseRemainderTo, txn.Txn.CloseRemainderTo[:]...)
				stub.SignedTxns[i].Txn.CloseRemainderTo = basics.Address{}
			}
		}
	}

	stub.BitmaskReceiver.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskAmount.trimBitmask(len(stub.SignedTxns))
	stub.BitmaskCloseRemainderTo.trimBitmask(len(stub.SignedTxns))
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
			copy(stub.SignedTxns[i].Sig[:], getSlice(stub.Sig, index, signatureSize))
			index++
		}
	}

	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskMsig.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Msig = stub.Msig[index]
			index++
		}
	}

	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskLsig.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Lsig = stub.Lsig[index]
			index++
		}
	}

	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskAuthAddr.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].AuthAddr[:], getSlice(stub.AuthAddr, index, addressSize))
			index++
		}
	}

	reconstructTransactions(stub)
}

func reconstructTransactions(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskTxType.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.Type = ByteToTxType(stub.TxType[index])
			index++
		} else {
			stub.SignedTxns[i].Txn.Type = protocol.PaymentTx
		}
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
	var index int
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskSender.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].Txn.Sender[:], getSlice(stub.Sender, index, addressSize))
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskFee.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.Fee = stub.Fee[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskFirstValid.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.FirstValid = stub.FirstValid[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskLastValid.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.LastValid = stub.LastValid[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskNote.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.Note = stub.Note[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskGenesisID.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.GenesisID = stub.GenesisID
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskGenesisHash.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.GenesisHash = stub.GenesisHash
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskLease.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].Txn.Lease[:], getSlice(stub.Lease, index, addressSize))
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskRekeyTo.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].Txn.RekeyTo[:], getSlice(stub.RekeyTo, index, addressSize))
			index++
		}
	}
}

func reconstructKeyregTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskVotePK.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].Txn.VotePK[:], getSlice(stub.VotePK, index, addressSize))
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskSelectionPK.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].Txn.SelectionPK[:], getSlice(stub.SelectionPK, index, addressSize))
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskVoteFirst.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskVoteLast.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.VoteLast = stub.VoteLast[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskVoteLast.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.VoteLast = stub.VoteLast[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskNonparticipation.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.Nonparticipation = stub.Nonparticipation[index]
			index++
		}
	}
}

func reconstructPaymentTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskReceiver.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].Txn.Receiver[:], getSlice(stub.Receiver, index, addressSize))
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskAmount.EntryExists(i, 0); exists {
			stub.SignedTxns[i].Txn.Amount = stub.Amount[index]
			index++
		}
	}
	index = 0
	for i := range stub.SignedTxns {
		if exists, _ := stub.BitmaskCloseRemainderTo.EntryExists(i, 0); exists {
			copy(stub.SignedTxns[i].Txn.CloseRemainderTo[:], getSlice(stub.CloseRemainderTo, index, addressSize))
			index++
		}
	}
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

func releaseEncodedTransactionGroups(buffer []byte) {
	if buffer == nil {
		return
	}

	protocol.PutEncodingBuf(buffer[:0])
}
