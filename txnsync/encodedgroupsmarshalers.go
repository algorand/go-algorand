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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func compactNibblesArray(b []byte) []byte {
	if len(b)%2 == 1 {
		b = append(b, byte(0))
	}
	for index := 0; index*2 < len(b); index++ {
		b[index] = b[index*2]*16 + b[index*2+1]
	}
	return b[0 : len(b)/2]
}

func addGroupHashes(txnGroups []transactions.SignedTxGroup, txnCount int, b bitmask) {
	index := 0
	txGroupHashes := make([]crypto.Digest, 16)
	for _, txns := range txnGroups {
		var txGroup transactions.TxGroup
		txGroup.TxGroupHashes = txGroupHashes[:len(txns.Transactions)]
		for i, tx := range txns.Transactions {
			txGroup.TxGroupHashes[i] = crypto.HashObj(tx.Txn)
		}
		groupHash := crypto.HashObj(txGroup)
		for i := range txns.Transactions {
			if exists := b.EntryExists(index, txnCount); exists || len(txns.Transactions) > 1 {
				txns.Transactions[i].Txn.Group = groupHash
			}
			index++
		}
	}
}

// deconstructs SignedTxn's into lists of fields and bitmasks
func (stub *txGroupsEncodingStub) deconstructSignedTransactions(i int, txn transactions.SignedTxn) error {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Sig.MsgIsZero() {
		if len(stub.BitmaskSig) == 0 {
			stub.BitmaskSig = make(bitmask, bitmaskLen)
			stub.Sig = make([]byte, 0, int(stub.TotalTransactionsCount)*len(crypto.Signature{}))
		}
		stub.BitmaskSig.SetBit(i)
		stub.Sig = append(stub.Sig, txn.Sig[:]...)
	}
	stub.deconstructMsigs(i, txn)
	stub.deconstructLsigs(i, txn)
	if !txn.AuthAddr.MsgIsZero() {
		if len(stub.BitmaskAuthAddr) == 0 {
			stub.BitmaskAuthAddr = make(bitmask, bitmaskLen)
			stub.AuthAddr = make([]byte, 0, int(stub.TotalTransactionsCount)*crypto.DigestSize)
		}
		stub.BitmaskAuthAddr.SetBit(i)
		stub.AuthAddr = append(stub.AuthAddr, txn.AuthAddr[:]...)
	}
	return stub.deconstructTransactions(i, txn)
}

func (stub *txGroupsEncodingStub) finishDeconstructSignedTransactions() {
	stub.BitmaskAuthAddr.trimBitmask(int(stub.TotalTransactionsCount))
	stub.finishDeconstructMsigs()
	stub.finishDeconstructLsigs()
	stub.BitmaskSig.trimBitmask(int(stub.TotalTransactionsCount))
	stub.finishDeconstructTransactions()
}

func (stub *txGroupsEncodingStub) deconstructMsigs(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if txn.Msig.Version != 0 {
		if len(stub.BitmaskVersion) == 0 {
			stub.BitmaskVersion = make(bitmask, bitmaskLen)
			stub.Version = make([]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskVersion.SetBit(i)
		stub.Version = append(stub.Version, txn.Msig.Version)
	}
	if txn.Msig.Threshold != 0 {
		if len(stub.BitmaskThreshold) == 0 {
			stub.BitmaskThreshold = make(bitmask, bitmaskLen)
			stub.Threshold = make([]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskThreshold.SetBit(i)
		stub.Threshold = append(stub.Threshold, txn.Msig.Threshold)
	}
	if txn.Msig.Subsigs != nil {
		if len(stub.BitmaskSubsigs) == 0 {
			stub.BitmaskSubsigs = make(bitmask, bitmaskLen)
			stub.Subsigs = make([][]crypto.MultisigSubsig, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskSubsigs.SetBit(i)
		stub.Subsigs = append(stub.Subsigs, txn.Msig.Subsigs)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructMsigs() {
	stub.BitmaskVersion.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskThreshold.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSubsigs.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructLsigs(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if txn.Lsig.Logic != nil {
		if len(stub.BitmaskLogic) == 0 {
			stub.BitmaskLogic = make(bitmask, bitmaskLen)
			stub.Logic = make([][]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskLogic.SetBit(i)
		stub.Logic = append(stub.Logic, txn.Lsig.Logic)
	}
	if txn.Lsig.Args != nil {
		if len(stub.BitmaskLogicArgs) == 0 {
			stub.BitmaskLogicArgs = make(bitmask, bitmaskLen)
			stub.LogicArgs = make([][][]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskLogicArgs.SetBit(i)
		stub.LogicArgs = append(stub.LogicArgs, txn.Lsig.Args)
	}
	if !txn.Lsig.Sig.MsgIsZero() {
		if len(stub.BitmaskSig) == 0 {
			stub.BitmaskSig = make(bitmask, bitmaskLen)
			stub.Sig = make([]byte, 0, int(stub.TotalTransactionsCount)*len(crypto.Signature{}))
		}
		stub.BitmaskSig.SetBit(i)
		stub.Sig = append(stub.Sig, txn.Lsig.Sig[:]...)
	}
	if txn.Lsig.Msig.Version != 0 {
		if len(stub.BitmaskVersion) == 0 {
			stub.BitmaskVersion = make(bitmask, bitmaskLen)
			stub.Version = make([]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskVersion.SetBit(i)
		stub.Version = append(stub.Version, txn.Lsig.Msig.Version)
	}
	if txn.Lsig.Msig.Threshold != 0 {
		if len(stub.BitmaskThreshold) == 0 {
			stub.BitmaskThreshold = make(bitmask, bitmaskLen)
			stub.Threshold = make([]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskThreshold.SetBit(i)
		stub.Threshold = append(stub.Threshold, txn.Lsig.Msig.Threshold)
	}
	if txn.Lsig.Msig.Subsigs != nil {
		if len(stub.BitmaskSubsigs) == 0 {
			stub.BitmaskSubsigs = make(bitmask, bitmaskLen)
			stub.Subsigs = make([][]crypto.MultisigSubsig, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskSubsigs.SetBit(i)
		stub.Subsigs = append(stub.Subsigs, txn.Lsig.Msig.Subsigs)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructLsigs() {
	stub.BitmaskLogic.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLogicArgs.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructTransactions(i int, txn transactions.SignedTxn) error {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	txTypeByte, err := TxTypeToByte(txn.Txn.Type)
	if err != nil {
		return fmt.Errorf("failed to deconstructTransactions: %w", err)
	}
	if len(stub.BitmaskTxType) == 0 {
		stub.BitmaskTxType = make(bitmask, bitmaskLen)
		stub.TxType = make([]byte, 0, int(stub.TotalTransactionsCount))
	}
	stub.TxType = append(stub.TxType, txTypeByte)
	stub.deconstructTxnHeader(i, txn)
	switch txTypeByte {
	case paymentTx:
		stub.deconstructPaymentTxnFields(i, txn)
	case keyRegistrationTx:
		stub.deconstructKeyregTxnFields(i, txn)
	case assetConfigTx:
		stub.deconstructAssetConfigTxnFields(i, txn)
	case assetTransferTx:
		stub.deconstructAssetTransferTxnFields(i, txn)
	case assetFreezeTx:
		stub.deconstructAssetFreezeTxnFields(i, txn)
	case applicationCallTx:
		stub.deconstructApplicationCallTxnFields(i, txn)
	case compactCertTx:
		stub.deconstructCompactCertTxnFields(i, txn)
	}
	return nil
}

func (stub *txGroupsEncodingStub) finishDeconstructTransactions() {
	stub.finishDeconstructTxType()
	stub.finishDeconstructTxnHeader()
	stub.finishDeconstructKeyregTxnFields()
	stub.finishDeconstructPaymentTxnFields()
	stub.finishDeconstructAssetConfigTxnFields()
	stub.finishDeconstructAssetTransferTxnFields()
	stub.finishDeconstructAssetFreezeTxnFields()
	stub.finishDeconstructApplicationCallTxnFields()
	stub.finishDeconstructCompactCertTxnFields()
}

func (stub *txGroupsEncodingStub) finishDeconstructTxType() {
	offset := byte(0)
	count := make(map[int]int)
	maxcount := 0
	for _, t := range stub.TxType {
		count[int(t)]++
	}
	for i := range protocol.TxnTypes {
		if c, ok := count[i]; ok && c > maxcount {
			offset = byte(i)
			maxcount = c
		}
	}
	newTxTypes := make([]byte, 0, stub.TotalTransactionsCount)
	for i := 0; i < int(stub.TotalTransactionsCount); i++ {
		if stub.TxType[i] != offset {
			stub.BitmaskTxType.SetBit(i)
			newTxTypes = append(newTxTypes, stub.TxType[i])
		}
	}
	stub.TxType = newTxTypes
	stub.TxTypeOffset = offset
	stub.TxType = compactNibblesArray(stub.TxType)
	stub.BitmaskTxType.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructTxnHeader(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.Sender.MsgIsZero() {
		if len(stub.BitmaskSender) == 0 {
			stub.BitmaskSender = make(bitmask, bitmaskLen)
			stub.Sender = make([]byte, 0, int(stub.TotalTransactionsCount)*crypto.DigestSize)
		}
		stub.BitmaskSender.SetBit(i)
		stub.Sender = append(stub.Sender, txn.Txn.Sender[:]...)
	}
	if !txn.Txn.Fee.MsgIsZero() {
		if len(stub.BitmaskFee) == 0 {
			stub.BitmaskFee = make(bitmask, bitmaskLen)
			stub.Fee = make([]basics.MicroAlgos, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskFee.SetBit(i)
		stub.Fee = append(stub.Fee, txn.Txn.Fee)
	}
	if !txn.Txn.FirstValid.MsgIsZero() {
		if len(stub.BitmaskFirstValid) == 0 {
			stub.BitmaskFirstValid = make(bitmask, bitmaskLen)
			stub.FirstValid = make([]basics.Round, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskFirstValid.SetBit(i)
		stub.FirstValid = append(stub.FirstValid, txn.Txn.FirstValid)
	}
	if !txn.Txn.LastValid.MsgIsZero() {
		if len(stub.BitmaskLastValid) == 0 {
			stub.BitmaskLastValid = make(bitmask, bitmaskLen)
			stub.LastValid = make([]basics.Round, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskLastValid.SetBit(i)
		stub.LastValid = append(stub.LastValid, txn.Txn.LastValid)
	}
	if txn.Txn.Note != nil {
		if len(stub.BitmaskNote) == 0 {
			stub.BitmaskNote = make(bitmask, bitmaskLen)
			stub.Note = make([][]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskNote.SetBit(i)
		stub.Note = append(stub.Note, txn.Txn.Note)
	}
	if txn.Txn.GenesisID != "" {
		if len(stub.BitmaskGenesisID) == 0 {
			stub.BitmaskGenesisID = make(bitmask, bitmaskLen)
		}
		stub.BitmaskGenesisID.SetBit(i)
	}
	if !txn.Txn.GenesisHash.MsgIsZero() {
		if len(stub.BitmaskGenesisHash) == 0 {
			stub.BitmaskGenesisHash = make(bitmask, bitmaskLen)
		}
		stub.BitmaskGenesisHash.SetBit(i)
	}
	if !txn.Txn.Group.MsgIsZero() {
		if len(stub.BitmaskGroup) == 0 {
			stub.BitmaskGroup = make(bitmask, bitmaskLen)
		}
		stub.BitmaskGroup.SetBit(i)
	}
	if txn.Txn.Lease != ([32]byte{}) {
		if len(stub.BitmaskLease) == 0 {
			stub.BitmaskLease = make(bitmask, bitmaskLen)
			stub.Lease = make([]byte, 0, int(stub.TotalTransactionsCount)*crypto.DigestSize)
		}
		stub.BitmaskLease.SetBit(i)
		stub.Lease = append(stub.Lease, txn.Txn.Lease[:]...)
	}
	if !txn.Txn.RekeyTo.MsgIsZero() {
		if len(stub.BitmaskRekeyTo) == 0 {
			stub.BitmaskRekeyTo = make(bitmask, bitmaskLen)
			stub.RekeyTo = make([]byte, 0, int(stub.TotalTransactionsCount)*crypto.DigestSize)
		}
		stub.BitmaskRekeyTo.SetBit(i)
		stub.RekeyTo = append(stub.RekeyTo, txn.Txn.RekeyTo[:]...)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructTxnHeader() {
	stub.BitmaskSender.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFee.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFirstValid.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLastValid.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskNote.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGenesisID.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGenesisHash.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGroup.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLease.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskRekeyTo.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructKeyregTxnFields(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.VotePK.MsgIsZero() || !txn.Txn.SelectionPK.MsgIsZero() || txn.Txn.VoteKeyDilution != 0 {
		if len(stub.BitmaskKeys) == 0 {
			stub.BitmaskKeys = make(bitmask, bitmaskLen)
			stub.VotePK = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
			stub.SelectionPK = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
			stub.VoteKeyDilution = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskKeys.SetBit(i)
		stub.VotePK = append(stub.VotePK, txn.Txn.VotePK[:]...)
		stub.SelectionPK = append(stub.SelectionPK, txn.Txn.SelectionPK[:]...)
		stub.VoteKeyDilution = append(stub.VoteKeyDilution, txn.Txn.VoteKeyDilution)
	}
	if !txn.Txn.VoteFirst.MsgIsZero() {
		if len(stub.BitmaskVoteFirst) == 0 {
			stub.BitmaskVoteFirst = make(bitmask, bitmaskLen)
			stub.VoteFirst = make([]basics.Round, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskVoteFirst.SetBit(i)
		stub.VoteFirst = append(stub.VoteFirst, txn.Txn.VoteFirst)
	}
	if !txn.Txn.VoteLast.MsgIsZero() {
		if len(stub.BitmaskVoteLast) == 0 {
			stub.BitmaskVoteLast = make(bitmask, bitmaskLen)
			stub.VoteLast = make([]basics.Round, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskVoteLast.SetBit(i)
		stub.VoteLast = append(stub.VoteLast, txn.Txn.VoteLast)
	}
	if txn.Txn.Nonparticipation {
		if len(stub.BitmaskNonparticipation) == 0 {
			stub.BitmaskNonparticipation = make(bitmask, bitmaskLen)
		}
		stub.BitmaskNonparticipation.SetBit(i)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructKeyregTxnFields() {
	stub.BitmaskKeys.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVoteFirst.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVoteLast.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskNonparticipation.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructPaymentTxnFields(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.Receiver.MsgIsZero() {
		if len(stub.BitmaskReceiver) == 0 {
			stub.BitmaskReceiver = make(bitmask, bitmaskLen)
			stub.Receiver = make([]byte, 0, int(stub.TotalTransactionsCount)*crypto.DigestSize)
		}
		stub.BitmaskReceiver.SetBit(i)
		stub.Receiver = append(stub.Receiver, txn.Txn.Receiver[:]...)
	}
	if !txn.Txn.Amount.MsgIsZero() {
		if len(stub.BitmaskAmount) == 0 {
			stub.BitmaskAmount = make(bitmask, bitmaskLen)
			stub.Amount = make([]basics.MicroAlgos, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskAmount.SetBit(i)
		stub.Amount = append(stub.Amount, txn.Txn.Amount)
	}
	if !txn.Txn.CloseRemainderTo.MsgIsZero() {
		if len(stub.BitmaskCloseRemainderTo) == 0 {
			stub.BitmaskCloseRemainderTo = make(bitmask, bitmaskLen)
			stub.CloseRemainderTo = make([]byte, 0, int(stub.TotalTransactionsCount)*crypto.DigestSize)
		}
		stub.BitmaskCloseRemainderTo.SetBit(i)
		stub.CloseRemainderTo = append(stub.CloseRemainderTo, txn.Txn.CloseRemainderTo[:]...)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructPaymentTxnFields() {
	stub.BitmaskReceiver.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAmount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCloseRemainderTo.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructAssetConfigTxnFields(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.ConfigAsset.MsgIsZero() {
		if len(stub.BitmaskConfigAsset) == 0 {
			stub.BitmaskConfigAsset = make(bitmask, bitmaskLen)
			stub.ConfigAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskConfigAsset.SetBit(i)
		stub.ConfigAsset = append(stub.ConfigAsset, txn.Txn.ConfigAsset)
	}
	stub.deconstructAssetParams(i, txn)
}

func (stub *txGroupsEncodingStub) finishDeconstructAssetConfigTxnFields() {
	stub.BitmaskConfigAsset.trimBitmask(int(stub.TotalTransactionsCount))
	stub.finishDeconstructAssetParams()
}

func (stub *txGroupsEncodingStub) deconstructAssetParams(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if txn.Txn.AssetParams.Total != 0 {
		if len(stub.BitmaskTotal) == 0 {
			stub.BitmaskTotal = make(bitmask, bitmaskLen)
			stub.Total = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskTotal.SetBit(i)
		stub.Total = append(stub.Total, txn.Txn.AssetParams.Total)
	}
	if txn.Txn.AssetParams.Decimals != 0 {
		if len(stub.BitmaskDecimals) == 0 {
			stub.BitmaskDecimals = make(bitmask, bitmaskLen)
			stub.Decimals = make([]uint32, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskDecimals.SetBit(i)
		stub.Decimals = append(stub.Decimals, txn.Txn.AssetParams.Decimals)
	}
	if txn.Txn.AssetParams.DefaultFrozen {
		if len(stub.BitmaskDefaultFrozen) == 0 {
			stub.BitmaskDefaultFrozen = make(bitmask, bitmaskLen)
		}
		stub.BitmaskDefaultFrozen.SetBit(i)
	}
	if txn.Txn.AssetParams.UnitName != "" {
		if len(stub.BitmaskUnitName) == 0 {
			stub.BitmaskUnitName = make(bitmask, bitmaskLen)
			stub.UnitName = make([]string, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskUnitName.SetBit(i)
		stub.UnitName = append(stub.UnitName, txn.Txn.AssetParams.UnitName)
	}
	if txn.Txn.AssetParams.AssetName != "" {
		if len(stub.BitmaskAssetName) == 0 {
			stub.BitmaskAssetName = make(bitmask, bitmaskLen)
			stub.AssetName = make([]string, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskAssetName.SetBit(i)
		stub.AssetName = append(stub.AssetName, txn.Txn.AssetParams.AssetName)
	}
	if txn.Txn.AssetParams.URL != "" {
		if len(stub.BitmaskURL) == 0 {
			stub.BitmaskURL = make(bitmask, bitmaskLen)
			stub.URL = make([]string, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskURL.SetBit(i)
		stub.URL = append(stub.URL, txn.Txn.AssetParams.URL)
	}
	if txn.Txn.AssetParams.MetadataHash != [32]byte{} {
		if len(stub.BitmaskMetadataHash) == 0 {
			stub.BitmaskMetadataHash = make(bitmask, bitmaskLen)
			stub.MetadataHash = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskMetadataHash.SetBit(i)
		stub.MetadataHash = append(stub.MetadataHash, txn.Txn.AssetParams.MetadataHash[:]...)
	}
	if !txn.Txn.AssetParams.Manager.MsgIsZero() {
		if len(stub.BitmaskManager) == 0 {
			stub.BitmaskManager = make(bitmask, bitmaskLen)
			stub.Manager = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskManager.SetBit(i)
		stub.Manager = append(stub.Manager, txn.Txn.AssetParams.Manager[:]...)
	}
	if !txn.Txn.AssetParams.Reserve.MsgIsZero() {
		if len(stub.BitmaskReserve) == 0 {
			stub.BitmaskReserve = make(bitmask, bitmaskLen)
			stub.Reserve = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskReserve.SetBit(i)
		stub.Reserve = append(stub.Reserve, txn.Txn.AssetParams.Reserve[:]...)
	}
	if !txn.Txn.AssetParams.Freeze.MsgIsZero() {
		if len(stub.BitmaskFreeze) == 0 {
			stub.BitmaskFreeze = make(bitmask, bitmaskLen)
			stub.Freeze = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskFreeze.SetBit(i)
		stub.Freeze = append(stub.Freeze, txn.Txn.AssetParams.Freeze[:]...)
	}
	if !txn.Txn.AssetParams.Clawback.MsgIsZero() {
		if len(stub.BitmaskClawback) == 0 {
			stub.BitmaskClawback = make(bitmask, bitmaskLen)
			stub.Clawback = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskClawback.SetBit(i)
		stub.Clawback = append(stub.Clawback, txn.Txn.AssetParams.Clawback[:]...)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructAssetParams() {
	stub.BitmaskTotal.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskDecimals.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskDefaultFrozen.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskUnitName.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetName.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskURL.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskMetadataHash.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskManager.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskReserve.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFreeze.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskClawback.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructAssetTransferTxnFields(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.XferAsset.MsgIsZero() {
		if len(stub.BitmaskXferAsset) == 0 {
			stub.BitmaskXferAsset = make(bitmask, bitmaskLen)
			stub.XferAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskXferAsset.SetBit(i)
		stub.XferAsset = append(stub.XferAsset, txn.Txn.XferAsset)
	}
	if txn.Txn.AssetAmount != 0 {
		if len(stub.BitmaskAssetAmount) == 0 {
			stub.BitmaskAssetAmount = make(bitmask, bitmaskLen)
			stub.AssetAmount = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskAssetAmount.SetBit(i)
		stub.AssetAmount = append(stub.AssetAmount, txn.Txn.AssetAmount)
	}
	if !txn.Txn.AssetSender.MsgIsZero() {
		if len(stub.BitmaskAssetSender) == 0 {
			stub.BitmaskAssetSender = make(bitmask, bitmaskLen)
			stub.AssetSender = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskAssetSender.SetBit(i)
		stub.AssetSender = append(stub.AssetSender, txn.Txn.AssetSender[:]...)
	}
	if !txn.Txn.AssetReceiver.MsgIsZero() {
		if len(stub.BitmaskAssetReceiver) == 0 {
			stub.BitmaskAssetReceiver = make(bitmask, bitmaskLen)
			stub.AssetReceiver = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskAssetReceiver.SetBit(i)
		stub.AssetReceiver = append(stub.AssetReceiver, txn.Txn.AssetReceiver[:]...)
	}
	if !txn.Txn.AssetCloseTo.MsgIsZero() {
		if len(stub.BitmaskAssetCloseTo) == 0 {
			stub.BitmaskAssetCloseTo = make(bitmask, bitmaskLen)
			stub.AssetCloseTo = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskAssetCloseTo.SetBit(i)
		stub.AssetCloseTo = append(stub.AssetCloseTo, txn.Txn.AssetCloseTo[:]...)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructAssetTransferTxnFields() {
	stub.BitmaskXferAsset.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetAmount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetSender.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetReceiver.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetCloseTo.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructAssetFreezeTxnFields(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.FreezeAccount.MsgIsZero() {
		if len(stub.BitmaskFreezeAccount) == 0 {
			stub.BitmaskFreezeAccount = make(bitmask, bitmaskLen)
			stub.FreezeAccount = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskFreezeAccount.SetBit(i)
		stub.FreezeAccount = append(stub.FreezeAccount, txn.Txn.FreezeAccount[:]...)
	}
	if txn.Txn.FreezeAsset != 0 {
		if len(stub.BitmaskFreezeAsset) == 0 {
			stub.BitmaskFreezeAsset = make(bitmask, bitmaskLen)
			stub.FreezeAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskFreezeAsset.SetBit(i)
		stub.FreezeAsset = append(stub.FreezeAsset, txn.Txn.FreezeAsset)
	}
	if txn.Txn.AssetFrozen {
		if len(stub.BitmaskAssetFrozen) == 0 {
			stub.BitmaskAssetFrozen = make(bitmask, bitmaskLen)
		}
		stub.BitmaskAssetFrozen.SetBit(i)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructAssetFreezeTxnFields() {
	stub.BitmaskFreezeAccount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFreezeAsset.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetFrozen.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructApplicationCallTxnFields(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.ApplicationID.MsgIsZero() {
		if len(stub.BitmaskApplicationID) == 0 {
			stub.BitmaskApplicationID = make(bitmask, bitmaskLen)
			stub.ApplicationID = make([]basics.AppIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskApplicationID.SetBit(i)
		stub.ApplicationID = append(stub.ApplicationID, txn.Txn.ApplicationID)
	}
	if txn.Txn.OnCompletion != 0 {
		if len(stub.BitmaskOnCompletion) == 0 {
			stub.BitmaskOnCompletion = make(bitmask, bitmaskLen)
			stub.OnCompletion = make([]byte, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskOnCompletion.SetBit(i)
		stub.OnCompletion = append(stub.OnCompletion, byte(txn.Txn.OnCompletion))
	}
	if txn.Txn.ApplicationArgs != nil {
		if len(stub.BitmaskApplicationArgs) == 0 {
			stub.BitmaskApplicationArgs = make(bitmask, bitmaskLen)
			stub.ApplicationArgs = make([]applicationArgs, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskApplicationArgs.SetBit(i)
		stub.ApplicationArgs = append(stub.ApplicationArgs, txn.Txn.ApplicationArgs)
	}
	if txn.Txn.Accounts != nil {
		if len(stub.BitmaskAccounts) == 0 {
			stub.BitmaskAccounts = make(bitmask, bitmaskLen)
			stub.Accounts = make([]addresses, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskAccounts.SetBit(i)
		stub.Accounts = append(stub.Accounts, txn.Txn.Accounts)
	}
	if txn.Txn.ForeignApps != nil {
		if len(stub.BitmaskForeignApps) == 0 {
			stub.BitmaskForeignApps = make(bitmask, bitmaskLen)
			stub.ForeignApps = make([]appIndices, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskForeignApps.SetBit(i)
		stub.ForeignApps = append(stub.ForeignApps, txn.Txn.ForeignApps)
	}
	if txn.Txn.ForeignAssets != nil {
		if len(stub.BitmaskForeignAssets) == 0 {
			stub.BitmaskForeignAssets = make(bitmask, bitmaskLen)
			stub.ForeignAssets = make([]assetIndices, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskForeignAssets.SetBit(i)
		stub.ForeignAssets = append(stub.ForeignAssets, txn.Txn.ForeignAssets)
	}
	if !txn.Txn.LocalStateSchema.MsgIsZero() {
		if len(stub.BitmaskLocalNumUint) == 0 {
			stub.BitmaskLocalNumUint = make(bitmask, bitmaskLen)
			stub.LocalNumUint = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskLocalNumUint.SetBit(i)
		stub.LocalNumUint = append(stub.LocalNumUint, txn.Txn.LocalStateSchema.NumUint)
	}
	if !txn.Txn.LocalStateSchema.MsgIsZero() {
		if len(stub.BitmaskLocalNumByteSlice) == 0 {
			stub.BitmaskLocalNumByteSlice = make(bitmask, bitmaskLen)
			stub.LocalNumByteSlice = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskLocalNumByteSlice.SetBit(i)
		stub.LocalNumByteSlice = append(stub.LocalNumByteSlice, txn.Txn.LocalStateSchema.NumByteSlice)
	}
	if !txn.Txn.GlobalStateSchema.MsgIsZero() {
		if len(stub.BitmaskGlobalNumUint) == 0 {
			stub.BitmaskGlobalNumUint = make(bitmask, bitmaskLen)
			stub.GlobalNumUint = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskGlobalNumUint.SetBit(i)
		stub.GlobalNumUint = append(stub.GlobalNumUint, txn.Txn.GlobalStateSchema.NumUint)
	}
	if !txn.Txn.GlobalStateSchema.MsgIsZero() {
		if len(stub.BitmaskGlobalNumByteSlice) == 0 {
			stub.BitmaskGlobalNumByteSlice = make(bitmask, bitmaskLen)
			stub.GlobalNumByteSlice = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskGlobalNumByteSlice.SetBit(i)
		stub.GlobalNumByteSlice = append(stub.GlobalNumByteSlice, txn.Txn.GlobalStateSchema.NumByteSlice)
	}
	if txn.Txn.ApprovalProgram != nil {
		if len(stub.BitmaskApprovalProgram) == 0 {
			stub.BitmaskApprovalProgram = make(bitmask, bitmaskLen)
			stub.ApprovalProgram = make([]program, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskApprovalProgram.SetBit(i)
		stub.ApprovalProgram = append(stub.ApprovalProgram, txn.Txn.ApprovalProgram)
	}
	if txn.Txn.ClearStateProgram != nil {
		if len(stub.BitmaskClearStateProgram) == 0 {
			stub.BitmaskClearStateProgram = make(bitmask, bitmaskLen)
			stub.ClearStateProgram = make([]program, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskClearStateProgram.SetBit(i)
		stub.ClearStateProgram = append(stub.ClearStateProgram, txn.Txn.ClearStateProgram)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructApplicationCallTxnFields() {
	stub.OnCompletion = compactNibblesArray(stub.OnCompletion)
	stub.BitmaskApplicationID.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskOnCompletion.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskApplicationArgs.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAccounts.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskForeignApps.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskForeignAssets.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLocalNumUint.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLocalNumByteSlice.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGlobalNumUint.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGlobalNumByteSlice.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskApprovalProgram.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskClearStateProgram.trimBitmask(int(stub.TotalTransactionsCount))
}

func (stub *txGroupsEncodingStub) deconstructCompactCertTxnFields(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.CertRound.MsgIsZero() {
		if len(stub.BitmaskCertRound) == 0 {
			stub.BitmaskCertRound = make(bitmask, bitmaskLen)
			stub.CertRound = make([]basics.Round, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskCertRound.SetBit(i)
		stub.CertRound = append(stub.CertRound, txn.Txn.CertRound)
	}
	if txn.Txn.CertType != 0 {
		if len(stub.BitmaskCertType) == 0 {
			stub.BitmaskCertType = make(bitmask, bitmaskLen)
			stub.CertType = make([]protocol.CompactCertType, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskCertType.SetBit(i)
		stub.CertType = append(stub.CertType, txn.Txn.CertType)
	}
	stub.deconstructCert(i, txn)
}

func (stub *txGroupsEncodingStub) finishDeconstructCompactCertTxnFields() {
	stub.BitmaskCertRound.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCertType.trimBitmask(int(stub.TotalTransactionsCount))
	stub.finishDeconstructCert()
}

func (stub *txGroupsEncodingStub) deconstructCert(i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.Cert.SigCommit.MsgIsZero() {
		if len(stub.BitmaskSigCommit) == 0 {
			stub.BitmaskSigCommit = make(bitmask, bitmaskLen)
			stub.SigCommit = make([]byte, 0, stub.TotalTransactionsCount*crypto.DigestSize)
		}
		stub.BitmaskSigCommit.SetBit(i)
		stub.SigCommit = append(stub.SigCommit, txn.Txn.Cert.SigCommit[:]...)
	}
	if txn.Txn.Cert.SignedWeight != 0 {
		if len(stub.BitmaskSignedWeight) == 0 {
			stub.BitmaskSignedWeight = make(bitmask, bitmaskLen)
			stub.SignedWeight = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskSignedWeight.SetBit(i)
		stub.SignedWeight = append(stub.SignedWeight, txn.Txn.Cert.SignedWeight)
	}
	if txn.Txn.Cert.SigProofs != nil {
		if len(stub.BitmaskSigProofs) == 0 {
			stub.BitmaskSigProofs = make(bitmask, bitmaskLen)
			stub.SigProofs = make([]certProofs, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskSigProofs.SetBit(i)
		stub.SigProofs = append(stub.SigProofs, txn.Txn.Cert.SigProofs)
	}
	if txn.Txn.Cert.PartProofs != nil {
		if len(stub.BitmaskPartProofs) == 0 {
			stub.BitmaskPartProofs = make(bitmask, bitmaskLen)
			stub.PartProofs = make([]certProofs, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskPartProofs.SetBit(i)
		stub.PartProofs = append(stub.PartProofs, txn.Txn.Cert.PartProofs)
	}
	if txn.Txn.Cert.Reveals != nil {
		if len(stub.BitmaskReveals) == 0 {
			stub.BitmaskReveals = make(bitmask, bitmaskLen)
			stub.Reveals = make([]revealMap, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskReveals.SetBit(i)
		stub.Reveals = append(stub.Reveals, txn.Txn.Cert.Reveals)
	}
}

func (stub *txGroupsEncodingStub) finishDeconstructCert() {
	stub.BitmaskSigCommit.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSignedWeight.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSigProofs.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskPartProofs.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskReveals.trimBitmask(int(stub.TotalTransactionsCount))
}
