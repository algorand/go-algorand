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
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
)

var errDataMissing = errors.New("failed to decode: data missing")

func getSlice(b []byte, index int, size int) ([]byte, error) {
	if index*size+size > len(b) {
		return nil, errDataMissing
	}
	return b[index*size : index*size+size], nil
}

func getNibble(b []byte, index int) (byte, error) {
	if index > len(b)*2 {
		return 0, errDataMissing
	}
	if index%2 == 0 {
		return b[index/2] / 16, nil
	}
	return b[index/2] % 16, nil
}

func (stub *txGroupsEncodingStub) reconstructSignedTransactions(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskSig.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskSig.EntryExists(i); exists {
			slice, err := getSlice(stub.Sig, index, len(crypto.Signature{}))
			if err != nil {
				return err
			}
			copy(signedTxns[i].Sig[:], slice)
			index++
		}
	}
	if err := stub.reconstructMsigs(signedTxns); err != nil {
		return fmt.Errorf("failed to msigs: %v", err)
	}
	if err := stub.reconstructLsigs(signedTxns); err != nil {
		return fmt.Errorf("failed to lsigs: %v", err)
	}
	index = 0
	stub.BitmaskAuthAddr.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAuthAddr.EntryExists(i); exists {
			slice, err := getSlice(stub.AuthAddr, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].AuthAddr[:], slice)
			index++
		}
	}

	return stub.reconstructTransactions(signedTxns)
}

func (stub *txGroupsEncodingStub) reconstructMsigs(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskVersion.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskVersion.EntryExists(i); exists {
			if index >= len(stub.Version) {
				return errDataMissing
			}
			signedTxns[i].Msig.Version = stub.Version[index]
			index++
		}
	}
	index = 0
	stub.BitmaskThreshold.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskThreshold.EntryExists(i); exists {
			if index >= len(stub.Threshold) {
				return errDataMissing
			}
			signedTxns[i].Msig.Threshold = stub.Threshold[index]
			index++
		}
	}
	index = 0
	stub.BitmaskSubsigs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskSubsigs.EntryExists(i); exists {
			if index >= len(stub.Subsigs) {
				return errDataMissing
			}
			signedTxns[i].Msig.Subsigs = stub.Subsigs[index]
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructLsigs(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskLogic.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskLogic.EntryExists(i); exists {
			if index >= len(stub.Logic) {
				return errDataMissing
			}
			signedTxns[i].Lsig.Logic = stub.Logic[index]
			// fetch sig/msig
			signedTxns[i].Lsig.Sig = signedTxns[i].Sig
			signedTxns[i].Sig = crypto.Signature{}
			signedTxns[i].Lsig.Msig = signedTxns[i].Msig
			signedTxns[i].Msig = crypto.MultisigSig{}
			index++
		}
	}
	index = 0
	stub.BitmaskLogicArgs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskLogicArgs.EntryExists(i); exists {
			if index >= len(stub.LogicArgs) {
				return errDataMissing
			}
			signedTxns[i].Lsig.Args = stub.LogicArgs[index]
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructTransactions(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskTxType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskTxType.EntryExists(i); exists {
			b, err := getNibble(stub.TxType, index)
			if err != nil {
				return err
			}
			if b == stub.TxTypeOffset {
				signedTxns[i].Txn.Type = ByteToTxType(0)
			} else {
				signedTxns[i].Txn.Type = ByteToTxType(b)
			}
			index++
		} else {
			signedTxns[i].Txn.Type = ByteToTxType(stub.TxTypeOffset)
		}
	}

	if err := stub.reconstructTxnHeader(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructTxnHeader: %v", err)
	}
	if err := stub.reconstructKeyregTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructKeyregTxnFields: %v", err)
	}
	if err := stub.reconstructPaymentTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructPaymentTxnFields: %v", err)
	}
	if err := stub.reconstructAssetConfigTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructAssetConfigTxnFields: %v", err)
	}
	if err := stub.reconstructAssetTransferTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructAssetTransferTxnFields: %v", err)
	}
	if err := stub.reconstructAssetFreezeTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructAssetFreezeTxnFields: %v", err)
	}
	if err := stub.reconstructApplicationCallTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructApplicationCallTxnFields: %v", err)
	}
	if err := stub.reconstructCompactCertTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructCompactCertTxnFields: %v", err)
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructTxnHeader(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskSender.EntryExists(i); exists {
			slice, err := getSlice(stub.Sender, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Sender[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFee.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskFee.EntryExists(i); exists {
			if index >= len(stub.Fee) {
				return errDataMissing
			}
			signedTxns[i].Txn.Fee = stub.Fee[index]
			index++
		}
	}
	index = 0
	stub.BitmaskFirstValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskFirstValid.EntryExists(i); exists {
			if index >= len(stub.FirstValid) {
				return errDataMissing
			}
			signedTxns[i].Txn.FirstValid = stub.FirstValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLastValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskLastValid.EntryExists(i); exists {
			if index >= len(stub.LastValid) {
				return errDataMissing
			}
			signedTxns[i].Txn.LastValid = stub.LastValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskNote.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskNote.EntryExists(i); exists {
			if index >= len(stub.Note) {
				return errDataMissing
			}
			signedTxns[i].Txn.Note = stub.Note[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGenesisID.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskGenesisID.EntryExists(i); exists {
			signedTxns[i].Txn.GenesisID = stub.GenesisID
			index++
		}
	}
	index = 0
	stub.BitmaskGenesisHash.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskGenesisHash.EntryExists(i); exists {
			signedTxns[i].Txn.GenesisHash = stub.GenesisHash
			index++
		}
	}
	index = 0
	stub.BitmaskLease.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskLease.EntryExists(i); exists {
			slice, err := getSlice(stub.Lease, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Lease[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskRekeyTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskRekeyTo.EntryExists(i); exists {
			slice, err := getSlice(stub.RekeyTo, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.RekeyTo[:], slice)
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructKeyregTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskKeys.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskKeys.EntryExists(i); exists {
			slice, err := getSlice(stub.VotePK, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.VotePK[:], slice)
			slice, err = getSlice(stub.SelectionPK, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.SelectionPK[:], slice)
			if index >= len(stub.VoteKeyDilution) {
				return errDataMissing
			}
			signedTxns[i].Txn.VoteKeyDilution = stub.VoteKeyDilution[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteFirst.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskVoteFirst.EntryExists(i); exists {
			if index >= len(stub.VoteFirst) {
				return errDataMissing
			}
			signedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteLast.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskVoteLast.EntryExists(i); exists {
			if index >= len(stub.VoteLast) {
				return errDataMissing
			}
			signedTxns[i].Txn.VoteLast = stub.VoteLast[index]
			index++
		}
	}
	stub.BitmaskNonparticipation.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskNonparticipation.EntryExists(i); exists {
			signedTxns[i].Txn.Nonparticipation = true
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructPaymentTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskReceiver.EntryExists(i); exists {
			slice, err := getSlice(stub.Receiver, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Receiver[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAmount.EntryExists(i); exists {
			if index >= len(stub.Amount) {
				return errDataMissing
			}
			signedTxns[i].Txn.Amount = stub.Amount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCloseRemainderTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskCloseRemainderTo.EntryExists(i); exists {
			slice, err := getSlice(stub.CloseRemainderTo, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.CloseRemainderTo[:], slice)
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetConfigTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskConfigAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskConfigAsset.EntryExists(i); exists {
			if index >= len(stub.ConfigAsset) {
				return errDataMissing
			}
			signedTxns[i].Txn.ConfigAsset = stub.ConfigAsset[index]
			index++
		}
	}
	return stub.reconstructAssetParams(signedTxns)
}

func (stub *txGroupsEncodingStub) reconstructAssetParams(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskTotal.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskTotal.EntryExists(i); exists {
			if index >= len(stub.Total) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.Total = stub.Total[index]
			index++
		}
	}
	index = 0
	stub.BitmaskDecimals.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskDecimals.EntryExists(i); exists {
			if index >= len(stub.Decimals) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.Decimals = stub.Decimals[index]
			index++
		}
	}
	index = 0
	stub.BitmaskDefaultFrozen.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskDefaultFrozen.EntryExists(i); exists {
			signedTxns[i].Txn.AssetParams.DefaultFrozen = true
			index++
		}
	}
	index = 0
	stub.BitmaskUnitName.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskUnitName.EntryExists(i); exists {
			if index >= len(stub.UnitName) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.UnitName = stub.UnitName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetName.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAssetName.EntryExists(i); exists {
			if index >= len(stub.AssetName) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.AssetName = stub.AssetName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskURL.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskURL.EntryExists(i); exists {
			if index >= len(stub.URL) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.URL = stub.URL[index]
			index++
		}
	}
	index = 0
	stub.BitmaskMetadataHash.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskMetadataHash.EntryExists(i); exists {
			slice, err := getSlice(stub.MetadataHash, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.MetadataHash[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskManager.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskManager.EntryExists(i); exists {
			slice, err := getSlice(stub.Manager, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.Manager[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskReserve.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskReserve.EntryExists(i); exists {
			slice, err := getSlice(stub.Reserve, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.Reserve[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFreeze.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskFreeze.EntryExists(i); exists {
			slice, err := getSlice(stub.Freeze, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.Freeze[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskClawback.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskClawback.EntryExists(i); exists {
			slice, err := getSlice(stub.Clawback, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.Clawback[:], slice)
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetTransferTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskXferAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskXferAsset.EntryExists(i); exists {
			if index >= len(stub.XferAsset) {
				return errDataMissing
			}
			signedTxns[i].Txn.XferAsset = stub.XferAsset[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAssetAmount.EntryExists(i); exists {
			if index >= len(stub.AssetAmount) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetAmount = stub.AssetAmount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAssetSender.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetSender, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetSender[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAssetReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAssetReceiver.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetReceiver, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetReceiver[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAssetCloseTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAssetCloseTo.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetCloseTo, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetCloseTo[:], slice)
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetFreezeTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskFreezeAccount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskFreezeAccount.EntryExists(i); exists {
			slice, err := getSlice(stub.FreezeAccount, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.FreezeAccount[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFreezeAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskFreezeAsset.EntryExists(i); exists {
			if index >= len(stub.FreezeAsset) {
				return errDataMissing
			}
			signedTxns[i].Txn.FreezeAsset = stub.FreezeAsset[index]
			index++
		}
	}
	stub.BitmaskAssetFrozen.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAssetFrozen.EntryExists(i); exists {
			signedTxns[i].Txn.AssetFrozen = true
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructApplicationCallTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskApplicationID.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskApplicationID.EntryExists(i); exists {
			if index >= len(stub.ApplicationID) {
				return errDataMissing
			}
			signedTxns[i].Txn.ApplicationID = stub.ApplicationID[index]
			index++
		}
	}
	index = 0
	stub.BitmaskOnCompletion.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskOnCompletion.EntryExists(i); exists {
			b, err := getNibble(stub.OnCompletion, index)
			if err != nil {
				return err
			}
			signedTxns[i].Txn.OnCompletion = transactions.OnCompletion(b)
			index++
		}
	}
	index = 0
	stub.BitmaskApplicationArgs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskApplicationArgs.EntryExists(i); exists {
			if index >= len(stub.ApplicationArgs) {
				return errDataMissing
			}
			signedTxns[i].Txn.ApplicationArgs = stub.ApplicationArgs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAccounts.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskAccounts.EntryExists(i); exists {
			if index >= len(stub.Accounts) {
				return errDataMissing
			}
			signedTxns[i].Txn.Accounts = stub.Accounts[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignApps.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskForeignApps.EntryExists(i); exists {
			if index >= len(stub.ForeignApps) {
				return errDataMissing
			}
			signedTxns[i].Txn.ForeignApps = stub.ForeignApps[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignAssets.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskForeignAssets.EntryExists(i); exists {
			if index >= len(stub.ForeignAssets) {
				return errDataMissing
			}
			signedTxns[i].Txn.ForeignAssets = stub.ForeignAssets[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskLocalNumUint.EntryExists(i); exists {
			if index >= len(stub.LocalNumUint) {
				return errDataMissing
			}
			signedTxns[i].Txn.LocalStateSchema.NumUint = stub.LocalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskLocalNumByteSlice.EntryExists(i); exists {
			if index >= len(stub.LocalNumByteSlice) {
				return errDataMissing
			}
			signedTxns[i].Txn.LocalStateSchema.NumByteSlice = stub.LocalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskGlobalNumUint.EntryExists(i); exists {
			if index >= len(stub.GlobalNumUint) {
				return errDataMissing
			}
			signedTxns[i].Txn.GlobalStateSchema.NumUint = stub.GlobalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskGlobalNumByteSlice.EntryExists(i); exists {
			if index >= len(stub.GlobalNumByteSlice) {
				return errDataMissing
			}
			signedTxns[i].Txn.GlobalStateSchema.NumByteSlice = stub.GlobalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskApprovalProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskApprovalProgram.EntryExists(i); exists {
			if index >= len(stub.ApprovalProgram) {
				return errDataMissing
			}
			signedTxns[i].Txn.ApprovalProgram = stub.ApprovalProgram[index]
			index++
		}
	}
	index = 0
	stub.BitmaskClearStateProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskClearStateProgram.EntryExists(i); exists {
			if index >= len(stub.ClearStateProgram) {
				return errDataMissing
			}
			signedTxns[i].Txn.ClearStateProgram = stub.ClearStateProgram[index]
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructCompactCertTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskCertRound.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskCertRound.EntryExists(i); exists {
			if index >= len(stub.CertRound) {
				return errDataMissing
			}
			signedTxns[i].Txn.CertRound = stub.CertRound[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCertType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskCertType.EntryExists(i); exists {
			if index >= len(stub.CertType) {
				return errDataMissing
			}
			signedTxns[i].Txn.CertType = stub.CertType[index]
			index++
		}
	}
	return stub.reconstructCert(signedTxns)
}

func (stub *txGroupsEncodingStub) reconstructCert(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	stub.BitmaskSigCommit.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskSigCommit.EntryExists(i); exists {
			slice, err := getSlice(stub.SigCommit, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Cert.SigCommit[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskSignedWeight.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskSignedWeight.EntryExists(i); exists {
			if index >= len(stub.SignedWeight) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.SignedWeight = stub.SignedWeight[index]
			index++
		}
	}
	index = 0
	stub.BitmaskSigProofs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskSigProofs.EntryExists(i); exists {
			if index >= len(stub.SigProofs) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.SigProofs = stub.SigProofs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskPartProofs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskPartProofs.EntryExists(i); exists {
			if index >= len(stub.PartProofs) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.PartProofs = stub.PartProofs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskReveals.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range signedTxns {
		if exists := stub.BitmaskReveals.EntryExists(i); exists {
			if index >= len(stub.Reveals) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.Reveals = stub.Reveals[index]
			index++
		}
	}
	return nil
}