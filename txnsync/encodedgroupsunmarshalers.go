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

func reconstructSignedTransactions(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskSig.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSig.EntryExists(i); exists {
			slice, err := getSlice(stub.Sig, index, len(crypto.Signature{}))
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Sig[:], slice)
			index++
		}
	}
	if err := reconstructMsigs(stub); err != nil {
		return fmt.Errorf("failed to msigs: %v", err)
	}
	if err := reconstructLsigs(stub); err != nil {
		return fmt.Errorf("failed to lsigs: %v", err)
	}
	index = 0
	stub.BitmaskAuthAddr.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAuthAddr.EntryExists(i); exists {
			slice, err := getSlice(stub.AuthAddr, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].AuthAddr[:], slice)
			index++
		}
	}

	return reconstructTransactions(stub)
}

func reconstructMsigs(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskVersion.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVersion.EntryExists(i); exists {
			if index >= len(stub.Version) {
				return errDataMissing
			}
			stub.SignedTxns[i].Msig.Version = stub.Version[index]
			index++
		}
	}
	index = 0
	stub.BitmaskThreshold.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskThreshold.EntryExists(i); exists {
			if index >= len(stub.Threshold) {
				return errDataMissing
			}
			stub.SignedTxns[i].Msig.Threshold = stub.Threshold[index]
			index++
		}
	}
	index = 0
	stub.BitmaskSubsigs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSubsigs.EntryExists(i); exists {
			if index >= len(stub.Subsigs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Msig.Subsigs = stub.Subsigs[index]
			index++
		}
	}
	return nil
}

func reconstructLsigs(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskLogic.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLogic.EntryExists(i); exists {
			if index >= len(stub.Logic) {
				return errDataMissing
			}
			stub.SignedTxns[i].Lsig.Logic = stub.Logic[index]
			// fetch sig/msig
			stub.SignedTxns[i].Lsig.Sig = stub.SignedTxns[i].Sig
			stub.SignedTxns[i].Sig = crypto.Signature{}
			stub.SignedTxns[i].Lsig.Msig = stub.SignedTxns[i].Msig
			stub.SignedTxns[i].Msig = crypto.MultisigSig{}
			index++
		}
	}
	index = 0
	stub.BitmaskLogicArgs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLogicArgs.EntryExists(i); exists {
			if index >= len(stub.LogicArgs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Lsig.Args = stub.LogicArgs[index]
			index++
		}
	}
	return nil
}

func reconstructTransactions(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskTxType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskTxType.EntryExists(i); exists {
			b, err := getNibble(stub.TxType, index)
			if err != nil {
				return err
			}
			if b == stub.TxTypeOffset {
				stub.SignedTxns[i].Txn.Type = ByteToTxType(0)
			} else {
				stub.SignedTxns[i].Txn.Type = ByteToTxType(b)
			}
			index++
		} else {
			stub.SignedTxns[i].Txn.Type = ByteToTxType(stub.TxTypeOffset)
		}
	}

	if err := reconstructTxnHeader(stub); err != nil {
		return fmt.Errorf("failed to reconstructTxnHeader: %v", err)
	}
	if err := reconstructKeyregTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructKeyregTxnFields: %v", err)
	}
	if err := reconstructPaymentTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructPaymentTxnFields: %v", err)
	}
	if err := reconstructAssetConfigTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructAssetConfigTxnFields: %v", err)
	}
	if err := reconstructAssetTransferTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructAssetTransferTxnFields: %v", err)
	}
	if err := reconstructAssetFreezeTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructAssetFreezeTxnFields: %v", err)
	}
	if err := reconstructApplicationCallTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructApplicationCallTxnFields: %v", err)
	}
	if err := reconstructCompactCertTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructCompactCertTxnFields: %v", err)
	}
	return nil
}

func reconstructTxnHeader(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSender.EntryExists(i); exists {
			slice, err := getSlice(stub.Sender, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Sender[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFee.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFee.EntryExists(i); exists {
			if index >= len(stub.Fee) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Fee = stub.Fee[index]
			index++
		}
	}
	index = 0
	stub.BitmaskFirstValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFirstValid.EntryExists(i); exists {
			if index >= len(stub.FirstValid) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.FirstValid = stub.FirstValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLastValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLastValid.EntryExists(i); exists {
			if index >= len(stub.LastValid) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.LastValid = stub.LastValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskNote.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskNote.EntryExists(i); exists {
			if index >= len(stub.Note) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Note = stub.Note[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGenesisID.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGenesisID.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.GenesisID = stub.GenesisID
			index++
		}
	}
	index = 0
	stub.BitmaskGenesisHash.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGenesisHash.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.GenesisHash = stub.GenesisHash
			index++
		}
	}
	index = 0
	stub.BitmaskLease.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLease.EntryExists(i); exists {
			slice, err := getSlice(stub.Lease, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Lease[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskRekeyTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskRekeyTo.EntryExists(i); exists {
			slice, err := getSlice(stub.RekeyTo, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.RekeyTo[:], slice)
			index++
		}
	}
	return nil
}

func reconstructKeyregTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskKeys.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskKeys.EntryExists(i); exists {
			slice, err := getSlice(stub.VotePK, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.VotePK[:], slice)
			slice, err = getSlice(stub.SelectionPK, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.SelectionPK[:], slice)
			if index >= len(stub.VoteKeyDilution) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.VoteKeyDilution = stub.VoteKeyDilution[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteFirst.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVoteFirst.EntryExists(i); exists {
			if index >= len(stub.VoteFirst) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteLast.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVoteLast.EntryExists(i); exists {
			if index >= len(stub.VoteLast) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.VoteLast = stub.VoteLast[index]
			index++
		}
	}
	stub.BitmaskNonparticipation.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskNonparticipation.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Nonparticipation = true
		}
	}
	return nil
}

func reconstructPaymentTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReceiver.EntryExists(i); exists {
			slice, err := getSlice(stub.Receiver, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Receiver[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAmount.EntryExists(i); exists {
			if index >= len(stub.Amount) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Amount = stub.Amount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCloseRemainderTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCloseRemainderTo.EntryExists(i); exists {
			slice, err := getSlice(stub.CloseRemainderTo, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.CloseRemainderTo[:], slice)
			index++
		}
	}
	return nil
}

func reconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskConfigAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskConfigAsset.EntryExists(i); exists {
			if index >= len(stub.ConfigAsset) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ConfigAsset = stub.ConfigAsset[index]
			index++
		}
	}
	return reconstructAssetParams(stub)
}

func reconstructAssetParams(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskTotal.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskTotal.EntryExists(i); exists {
			if index >= len(stub.Total) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.Total = stub.Total[index]
			index++
		}
	}
	index = 0
	stub.BitmaskDecimals.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskDecimals.EntryExists(i); exists {
			if index >= len(stub.Decimals) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.Decimals = stub.Decimals[index]
			index++
		}
	}
	index = 0
	stub.BitmaskDefaultFrozen.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskDefaultFrozen.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetParams.DefaultFrozen = true
			index++
		}
	}
	index = 0
	stub.BitmaskUnitName.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskUnitName.EntryExists(i); exists {
			if index >= len(stub.UnitName) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.UnitName = stub.UnitName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetName.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetName.EntryExists(i); exists {
			if index >= len(stub.AssetName) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.AssetName = stub.AssetName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskURL.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskURL.EntryExists(i); exists {
			if index >= len(stub.URL) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.URL = stub.URL[index]
			index++
		}
	}
	index = 0
	stub.BitmaskMetadataHash.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskMetadataHash.EntryExists(i); exists {
			slice, err := getSlice(stub.MetadataHash, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.MetadataHash[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskManager.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskManager.EntryExists(i); exists {
			slice, err := getSlice(stub.Manager, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Manager[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskReserve.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReserve.EntryExists(i); exists {
			slice, err := getSlice(stub.Reserve, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Reserve[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFreeze.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreeze.EntryExists(i); exists {
			slice, err := getSlice(stub.Freeze, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Freeze[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskClawback.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskClawback.EntryExists(i); exists {
			slice, err := getSlice(stub.Clawback, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Clawback[:], slice)
			index++
		}
	}
	return nil
}

func reconstructAssetTransferTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskXferAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskXferAsset.EntryExists(i); exists {
			if index >= len(stub.XferAsset) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.XferAsset = stub.XferAsset[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetAmount.EntryExists(i); exists {
			if index >= len(stub.AssetAmount) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetAmount = stub.AssetAmount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetSender.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetSender, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetSender[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAssetReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetReceiver.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetReceiver, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetReceiver[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAssetCloseTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetCloseTo.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetCloseTo, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetCloseTo[:], slice)
			index++
		}
	}
	return nil
}

func reconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskFreezeAccount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreezeAccount.EntryExists(i); exists {
			slice, err := getSlice(stub.FreezeAccount, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.FreezeAccount[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFreezeAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreezeAsset.EntryExists(i); exists {
			if index >= len(stub.FreezeAsset) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.FreezeAsset = stub.FreezeAsset[index]
			index++
		}
	}
	stub.BitmaskAssetFrozen.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetFrozen.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetFrozen = true
		}
	}
	return nil
}

func reconstructApplicationCallTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskApplicationID.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApplicationID.EntryExists(i); exists {
			if index >= len(stub.ApplicationID) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ApplicationID = stub.ApplicationID[index]
			index++
		}
	}
	index = 0
	stub.BitmaskOnCompletion.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskOnCompletion.EntryExists(i); exists {
			b, err := getNibble(stub.OnCompletion, index)
			if err != nil {
				return err
			}
			stub.SignedTxns[i].Txn.OnCompletion = transactions.OnCompletion(b)
			index++
		}
	}
	index = 0
	stub.BitmaskApplicationArgs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApplicationArgs.EntryExists(i); exists {
			if index >= len(stub.ApplicationArgs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ApplicationArgs = stub.ApplicationArgs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAccounts.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAccounts.EntryExists(i); exists {
			if index >= len(stub.Accounts) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Accounts = stub.Accounts[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignApps.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskForeignApps.EntryExists(i); exists {
			if index >= len(stub.ForeignApps) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ForeignApps = stub.ForeignApps[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignAssets.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskForeignAssets.EntryExists(i); exists {
			if index >= len(stub.ForeignAssets) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ForeignAssets = stub.ForeignAssets[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLocalNumUint.EntryExists(i); exists {
			if index >= len(stub.LocalNumUint) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.LocalStateSchema.NumUint = stub.LocalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLocalNumByteSlice.EntryExists(i); exists {
			if index >= len(stub.LocalNumByteSlice) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.LocalStateSchema.NumByteSlice = stub.LocalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGlobalNumUint.EntryExists(i); exists {
			if index >= len(stub.GlobalNumUint) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.GlobalStateSchema.NumUint = stub.GlobalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGlobalNumByteSlice.EntryExists(i); exists {
			if index >= len(stub.GlobalNumByteSlice) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.GlobalStateSchema.NumByteSlice = stub.GlobalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskApprovalProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApprovalProgram.EntryExists(i); exists {
			if index >= len(stub.ApprovalProgram) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ApprovalProgram = stub.ApprovalProgram[index]
			index++
		}
	}
	index = 0
	stub.BitmaskClearStateProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskClearStateProgram.EntryExists(i); exists {
			if index >= len(stub.ClearStateProgram) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ClearStateProgram = stub.ClearStateProgram[index]
			index++
		}
	}
	return nil
}

func reconstructCompactCertTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskCertRound.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCertRound.EntryExists(i); exists {
			if index >= len(stub.CertRound) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.CertRound = stub.CertRound[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCertType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCertType.EntryExists(i); exists {
			if index >= len(stub.CertType) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.CertType = stub.CertType[index]
			index++
		}
	}
	return reconstructCert(stub)
}

func reconstructCert(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskSigCommit.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSigCommit.EntryExists(i); exists {
			slice, err := getSlice(stub.SigCommit, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Cert.SigCommit[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskSignedWeight.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSignedWeight.EntryExists(i); exists {
			if index >= len(stub.SignedWeight) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.SignedWeight = stub.SignedWeight[index]
			index++
		}
	}
	index = 0
	stub.BitmaskSigProofs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSigProofs.EntryExists(i); exists {
			if index >= len(stub.SigProofs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.SigProofs = stub.SigProofs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskPartProofs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskPartProofs.EntryExists(i); exists {
			if index >= len(stub.PartProofs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.PartProofs = stub.PartProofs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskReveals.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReveals.EntryExists(i); exists {
			if index >= len(stub.Reveals) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.Reveals = stub.Reveals[index]
			index++
		}
	}
	return nil
}