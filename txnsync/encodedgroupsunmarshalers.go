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

func (stub *txGroupsEncodingStub) reconstructSignedTransactions(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) error {
	var index int
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskSig.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.Sig, index, len(crypto.Signature{}))
			if err != nil {
				return err
			}
			copy(signedTxns[i].Sig[:], slice)
			index++
		}
	}
	if err := stub.reconstructMsigs(signedTxns); err != nil {
		return fmt.Errorf("failed to msigs: %w", err)
	}
	if err := stub.reconstructLsigs(signedTxns); err != nil {
		return fmt.Errorf("failed to lsigs: %w", err)
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAuthAddr.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.AuthAddr, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].AuthAddr[:], slice)
			index++
		}
	}

	return stub.reconstructTransactions(signedTxns, genesisID, genesisHash)
}

func (stub *txGroupsEncodingStub) reconstructMsigs(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskVersion.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Version) {
				return errDataMissing
			}
			signedTxns[i].Msig.Version = stub.Version[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskThreshold.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Threshold) {
				return errDataMissing
			}
			signedTxns[i].Msig.Threshold = stub.Threshold[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskSubsigs.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskLogic.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskLogicArgs.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.LogicArgs) {
				return errDataMissing
			}
			signedTxns[i].Lsig.Args = stub.LogicArgs[index]
			index++
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructTransactions(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) error {
	var index int
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskTxType.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			b, err := getNibble(stub.TxType, index)
			if err != nil {
				return err
			}
			signedTxns[i].Txn.Type = ByteToTxType(b)
			index++
		} else {
			signedTxns[i].Txn.Type = ByteToTxType(stub.TxTypeOffset)
		}
	}

	if err := stub.reconstructTxnHeader(signedTxns, genesisID, genesisHash); err != nil {
		return fmt.Errorf("failed to reconstructTxnHeader: %w", err)
	}
	if err := stub.reconstructKeyregTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructKeyregTxnFields: %w", err)
	}
	if err := stub.reconstructPaymentTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructPaymentTxnFields: %w", err)
	}
	if err := stub.reconstructAssetConfigTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructAssetConfigTxnFields: %w", err)
	}
	if err := stub.reconstructAssetTransferTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructAssetTransferTxnFields: %w", err)
	}
	if err := stub.reconstructAssetFreezeTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructAssetFreezeTxnFields: %w", err)
	}
	if err := stub.reconstructApplicationCallTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructApplicationCallTxnFields: %w", err)
	}
	if err := stub.reconstructCompactCertTxnFields(signedTxns); err != nil {
		return fmt.Errorf("failed to reconstructCompactCertTxnFields: %w", err)
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructTxnHeader(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) error {
	var index int
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskSender.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.Sender, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Sender[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskFee.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Fee) {
				return errDataMissing
			}
			signedTxns[i].Txn.Fee = stub.Fee[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskFirstValid.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.FirstValid) {
				return errDataMissing
			}
			signedTxns[i].Txn.FirstValid = stub.FirstValid[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskLastValid.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.LastValid) {
				return errDataMissing
			}
			signedTxns[i].Txn.LastValid = stub.LastValid[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskNote.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Note) {
				return errDataMissing
			}
			signedTxns[i].Txn.Note = stub.Note[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskGenesisID.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			signedTxns[i].Txn.GenesisID = genesisID
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskGenesisHash.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			signedTxns[i].Txn.GenesisHash = genesisHash
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskLease.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.Lease, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Lease[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskRekeyTo.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskKeys.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskVoteFirst.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.VoteFirst) {
				return errDataMissing
			}
			signedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskVoteLast.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.VoteLast) {
				return errDataMissing
			}
			signedTxns[i].Txn.VoteLast = stub.VoteLast[index]
			index++
		}
	}

	for i := range signedTxns {
		if exists := stub.BitmaskNonparticipation.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			signedTxns[i].Txn.Nonparticipation = true
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructPaymentTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskReceiver.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.Receiver, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Receiver[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAmount.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Amount) {
				return errDataMissing
			}
			signedTxns[i].Txn.Amount = stub.Amount[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskCloseRemainderTo.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskConfigAsset.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskTotal.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Total) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.Total = stub.Total[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskDecimals.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Decimals) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.Decimals = stub.Decimals[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskDefaultFrozen.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			signedTxns[i].Txn.AssetParams.DefaultFrozen = true
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskUnitName.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.UnitName) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.UnitName = stub.UnitName[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAssetName.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.AssetName) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.AssetName = stub.AssetName[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskURL.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.URL) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetParams.URL = stub.URL[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskMetadataHash.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.MetadataHash, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.MetadataHash[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskManager.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.Manager, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.Manager[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskReserve.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.Reserve, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.Reserve[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskFreeze.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.Freeze, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetParams.Freeze[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskClawback.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskXferAsset.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.XferAsset) {
				return errDataMissing
			}
			signedTxns[i].Txn.XferAsset = stub.XferAsset[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAssetAmount.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.AssetAmount) {
				return errDataMissing
			}
			signedTxns[i].Txn.AssetAmount = stub.AssetAmount[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAssetSender.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.AssetSender, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetSender[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAssetReceiver.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.AssetReceiver, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.AssetReceiver[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAssetCloseTo.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskFreezeAccount.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.FreezeAccount, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.FreezeAccount[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskFreezeAsset.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.FreezeAsset) {
				return errDataMissing
			}
			signedTxns[i].Txn.FreezeAsset = stub.FreezeAsset[index]
			index++
		}
	}

	for i := range signedTxns {
		if exists := stub.BitmaskAssetFrozen.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			signedTxns[i].Txn.AssetFrozen = true
		}
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructApplicationCallTxnFields(signedTxns []transactions.SignedTxn) error {
	var index int
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskApplicationID.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.ApplicationID) {
				return errDataMissing
			}
			signedTxns[i].Txn.ApplicationID = stub.ApplicationID[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskOnCompletion.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			b, err := getNibble(stub.OnCompletion, index)
			if err != nil {
				return err
			}
			signedTxns[i].Txn.OnCompletion = transactions.OnCompletion(b)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskApplicationArgs.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.ApplicationArgs) {
				return errDataMissing
			}
			signedTxns[i].Txn.ApplicationArgs = stub.ApplicationArgs[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskAccounts.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Accounts) {
				return errDataMissing
			}
			signedTxns[i].Txn.Accounts = stub.Accounts[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskForeignApps.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.ForeignApps) {
				return errDataMissing
			}
			signedTxns[i].Txn.ForeignApps = stub.ForeignApps[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskForeignAssets.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.ForeignAssets) {
				return errDataMissing
			}
			signedTxns[i].Txn.ForeignAssets = stub.ForeignAssets[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskLocalNumUint.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.LocalNumUint) {
				return errDataMissing
			}
			signedTxns[i].Txn.LocalStateSchema.NumUint = stub.LocalNumUint[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskLocalNumByteSlice.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.LocalNumByteSlice) {
				return errDataMissing
			}
			signedTxns[i].Txn.LocalStateSchema.NumByteSlice = stub.LocalNumByteSlice[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskGlobalNumUint.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.GlobalNumUint) {
				return errDataMissing
			}
			signedTxns[i].Txn.GlobalStateSchema.NumUint = stub.GlobalNumUint[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskGlobalNumByteSlice.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.GlobalNumByteSlice) {
				return errDataMissing
			}
			signedTxns[i].Txn.GlobalStateSchema.NumByteSlice = stub.GlobalNumByteSlice[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskApprovalProgram.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.ApprovalProgram) {
				return errDataMissing
			}
			signedTxns[i].Txn.ApprovalProgram = stub.ApprovalProgram[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskClearStateProgram.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskCertRound.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.CertRound) {
				return errDataMissing
			}
			signedTxns[i].Txn.CertRound = stub.CertRound[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskCertType.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
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
	for i := range signedTxns {
		if exists := stub.BitmaskSigCommit.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			slice, err := getSlice(stub.SigCommit, index, crypto.DigestSize)
			if err != nil {
				return err
			}
			copy(signedTxns[i].Txn.Cert.SigCommit[:], slice)
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskSignedWeight.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.SignedWeight) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.SignedWeight = stub.SignedWeight[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskSigProofs.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.SigProofs) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.SigProofs = stub.SigProofs[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskPartProofs.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.PartProofs) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.PartProofs = stub.PartProofs[index]
			index++
		}
	}
	index = 0
	for i := range signedTxns {
		if exists := stub.BitmaskReveals.EntryExists(i, int(stub.TotalTransactionsCount)); exists {
			if index >= len(stub.Reveals) {
				return errDataMissing
			}
			signedTxns[i].Txn.Cert.Reveals = stub.Reveals[index]
			index++
		}
	}
	return nil
}
