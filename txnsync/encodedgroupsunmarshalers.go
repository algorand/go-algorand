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

// the nextSlice definition - copy the next slice and slide the src window.
func nextSlice(src *[]byte, dst []byte, size int) error {
	if len(*src) < size {
		return errDataMissing
	}
	copy(dst[:], (*src)[:size])
	// slice the src window so next call would get the next entry.
	*src = (*src)[size:]
	return nil
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

func addGroupHashes(txnGroups []transactions.SignedTxGroup, txnCount int, b bitmask) {
	index := 0
	txGroupHashes := make([]crypto.Digest, 16)
	tStart := 0

	// addGroupHashesFunc adds hashes to transactions in groups of more than 1 transaction,
	// or to transactions with one transaction and bitmask set for that index.
	// It stops at index nextSetBitIndex, or stops when all in txnGroups are visited.
	addGroupHashesFunc := func(nextSetBitIndex int, count int) error {
		remainingTxnGroups := txnGroups[tStart:]
		for t := range remainingTxnGroups {
			txns := remainingTxnGroups[t]
			if len(txns.Transactions) == 1 && index != nextSetBitIndex {
				index++
				continue
			}
			var txGroup transactions.TxGroup
			txGroup.TxGroupHashes = txGroupHashes[:len(txns.Transactions)]
			for i, tx := range txns.Transactions {
				txGroup.TxGroupHashes[i] = crypto.HashObj(tx.Txn)
			}
			groupHash := crypto.HashObj(txGroup)
			for i := range txns.Transactions {
				txns.Transactions[i].Txn.Group = groupHash
				index++
			}
			if index > nextSetBitIndex {
				tStart += t + 1
				return nil
			}
		}
		tStart = len(txnGroups)
		return nil
	}
	// addGroupHashesFunc will be called for each set bit. Between set bits, all transactions
	// in groups of more than 1 transactions will have the hashes added.
	b.iterate(txnCount, txnCount, addGroupHashesFunc)
	// One more call to addGroupHashesFunc to cover all the remaining transactions in groups of
	// more than 1 transaction that were not added because no groups with one transaction are left.
	addGroupHashesFunc(txnCount+1, -1)
}

func (stub *txGroupsEncodingStub) reconstructSignedTransactions(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) (err error) {
	err = stub.BitmaskSig.iterate(int(stub.TotalTransactionsCount), len(stub.Sig)/len(crypto.Signature{}), func(i int, index int) error {
		return nextSlice(&stub.Sig, signedTxns[i].Sig[:], len(crypto.Signature{}))
	})
	if err != nil {
		return err
	}

	if err := stub.reconstructMsigs(signedTxns); err != nil {
		return fmt.Errorf("failed to msigs: %w", err)
	}
	if err := stub.reconstructLsigs(signedTxns); err != nil {
		return fmt.Errorf("failed to lsigs: %w", err)
	}
	err = stub.BitmaskAuthAddr.iterate(int(stub.TotalTransactionsCount), len(stub.AuthAddr), func(i int, index int) error {
		return nextSlice(&stub.AuthAddr, signedTxns[i].AuthAddr[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}

	return stub.reconstructTransactions(signedTxns, genesisID, genesisHash)
}

func (stub *txGroupsEncodingStub) reconstructMsigs(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskVersion.iterate(int(stub.TotalTransactionsCount), len(stub.Version), func(i int, index int) error {
		signedTxns[i].Msig.Version = stub.Version[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskThreshold.iterate(int(stub.TotalTransactionsCount), len(stub.Threshold), func(i int, index int) error {
		signedTxns[i].Msig.Threshold = stub.Threshold[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskSubsigs.iterate(int(stub.TotalTransactionsCount), len(stub.Subsigs), func(i int, index int) error {
		signedTxns[i].Msig.Subsigs = stub.Subsigs[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructLsigs(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskLogic.iterate(int(stub.TotalTransactionsCount), len(stub.Logic), func(i int, index int) error {
		signedTxns[i].Lsig.Logic = stub.Logic[index]
		// fetch sig/msig
		signedTxns[i].Lsig.Sig = signedTxns[i].Sig
		signedTxns[i].Sig = crypto.Signature{}
		signedTxns[i].Lsig.Msig = signedTxns[i].Msig
		signedTxns[i].Msig = crypto.MultisigSig{}
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskLogicArgs.iterate(int(stub.TotalTransactionsCount), len(stub.LogicArgs), func(i int, index int) error {
		signedTxns[i].Lsig.Args = stub.LogicArgs[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructTransactions(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) (err error) {
	err = stub.BitmaskTxType.iterate(int(stub.TotalTransactionsCount), len(stub.TxType)*2, func(i int, index int) error {
		b, err := getNibble(stub.TxType, index)
		if err != nil {
			return err
		}
		signedTxns[i].Txn.Type = ByteToTxType(b)
		return nil
	})
	for i := range signedTxns {
		if signedTxns[i].Txn.Type == "" {
			signedTxns[i].Txn.Type = ByteToTxType(stub.TxTypeOffset)
		}
	}
	if err != nil {
		return err
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

func (stub *txGroupsEncodingStub) reconstructTxnHeader(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) (err error) {
	err = stub.BitmaskSender.iterate(int(stub.TotalTransactionsCount), len(stub.Sender)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.Sender, signedTxns[i].Txn.Sender[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFee.iterate(int(stub.TotalTransactionsCount), len(stub.Fee), func(i int, index int) error {
		signedTxns[i].Txn.Fee = stub.Fee[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFirstValid.iterate(int(stub.TotalTransactionsCount), len(stub.FirstValid), func(i int, index int) error {
		signedTxns[i].Txn.FirstValid = stub.FirstValid[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskLastValid.iterate(int(stub.TotalTransactionsCount), len(stub.LastValid), func(i int, index int) error {
		signedTxns[i].Txn.LastValid = stub.LastValid[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskNote.iterate(int(stub.TotalTransactionsCount), len(stub.Note), func(i int, index int) error {
		signedTxns[i].Txn.Note = stub.Note[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskGenesisID.iterate(int(stub.TotalTransactionsCount), int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.GenesisID = genesisID
		return nil
	})
	if err != nil {
		return err
	}
	for i := range signedTxns {
		signedTxns[i].Txn.GenesisHash = genesisHash
	}
	err = stub.BitmaskLease.iterate(int(stub.TotalTransactionsCount), len(stub.Lease)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.Lease, signedTxns[i].Txn.Lease[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskRekeyTo.iterate(int(stub.TotalTransactionsCount), len(stub.RekeyTo)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.RekeyTo, signedTxns[i].Txn.RekeyTo[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructKeyregTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	// should all have same number of elements
	if len(stub.VotePK)/crypto.DigestSize != len(stub.VoteKeyDilution) || len(stub.SelectionPK)/crypto.DigestSize != len(stub.VoteKeyDilution) {
		return errDataMissing
	}
	err = stub.BitmaskKeys.iterate(int(stub.TotalTransactionsCount), len(stub.VoteKeyDilution), func(i int, index int) error {
		signedTxns[i].Txn.VoteKeyDilution = stub.VoteKeyDilution[index]
		err := nextSlice(&stub.VotePK, signedTxns[i].Txn.VotePK[:], crypto.DigestSize)
		if err != nil {
			return err
		}
		return nextSlice(&stub.SelectionPK, signedTxns[i].Txn.SelectionPK[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskVoteFirst.iterate(int(stub.TotalTransactionsCount), len(stub.VoteFirst), func(i int, index int) error {
		if index >= len(stub.VoteFirst) {
			return errDataMissing
		}
		signedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskVoteLast.iterate(int(stub.TotalTransactionsCount), len(stub.VoteLast), func(i int, index int) error {
		if index >= len(stub.VoteLast) {
			return errDataMissing
		}
		signedTxns[i].Txn.VoteLast = stub.VoteLast[index]
		return nil
	})
	if err != nil {
		return err
	}

	err = stub.BitmaskNonparticipation.iterate(int(stub.TotalTransactionsCount), int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.Nonparticipation = true
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructPaymentTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskReceiver.iterate(int(stub.TotalTransactionsCount), len(stub.Receiver)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.Receiver, signedTxns[i].Txn.Receiver[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAmount.iterate(int(stub.TotalTransactionsCount), len(stub.Amount), func(i int, index int) error {
		signedTxns[i].Txn.Amount = stub.Amount[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskCloseRemainderTo.iterate(int(stub.TotalTransactionsCount), len(stub.CloseRemainderTo)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.CloseRemainderTo, signedTxns[i].Txn.CloseRemainderTo[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetConfigTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskConfigAsset.iterate(int(stub.TotalTransactionsCount), len(stub.ConfigAsset), func(i int, index int) error {
		signedTxns[i].Txn.ConfigAsset = stub.ConfigAsset[index]
		return nil
	})
	if err != nil {
		return err
	}
	return stub.reconstructAssetParams(signedTxns)
}

func (stub *txGroupsEncodingStub) reconstructAssetParams(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskTotal.iterate(int(stub.TotalTransactionsCount), len(stub.Total), func(i int, index int) error {
		signedTxns[i].Txn.AssetParams.Total = stub.Total[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskDecimals.iterate(int(stub.TotalTransactionsCount), len(stub.Decimals), func(i int, index int) error {
		signedTxns[i].Txn.AssetParams.Decimals = stub.Decimals[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskDefaultFrozen.iterate(int(stub.TotalTransactionsCount), int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.AssetParams.DefaultFrozen = true
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskUnitName.iterate(int(stub.TotalTransactionsCount), len(stub.UnitName), func(i int, index int) error {
		signedTxns[i].Txn.AssetParams.UnitName = stub.UnitName[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetName.iterate(int(stub.TotalTransactionsCount), len(stub.AssetName), func(i int, index int) error {
		signedTxns[i].Txn.AssetParams.AssetName = stub.AssetName[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskURL.iterate(int(stub.TotalTransactionsCount), len(stub.URL), func(i int, index int) error {
		signedTxns[i].Txn.AssetParams.URL = stub.URL[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskMetadataHash.iterate(int(stub.TotalTransactionsCount), len(stub.MetadataHash)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.MetadataHash, signedTxns[i].Txn.AssetParams.MetadataHash[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskManager.iterate(int(stub.TotalTransactionsCount), len(stub.Manager)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.Manager, signedTxns[i].Txn.AssetParams.Manager[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskReserve.iterate(int(stub.TotalTransactionsCount), len(stub.Reserve)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.Reserve, signedTxns[i].Txn.AssetParams.Reserve[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFreeze.iterate(int(stub.TotalTransactionsCount), len(stub.Freeze)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.Freeze, signedTxns[i].Txn.AssetParams.Freeze[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskClawback.iterate(int(stub.TotalTransactionsCount), len(stub.Clawback)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.Clawback, signedTxns[i].Txn.AssetParams.Clawback[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetTransferTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskXferAsset.iterate(int(stub.TotalTransactionsCount), len(stub.XferAsset), func(i int, index int) error {
		signedTxns[i].Txn.XferAsset = stub.XferAsset[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetAmount.iterate(int(stub.TotalTransactionsCount), len(stub.AssetAmount), func(i int, index int) error {
		signedTxns[i].Txn.AssetAmount = stub.AssetAmount[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetSender.iterate(int(stub.TotalTransactionsCount), len(stub.AssetSender)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.AssetSender, signedTxns[i].Txn.AssetSender[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetReceiver.iterate(int(stub.TotalTransactionsCount), len(stub.AssetReceiver)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.AssetReceiver, signedTxns[i].Txn.AssetReceiver[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetCloseTo.iterate(int(stub.TotalTransactionsCount), len(stub.AssetCloseTo)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.AssetCloseTo, signedTxns[i].Txn.AssetCloseTo[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetFreezeTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskFreezeAccount.iterate(int(stub.TotalTransactionsCount), len(stub.FreezeAccount)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.FreezeAccount, signedTxns[i].Txn.FreezeAccount[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFreezeAsset.iterate(int(stub.TotalTransactionsCount), len(stub.FreezeAsset), func(i int, index int) error {
		signedTxns[i].Txn.FreezeAsset = stub.FreezeAsset[index]
		return nil
	})
	if err != nil {
		return err
	}

	err = stub.BitmaskAssetFrozen.iterate(int(stub.TotalTransactionsCount), int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.AssetFrozen = true
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructApplicationCallTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskApplicationID.iterate(int(stub.TotalTransactionsCount), len(stub.ApplicationID), func(i int, index int) error {
		signedTxns[i].Txn.ApplicationID = stub.ApplicationID[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskOnCompletion.iterate(int(stub.TotalTransactionsCount), len(stub.OnCompletion)*2, func(i int, index int) error {
		b, err := getNibble(stub.OnCompletion, index)
		if err != nil {
			return err
		}
		signedTxns[i].Txn.OnCompletion = transactions.OnCompletion(b)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskApplicationArgs.iterate(int(stub.TotalTransactionsCount), len(stub.ApplicationArgs), func(i int, index int) error {
		signedTxns[i].Txn.ApplicationArgs = stub.ApplicationArgs[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAccounts.iterate(int(stub.TotalTransactionsCount), len(stub.Accounts), func(i int, index int) error {
		signedTxns[i].Txn.Accounts = stub.Accounts[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskForeignApps.iterate(int(stub.TotalTransactionsCount), len(stub.ForeignApps), func(i int, index int) error {
		signedTxns[i].Txn.ForeignApps = stub.ForeignApps[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskForeignAssets.iterate(int(stub.TotalTransactionsCount), len(stub.ForeignAssets), func(i int, index int) error {
		signedTxns[i].Txn.ForeignAssets = stub.ForeignAssets[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskLocalNumUint.iterate(int(stub.TotalTransactionsCount), len(stub.LocalNumUint), func(i int, index int) error {
		signedTxns[i].Txn.LocalStateSchema.NumUint = stub.LocalNumUint[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskLocalNumByteSlice.iterate(int(stub.TotalTransactionsCount), len(stub.LocalNumByteSlice), func(i int, index int) error {
		signedTxns[i].Txn.LocalStateSchema.NumByteSlice = stub.LocalNumByteSlice[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskGlobalNumUint.iterate(int(stub.TotalTransactionsCount), len(stub.GlobalNumUint), func(i int, index int) error {
		signedTxns[i].Txn.GlobalStateSchema.NumUint = stub.GlobalNumUint[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskGlobalNumByteSlice.iterate(int(stub.TotalTransactionsCount), len(stub.GlobalNumByteSlice), func(i int, index int) error {
		signedTxns[i].Txn.GlobalStateSchema.NumByteSlice = stub.GlobalNumByteSlice[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskApprovalProgram.iterate(int(stub.TotalTransactionsCount), len(stub.ApprovalProgram), func(i int, index int) error {
		signedTxns[i].Txn.ApprovalProgram = stub.ApprovalProgram[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskClearStateProgram.iterate(int(stub.TotalTransactionsCount), len(stub.ClearStateProgram), func(i int, index int) error {
		signedTxns[i].Txn.ClearStateProgram = stub.ClearStateProgram[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskExtraProgramPages.iterate(int(stub.TotalTransactionsCount), len(stub.ExtraProgramPages), func(i int, index int) error {
		signedTxns[i].Txn.ExtraProgramPages = stub.ExtraProgramPages[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructCompactCertTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskCertRound.iterate(int(stub.TotalTransactionsCount), len(stub.CertRound), func(i int, index int) error {
		signedTxns[i].Txn.CertRound = stub.CertRound[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskCertType.iterate(int(stub.TotalTransactionsCount), len(stub.CertType), func(i int, index int) error {
		signedTxns[i].Txn.CertType = stub.CertType[index]
		return nil
	})
	if err != nil {
		return err
	}
	return stub.reconstructCert(signedTxns)
}

func (stub *txGroupsEncodingStub) reconstructCert(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskSigCommit.iterate(int(stub.TotalTransactionsCount), len(stub.SigCommit)/crypto.DigestSize, func(i int, index int) error {
		return nextSlice(&stub.SigCommit, signedTxns[i].Txn.Cert.SigCommit[:], crypto.DigestSize)
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskSignedWeight.iterate(int(stub.TotalTransactionsCount), len(stub.SignedWeight), func(i int, index int) error {
		signedTxns[i].Txn.Cert.SignedWeight = stub.SignedWeight[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskSigProofs.iterate(int(stub.TotalTransactionsCount), len(stub.SigProofs), func(i int, index int) error {
		signedTxns[i].Txn.Cert.SigProofs = stub.SigProofs[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskPartProofs.iterate(int(stub.TotalTransactionsCount), len(stub.PartProofs), func(i int, index int) error {
		signedTxns[i].Txn.Cert.PartProofs = stub.PartProofs[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskReveals.iterate(int(stub.TotalTransactionsCount), len(stub.Reveals), func(i int, index int) error {
		signedTxns[i].Txn.Cert.Reveals = stub.Reveals[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
