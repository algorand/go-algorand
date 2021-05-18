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

func (stub *txGroupsEncodingStub) reconstructSignedTransactions(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) (err error) {
	err = stub.BitmaskSig.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Sig, index, len(crypto.Signature{}))
		if err != nil {
			return err
		}
		copy(signedTxns[i].Sig[:], slice)
		return nil
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
	err = stub.BitmaskAuthAddr.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.AuthAddr, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].AuthAddr[:], slice)
		return nil
	})
	if err != nil {
		return err
	}

	return stub.reconstructTransactions(signedTxns, genesisID, genesisHash)
}

func (stub *txGroupsEncodingStub) reconstructMsigs(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskVersion.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Version) {
			return errDataMissing
		}
		signedTxns[i].Msig.Version = stub.Version[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskThreshold.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Threshold) {
			return errDataMissing
		}
		signedTxns[i].Msig.Threshold = stub.Threshold[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskSubsigs.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Subsigs) {
			return errDataMissing
		}
		signedTxns[i].Msig.Subsigs = stub.Subsigs[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructLsigs(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskLogic.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Logic) {
			return errDataMissing
		}
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
	err = stub.BitmaskLogicArgs.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.LogicArgs) {
			return errDataMissing
		}
		signedTxns[i].Lsig.Args = stub.LogicArgs[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructTransactions(signedTxns []transactions.SignedTxn, genesisID string, genesisHash crypto.Digest) (err error) {
	err = stub.BitmaskTxType.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
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
	err = stub.BitmaskSender.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Sender, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.Sender[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFee.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Fee) {
			return errDataMissing
		}
		signedTxns[i].Txn.Fee = stub.Fee[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFirstValid.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.FirstValid) {
			return errDataMissing
		}
		signedTxns[i].Txn.FirstValid = stub.FirstValid[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskLastValid.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.LastValid) {
			return errDataMissing
		}
		signedTxns[i].Txn.LastValid = stub.LastValid[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskNote.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Note) {
			return errDataMissing
		}
		signedTxns[i].Txn.Note = stub.Note[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskGenesisID.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.GenesisID = genesisID
		return nil
	})
	if err != nil {
		return err
	}
	for i := range signedTxns {
		signedTxns[i].Txn.GenesisHash = genesisHash
	}
	err = stub.BitmaskLease.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Lease, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.Lease[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskRekeyTo.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.RekeyTo, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.RekeyTo[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructKeyregTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskKeys.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
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
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskVoteFirst.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.VoteFirst) {
			return errDataMissing
		}
		signedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskVoteLast.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.VoteLast) {
			return errDataMissing
		}
		signedTxns[i].Txn.VoteLast = stub.VoteLast[index]
		return nil
	})
	if err != nil {
		return err
	}

	err = stub.BitmaskNonparticipation.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.Nonparticipation = true
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructPaymentTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskReceiver.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Receiver, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.Receiver[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAmount.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Amount) {
			return errDataMissing
		}
		signedTxns[i].Txn.Amount = stub.Amount[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskCloseRemainderTo.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.CloseRemainderTo, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.CloseRemainderTo[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetConfigTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskConfigAsset.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.ConfigAsset) {
			return errDataMissing
		}
		signedTxns[i].Txn.ConfigAsset = stub.ConfigAsset[index]
		return nil
	})
	if err != nil {
		return err
	}
	return stub.reconstructAssetParams(signedTxns)
}

func (stub *txGroupsEncodingStub) reconstructAssetParams(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskTotal.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Total) {
			return errDataMissing
		}
		signedTxns[i].Txn.AssetParams.Total = stub.Total[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskDecimals.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Decimals) {
			return errDataMissing
		}
		signedTxns[i].Txn.AssetParams.Decimals = stub.Decimals[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskDefaultFrozen.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.AssetParams.DefaultFrozen = true
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskUnitName.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.UnitName) {
			return errDataMissing
		}
		signedTxns[i].Txn.AssetParams.UnitName = stub.UnitName[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetName.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.AssetName) {
			return errDataMissing
		}
		signedTxns[i].Txn.AssetParams.AssetName = stub.AssetName[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskURL.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.URL) {
			return errDataMissing
		}
		signedTxns[i].Txn.AssetParams.URL = stub.URL[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskMetadataHash.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.MetadataHash, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetParams.MetadataHash[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskManager.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Manager, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetParams.Manager[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskReserve.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Reserve, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetParams.Reserve[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFreeze.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Freeze, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetParams.Freeze[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskClawback.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.Clawback, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetParams.Clawback[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetTransferTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskXferAsset.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.XferAsset) {
			return errDataMissing
		}
		signedTxns[i].Txn.XferAsset = stub.XferAsset[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetAmount.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.AssetAmount) {
			return errDataMissing
		}
		signedTxns[i].Txn.AssetAmount = stub.AssetAmount[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetSender.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.AssetSender, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetSender[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetReceiver.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.AssetReceiver, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetReceiver[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAssetCloseTo.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.AssetCloseTo, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.AssetCloseTo[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructAssetFreezeTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskFreezeAccount.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.FreezeAccount, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.FreezeAccount[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskFreezeAsset.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.FreezeAsset) {
			return errDataMissing
		}
		signedTxns[i].Txn.FreezeAsset = stub.FreezeAsset[index]
		return nil
	})
	if err != nil {
		return err
	}

	err = stub.BitmaskAssetFrozen.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		signedTxns[i].Txn.AssetFrozen = true
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructApplicationCallTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskApplicationID.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.ApplicationID) {
			return errDataMissing
		}
		signedTxns[i].Txn.ApplicationID = stub.ApplicationID[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskOnCompletion.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
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
	err = stub.BitmaskApplicationArgs.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.ApplicationArgs) {
			return errDataMissing
		}
		signedTxns[i].Txn.ApplicationArgs = stub.ApplicationArgs[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskAccounts.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Accounts) {
			return errDataMissing
		}
		signedTxns[i].Txn.Accounts = stub.Accounts[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskForeignApps.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.ForeignApps) {
			return errDataMissing
		}
		signedTxns[i].Txn.ForeignApps = stub.ForeignApps[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskForeignAssets.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.ForeignAssets) {
			return errDataMissing
		}
		signedTxns[i].Txn.ForeignAssets = stub.ForeignAssets[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskLocalNumUint.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.LocalNumUint) {
			return errDataMissing
		}
		signedTxns[i].Txn.LocalStateSchema.NumUint = stub.LocalNumUint[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskLocalNumByteSlice.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.LocalNumByteSlice) {
			return errDataMissing
		}
		signedTxns[i].Txn.LocalStateSchema.NumByteSlice = stub.LocalNumByteSlice[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskGlobalNumUint.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.GlobalNumUint) {
			return errDataMissing
		}
		signedTxns[i].Txn.GlobalStateSchema.NumUint = stub.GlobalNumUint[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskGlobalNumByteSlice.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.GlobalNumByteSlice) {
			return errDataMissing
		}
		signedTxns[i].Txn.GlobalStateSchema.NumByteSlice = stub.GlobalNumByteSlice[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskApprovalProgram.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.ApprovalProgram) {
			return errDataMissing
		}
		signedTxns[i].Txn.ApprovalProgram = stub.ApprovalProgram[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskClearStateProgram.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.ClearStateProgram) {
			return errDataMissing
		}
		signedTxns[i].Txn.ClearStateProgram = stub.ClearStateProgram[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (stub *txGroupsEncodingStub) reconstructCompactCertTxnFields(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskCertRound.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.CertRound) {
			return errDataMissing
		}
		signedTxns[i].Txn.CertRound = stub.CertRound[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskCertType.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.CertType) {
			return errDataMissing
		}
		signedTxns[i].Txn.CertType = stub.CertType[index]
		return nil
	})
	if err != nil {
		return err
	}
	return stub.reconstructCert(signedTxns)
}

func (stub *txGroupsEncodingStub) reconstructCert(signedTxns []transactions.SignedTxn) (err error) {
	err = stub.BitmaskSigCommit.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		slice, err := getSlice(stub.SigCommit, index, crypto.DigestSize)
		if err != nil {
			return err
		}
		copy(signedTxns[i].Txn.Cert.SigCommit[:], slice)
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskSignedWeight.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.SignedWeight) {
			return errDataMissing
		}
		signedTxns[i].Txn.Cert.SignedWeight = stub.SignedWeight[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskSigProofs.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.SigProofs) {
			return errDataMissing
		}
		signedTxns[i].Txn.Cert.SigProofs = stub.SigProofs[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskPartProofs.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.PartProofs) {
			return errDataMissing
		}
		signedTxns[i].Txn.Cert.PartProofs = stub.PartProofs[index]
		return nil
	})
	if err != nil {
		return err
	}
	err = stub.BitmaskReveals.Iterate(int(stub.TotalTransactionsCount), func(i int, index int) error {
		if index >= len(stub.Reveals) {
			return errDataMissing
		}
		signedTxns[i].Txn.Cert.Reveals = stub.Reveals[index]
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
