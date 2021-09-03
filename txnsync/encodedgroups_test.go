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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBadBitmask(t *testing.T) {
	partitiontest.PartitionTest(t)

	txnGroups, genesisID, genesisHash, err := txnGroupsData(96)
	require.NoError(t, err)

	var s syncState
	ptg, err := badEncodeTransactionGroups(t, &s, txnGroups, 0)
	require.NoError(t, err)
	require.Equal(t, ptg.CompressionFormat, compressionFormatDeflate)
	_, err = decodeTransactionGroups(ptg, genesisID, genesisHash)
	require.Equal(t, errIndexNotFound, err)
}

// corrupted bitmask may bcause panic during decoding. This test is to make sure it is an error and not a panic
func badEncodeTransactionGroups(t *testing.T, s *syncState, inTxnGroups []pooldata.SignedTxGroup, dataExchangeRate uint64) (packedTransactionGroups, error) {
	txnCount := 0
	for _, txGroup := range inTxnGroups {
		txnCount += len(txGroup.Transactions)
	}
	stub := txGroupsEncodingStub{
		TotalTransactionsCount: uint64(txnCount),
		TransactionGroupCount:  uint64(len(inTxnGroups)),
		TransactionGroupSizes:  make([]byte, 0, len(inTxnGroups)),
	}

	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	index := 0
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) > 1 {
			for _, txn := range txGroup.Transactions {
				err := stub.deconstructSignedTransaction(index, &txn)
				require.NoError(t, err)
				index++
			}
			stub.TransactionGroupSizes = append(stub.TransactionGroupSizes, byte(len(txGroup.Transactions)-1))
		}
	}
	compactNibblesArray(&stub.TransactionGroupSizes)
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) == 1 {
			for _, txn := range txGroup.Transactions {
				if !txn.Txn.Group.MsgIsZero() {
					if len(stub.BitmaskGroup) == 0 {
						stub.BitmaskGroup = make(bitmask, bitmaskLen)
					}
					stub.BitmaskGroup.setBit(index)
				}
				err := stub.deconstructSignedTransaction(index, &txn)
				require.NoError(t, err)
				index++
			}
		}
	}

	stub.BitmaskAuthAddr.trimBitmask(int(stub.TotalTransactionsCount))
	stub.finishDeconstructMsigs()
	stub.finishDeconstructLsigs()
	stub.BitmaskSig.trimBitmask(int(stub.TotalTransactionsCount))

	stub.finishDeconstructTxType()
	// corrupted bitmask
	stub.BitmaskTxType = make(bitmask, bitmaskLen*10)
	stub.BitmaskTxType.setBit(bitmaskLen*10 - 10)

	stub.finishDeconstructTxnHeader()
	stub.finishDeconstructKeyregTxnFields()
	stub.finishDeconstructPaymentTxnFields()
	stub.finishDeconstructAssetConfigTxnFields()
	stub.finishDeconstructAssetTransferTxnFields()
	stub.finishDeconstructAssetFreezeTxnFields()
	stub.finishDeconstructApplicationCallTxnFields()
	stub.finishDeconstructCompactCertTxnFields()

	encoded := stub.MarshalMsg(getMessageBuffer())

	// check if time saved by compression: estimatedDeflateCompressionGains * len(msg) / dataExchangeRate
	// is greater than by time spent during compression: len(msg) / estimatedDeflateCompressionSpeed
	if len(encoded) > minEncodedTransactionGroupsCompressionThreshold && float32(dataExchangeRate) < (estimatedDeflateCompressionGains*estimatedDeflateCompressionSpeed) {
		compressedBytes, compressionFormat := s.compressTransactionGroupsBytes(encoded)
		if compressionFormat != compressionFormatNone {
			packedGroups := packedTransactionGroups{
				Bytes:                compressedBytes,
				CompressionFormat:    compressionFormat,
				LenDecompressedBytes: uint64(len(encoded)),
			}
			releaseMessageBuffer(encoded)
			return packedGroups, nil
		}
	}

	return packedTransactionGroups{
		Bytes:             encoded,
		CompressionFormat: compressionFormatNone,
	}, nil
}
