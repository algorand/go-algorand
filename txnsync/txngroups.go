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
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/logging"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// gzip performance constants measured by BenchmarkTxnGroupCompression
const estimatedGzipCompressionSpeed = 23071093.0 // bytes per second of how fast gzip compresses data
const estimatedGzipCompressionGains = 0.32 // fraction of data reduced by gzip on txnsync msgs

const minEncodedTransactionGroupsCompressionThreshold = 1000

func encodeTransactionGroups(inTxnGroups []transactions.SignedTxGroup, dataExchangeRate uint64) ([]byte, byte, error) {
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
				if err := stub.deconstructSignedTransactions(index, &txn); err != nil {
					return nil, 0, fmt.Errorf("failed to encodeTransactionGroups: %w", err)
				}
				index++
			}
			stub.TransactionGroupSizes = append(stub.TransactionGroupSizes, byte(len(txGroup.Transactions)-1))
		}
	}
	stub.TransactionGroupSizes = compactNibblesArray(stub.TransactionGroupSizes)
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) == 1 {
			for _, txn := range txGroup.Transactions {
				if !txn.Txn.Group.MsgIsZero() {
					if len(stub.BitmaskGroup) == 0 {
						stub.BitmaskGroup = make(bitmask, bitmaskLen)
					}
					stub.BitmaskGroup.SetBit(index)
				}
				if err := stub.deconstructSignedTransactions(index, &txn); err != nil {
					return nil, 0, fmt.Errorf("failed to encodeTransactionGroups: %w", err)
				}
				index++
			}
		}
	}
	stub.finishDeconstructSignedTransactions()

	encoded := stub.MarshalMsg(protocol.GetEncodingBuf()[:0])

	// check if time saved by compression: estimatedGzipCompressionGains * len(msg) / dataExchangeRate
	// is greater than by time spent during compression: len(msg) / estimatedGzipCompressionSpeed
	if len(encoded) > minEncodedTransactionGroupsCompressionThreshold && float32(dataExchangeRate) < (estimatedGzipCompressionGains * estimatedGzipCompressionSpeed) {
		compressedBytes, err := compressTransactionGroupsBytes(encoded)
		if err == nil {
			return compressedBytes, 1, nil
		}
		logging.Base().Warnf("failed to compress txnsync msg: %v", err)
	}

	return encoded, 0, nil
}

func compressTransactionGroupsBytes(data []byte) ([]byte, error) {
	b := make([]byte, 0, len(data))
	buf := bytes.NewBuffer(b)
	zw := gzip.NewWriter(buf)

	if _, err := zw.Write(data); err != nil {
		return nil, fmt.Errorf("error gzip compressing data: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("error gzip compressing data: %w", err)
	}
	return buf.Bytes(), nil
}

func decodeTransactionGroups(data []byte, compressionFormat byte, genesisID string, genesisHash crypto.Digest) (txnGroups []transactions.SignedTxGroup, err error) {
	if len(data) == 0 {
		return nil, nil
	}

	if compressionFormat == 1 {
		data, err = decompressTransactionGroupsBytes(data)
		if err != nil {
			return
		}
	}

	if compressionFormat > 1 {
		return nil, fmt.Errorf("invalid compressionFormat, %v", compressionFormat)
	}

	var stub txGroupsEncodingStub
	_, err = stub.UnmarshalMsg(data)
	if err != nil {
		return nil, err
	}

	if stub.TransactionGroupCount > maxEncodedTransactionGroup {
		return nil, errors.New("invalid TransactionGroupCount")
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

func decompressTransactionGroupsBytes(data []byte) (decoded []byte, err error){
	zr, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("error gzip decompressing data: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error gzip decompressing data: %w", err)
	}
	return buf.Bytes(), nil
}

func releaseEncodedTransactionGroups(buffer []byte) {
	if buffer == nil {
		return
	}

	protocol.PutEncodingBuf(buffer[:0])
}
