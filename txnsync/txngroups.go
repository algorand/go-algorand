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
	"github.com/algorand/go-algorand/util/compress"
)

// Deflate performance constants measured by BenchmarkTxnGroupCompression
const estimatedDeflateCompressionSpeed = 121123260.0 // bytes per second of how fast Deflate compresses data
const estimatedDeflateCompressionGains = 0.32        // fraction of data reduced by Deflate on txnsync msgs

const minEncodedTransactionGroupsCompressionThreshold = 1000

const maxCompressionRatio = 20 // don't allow more than 95% compression

func (s *syncState) encodeTransactionGroups(inTxnGroups []transactions.SignedTxGroup, dataExchangeRate uint64) (packedTransactionGroups, error) {
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
					return packedTransactionGroups{}, fmt.Errorf("failed to encodeTransactionGroups: %w", err)
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
					stub.BitmaskGroup.setBit(index)
				}
				if err := stub.deconstructSignedTransactions(index, &txn); err != nil {
					return packedTransactionGroups{}, fmt.Errorf("failed to encodeTransactionGroups: %w", err)
				}
				index++
			}
		}
	}
	stub.finishDeconstructSignedTransactions()

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

func (s *syncState) compressTransactionGroupsBytes(data []byte) ([]byte, byte) {
	b := getMessageBuffer()
	if cap(b) < len(data) {
		releaseMessageBuffer(b)
		b = make([]byte, 0, len(data))
	}
	_, out, err := compress.Compress(data, b, 1)
	if err != nil {
		if errors.Is(err, compress.ErrShortBuffer) {
			s.log.Infof("compression had negative effect, made message bigger: original msg length: %d", len(data))
		} else {
			s.log.Warnf("failed to compress %d bytes txnsync msg: %v", len(data), err)
		}
		releaseMessageBuffer(b)
		return data, compressionFormatNone
	}
	if len(data) > len(out)*maxCompressionRatio {
		s.log.Infof("compression exceeded compression ratio: compressed data len: %d", len(out))
		releaseMessageBuffer(b)
		return data, compressionFormatNone
	}
	return out, compressionFormatDeflate
}

func decodeTransactionGroups(ptg packedTransactionGroups, genesisID string, genesisHash crypto.Digest) (txnGroups []transactions.SignedTxGroup, err error) {
	data := ptg.Bytes
	if len(data) == 0 {
		return nil, nil
	}

	switch ptg.CompressionFormat {
	case compressionFormatNone:
	case compressionFormatDeflate:
		data, err = decompressTransactionGroupsBytes(data, ptg.LenDecompressedBytes)
		if err != nil {
			return
		}
		defer releaseMessageBuffer(data)
	default:
		return nil, fmt.Errorf("invalid compressionFormat, %d", ptg.CompressionFormat)
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

func decompressTransactionGroupsBytes(data []byte, lenDecompressedBytes uint64) (decoded []byte, err error) {
	compressionRatio := lenDecompressedBytes / uint64(len(data)) // data should have been compressed between 0 and 95%
	if lenDecompressedBytes > maxEncodedTransactionGroupBytes || compressionRatio <= 0 || compressionRatio >= maxCompressionRatio {
		return nil, fmt.Errorf("invalid lenDecompressedBytes: %d, lenCompressedBytes: %d", lenDecompressedBytes, len(data))
	}

	out := getMessageBuffer()
	if uint64(cap(out)) < lenDecompressedBytes {
		releaseMessageBuffer(out)
		out = make([]byte, 0, lenDecompressedBytes)
	}

	decoded, err = compress.Decompress(data, out)
	if err != nil {
		releaseMessageBuffer(out)
		decoded = nil
		return
	}
	if uint64(len(decoded)) != lenDecompressedBytes {
		releaseMessageBuffer(out)
		decoded = nil
		return nil, fmt.Errorf("lenDecompressedBytes didn't match: expected %d, actual %d", lenDecompressedBytes, len(decoded))
	}
	return
}

func releaseEncodedTransactionGroups(buffer []byte) {
	if buffer == nil {
		return
	}

	releaseMessageBuffer(buffer)
}
