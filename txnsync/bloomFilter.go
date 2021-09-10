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
	"encoding/binary"
	"errors"
	"math"

	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/util/bloom"
)

// bloomFilterFalsePositiveRate is used as the target false positive rate for the multiHashBloomFilter implementation.
// the xor based bloom filters have their own hard-coded false positive rate, and therefore require no configuration.
const bloomFilterFalsePositiveRate = 0.01

var errInvalidBloomFilterEncoding = errors.New("invalid bloom filter encoding")
var errEncodingBloomFilterFailed = errors.New("encoding bloom filter failed")

//msgp:ignore bloomFilterType
type bloomFilterType byte

const (
	invalidBloomFilter bloomFilterType = iota //nolint:deadcode,varcheck
	multiHashBloomFilter
	xorBloomFilter32
	xorBloomFilter8
)

// transactionsRange helps us to identify a subset of the transaction pool pending transaction groups.
// it's being used as part of an optimization when we're attempting to recreate a bloom filter :
// if the new bloom filter shares the same set of parameters, then the result is expected to be the
// same and therefore the old bloom filter can be used.
type transactionsRange struct {
	firstCounter      uint64
	lastCounter       uint64
	transactionsCount uint64
}

type bloomFilter struct {
	containedTxnsRange transactionsRange

	encoded encodedBloomFilter

	encodedLength int
}

// testableBloomFilter is used for a bloom filters that were received from the network, decoded
// and are ready to be tested against.
type testableBloomFilter struct {
	encodingParams requestParams

	filter bloom.GenericFilter
}

func decodeBloomFilter(enc encodedBloomFilter) (outFilter *testableBloomFilter, err error) {
	outFilter = &testableBloomFilter{
		encodingParams: enc.EncodingParams,
	}
	switch bloomFilterType(enc.BloomFilterType) {
	case multiHashBloomFilter:
		outFilter.filter, err = bloom.UnmarshalBinary(enc.BloomFilter)
	case xorBloomFilter32:
		outFilter.filter = new(bloom.XorFilter)
		err = outFilter.filter.UnmarshalBinary(enc.BloomFilter)
	case xorBloomFilter8:
		outFilter.filter = new(bloom.XorFilter8)
		err = outFilter.filter.UnmarshalBinary(enc.BloomFilter)
	default:
		return nil, errInvalidBloomFilterEncoding
	}

	if err != nil {
		return nil, err
	}
	outFilter.encodingParams = enc.EncodingParams
	return
}

func (bf *bloomFilter) encode(filter bloom.GenericFilter, filterType bloomFilterType) (err error) {
	bf.encoded.BloomFilterType = byte(filterType)
	bf.encoded.BloomFilter, err = filter.MarshalBinary()
	bf.encodedLength = len(bf.encoded.BloomFilter)
	if err != nil || bf.encodedLength == 0 {
		return errEncodingBloomFilterFailed
	}
	// increase the counter for a successful bloom filter encoding
	txsyncEncodedBloomFiltersTotal.Inc(nil)
	return
}

func (bf *bloomFilter) sameParams(other bloomFilter) bool {
	return (bf.encoded.EncodingParams == other.encoded.EncodingParams) &&
		(bf.containedTxnsRange == other.containedTxnsRange)
}

func (bf *testableBloomFilter) test(txID transactions.Txid) bool {
	if bf.encodingParams.Modulator > 1 {
		if txidToUint64(txID)%uint64(bf.encodingParams.Modulator) != uint64(bf.encodingParams.Offset) {
			return false
		}
	}
	return bf.filter.Test(txID[:])
}

func filterFactoryBloom(numEntries int, s *syncState) (filter bloom.GenericFilter, filterType bloomFilterType) {
	shuffler := uint32(s.node.Random(math.MaxUint64))
	sizeBits, numHashes := bloom.Optimal(numEntries, bloomFilterFalsePositiveRate)
	return bloom.New(sizeBits, numHashes, shuffler), multiHashBloomFilter
}

func filterFactoryXor8(numEntries int, s *syncState) (filter bloom.GenericFilter, filterType bloomFilterType) { //nolint:deadcode,unused
	s.xorBuilder.RandomNumberGeneratorSeed = s.node.Random(math.MaxUint64)
	return bloom.NewXor8(numEntries, &s.xorBuilder), xorBloomFilter8
}

func filterFactoryXor32(numEntries int, s *syncState) (filter bloom.GenericFilter, filterType bloomFilterType) {
	s.xorBuilder.RandomNumberGeneratorSeed = s.node.Random(math.MaxUint64)
	return bloom.NewXor(numEntries, &s.xorBuilder), xorBloomFilter32
}

var filterFactory func(int, *syncState) (filter bloom.GenericFilter, filterType bloomFilterType) = filterFactoryXor32

func (s *syncState) makeBloomFilter(encodingParams requestParams, txnGroups []pooldata.SignedTxGroup, excludeTransactions *transactionCache, hintPrevBloomFilter *bloomFilter) (result bloomFilter) {
	result.encoded.EncodingParams = encodingParams
	if encodingParams.Modulator == 0 {
		// we want none.
		return
	}
	if encodingParams.Modulator == 1 && excludeTransactions == nil {
		// we want all.
		if len(txnGroups) > 0 {
			result.containedTxnsRange.firstCounter = txnGroups[0].GroupCounter
			result.containedTxnsRange.lastCounter = txnGroups[len(txnGroups)-1].GroupCounter
			result.containedTxnsRange.transactionsCount = uint64(len(txnGroups))
		} else {
			return
		}

		if hintPrevBloomFilter != nil {
			if result.sameParams(*hintPrevBloomFilter) {
				return *hintPrevBloomFilter
			}
		}

		filter, filterType := filterFactory(len(txnGroups), s)
		for _, group := range txnGroups {
			filter.Set(group.GroupTransactionID[:])
		}
		err := result.encode(filter, filterType)
		if err != nil {
			// fall back to standard bloom filter
			filter, filterType = filterFactoryBloom(len(txnGroups), s)
			for _, group := range txnGroups {
				filter.Set(group.GroupTransactionID[:])
			}
			result.encode(filter, filterType) //nolint:errcheck
			// the error in the above case can be silently ignored.
		}
		return result
	}

	// we want subset.
	result.containedTxnsRange.firstCounter = math.MaxUint64
	filteredTransactionsIDs := getTxIDSliceBuffer(len(txnGroups))
	defer releaseTxIDSliceBuffer(filteredTransactionsIDs)

	for _, group := range txnGroups {
		txID := group.GroupTransactionID
		if txidToUint64(txID)%uint64(encodingParams.Modulator) != uint64(encodingParams.Offset) {
			continue
		}
		if excludeTransactions != nil && excludeTransactions.contained(txID) {
			continue
		}
		filteredTransactionsIDs = append(filteredTransactionsIDs, txID)
		if result.containedTxnsRange.firstCounter == math.MaxUint64 {
			result.containedTxnsRange.firstCounter = group.GroupCounter
		}
		result.containedTxnsRange.lastCounter = group.GroupCounter
	}

	result.containedTxnsRange.transactionsCount = uint64(len(filteredTransactionsIDs))

	if hintPrevBloomFilter != nil {
		if result.sameParams(*hintPrevBloomFilter) {
			return *hintPrevBloomFilter
		}
	}

	if len(filteredTransactionsIDs) == 0 {
		return
	}

	filter, filterType := filterFactory(len(filteredTransactionsIDs), s)

	for _, txid := range filteredTransactionsIDs {
		filter.Set(txid[:])
	}
	err := result.encode(filter, filterType)
	if err != nil {
		// fall back to standard bloom filter
		filter, filterType = filterFactoryBloom(len(filteredTransactionsIDs), s)
		for _, txid := range filteredTransactionsIDs {
			filter.Set(txid[:])
		}
		result.encode(filter, filterType) //nolint:errcheck
		// the error in the above case can be silently ignored.
	}

	return result
}

func txidToUint64(txID transactions.Txid) uint64 {
	return binary.LittleEndian.Uint64(txID[:8])
}
