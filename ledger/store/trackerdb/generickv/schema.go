// Copyright (C) 2019-2024 Algorand, Inc.
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

package generickv

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/data/basics"
)

const (
	prefixLength    = 2
	separatorLength = 1
	addressLength   = 32
	roundLength     = 8
)

const (
	kvPrefixAccount              = "xa"
	kvPrefixResource             = "xb"
	kvPrefixAppKv                = "xc"
	kvPrefixCreatorIndex         = "xd"
	kvPrefixOnlineAccount        = "xe"
	kvPrefixOnlineAccountBalance = "xf"
	kvRoundKey                   = "xg"
	kvSchemaVersionKey           = "xh"
	kvTotalsKey                  = "xi"
	kvTxTail                     = "xj"
	kvOnlineAccountRoundParams   = "xk"
	kvPrefixStateproof           = "xl"
)

const (
	// this is the true separator used in the keys
	separator = '-'
	// this is used as a value greather than the `separator` to get all the keys with a given prefix
	endRangeSeparator = '.'
)

// return the big-endian binary encoding of a uint64
func bigEndianUint64(v uint64) [8]byte {
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], v)
	return ret
}

// return the big-endian binary encoding of a uint32
func bigEndianUint32(v uint32) [4]byte {
	var ret [4]byte
	binary.BigEndian.PutUint32(ret[:], v)
	return ret
}

func accountKey(address basics.Address) [35]byte {
	var key [prefixLength + separatorLength + addressLength]byte

	copy(key[0:], kvPrefixAccount)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], address[:])

	return key
}

func extractResourceAidx(key []byte) basics.CreatableIndex {
	const offset int = prefixLength + separatorLength + addressLength + separatorLength
	aidx64 := binary.BigEndian.Uint64(key[offset : offset+8])
	return basics.CreatableIndex(aidx64)
}

// TODO: [Review] discuss if we want/need to have the address as part of the key
func resourceKey(address basics.Address, aidx basics.CreatableIndex) [44]byte {
	var key [prefixLength + separatorLength + addressLength + separatorLength + 8]byte

	copy(key[0:], kvPrefixResource)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], address[:])
	key[prefixLength+separatorLength+addressLength] = separator

	aidx8 := bigEndianUint64(uint64(aidx))
	copy(key[prefixLength+separatorLength+addressLength+separatorLength:], aidx8[:])

	return key
}

func resourceAddrOnlyRangePrefix(address basics.Address) ([36]byte, [36]byte) {
	var low, high [prefixLength + separatorLength + addressLength + separatorLength]byte

	// low
	copy(low[0:], kvPrefixResource)
	low[prefixLength] = separator
	copy(low[prefixLength+separatorLength:], address[:])
	low[prefixLength+separatorLength+addressLength] = separator
	// high
	copy(high[:], low[:])
	high[prefixLength+separatorLength+addressLength] = endRangeSeparator

	return low, high
}

func appKvKey(kvKey string) []byte {
	key := make([]byte, 0, prefixLength+separatorLength+len(kvKey))

	key = append(key, kvPrefixAppKv...)
	key = append(key, separator)
	key = append(key, kvKey...)

	return key
}

func creatableKey(cidx basics.CreatableIndex) [11]byte {
	var key [prefixLength + separatorLength + 8]byte

	copy(key[0:], kvPrefixCreatorIndex)
	key[prefixLength] = separator

	cidx8 := bigEndianUint64(uint64(cidx))
	copy(key[prefixLength+separatorLength:], cidx8[:])

	return key
}

func creatableMaxRangePrefix(maxIdx basics.CreatableIndex) ([3]byte, [11]byte) {
	var low [prefixLength + separatorLength]byte

	copy(low[0:], kvPrefixCreatorIndex)
	low[prefixLength] = separator

	high := creatableKey(basics.CreatableIndex(uint64(maxIdx) + 1))

	return low, high
}

func extractOnlineAccountAddress(key []byte) (addr basics.Address) {
	const offset int = prefixLength + separatorLength
	copy(addr[:], key[offset:])
	return
}

func extractOnlineAccountRound(key []byte) basics.Round {
	const offset int = prefixLength + separatorLength + addressLength + separatorLength
	u64Rnd := binary.BigEndian.Uint64(key[offset : offset+roundLength])
	return basics.Round(u64Rnd)
}

func onlineAccountKey(address basics.Address, round basics.Round) [44]byte {
	var key [prefixLength + separatorLength + addressLength + separatorLength + 8]byte

	copy(key[0:], kvPrefixOnlineAccount)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], address[:])
	key[prefixLength+separatorLength+addressLength] = separator

	round8 := bigEndianUint64(uint64(round))
	copy(key[prefixLength+separatorLength+addressLength+separatorLength:], round8[:])

	return key
}

func onlineAccountLatestRangePrefix(address basics.Address, round basics.Round) ([36]byte, [44]byte) {
	low := onlineAccountOnlyPartialKey(address)
	high := onlineAccountKey(address, round)
	// inc the last byte to make it inclusive
	high[len(high)-1]++

	return low, high
}

func onlineAccountAddressRangePrefix(address basics.Address) ([36]byte, [36]byte) {
	low := onlineAccountOnlyPartialKey(address)
	high := onlineAccountOnlyPartialKey(address)
	high[prefixLength+separatorLength+addressLength] = endRangeSeparator

	return low, high
}

func onlineAccountFullRangePrefix() ([3]byte, [3]byte) {
	var low, high [prefixLength + separatorLength]byte

	copy(low[0:], kvPrefixOnlineAccount)
	low[prefixLength] = separator

	copy(high[0:], kvPrefixOnlineAccount)
	high[prefixLength] = endRangeSeparator

	return low, high
}

func onlineAccountOnlyPartialKey(address basics.Address) [36]byte {
	var key [prefixLength + separatorLength + addressLength + separatorLength]byte

	copy(key[0:], kvPrefixOnlineAccount)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], address[:])
	key[prefixLength+separatorLength+addressLength] = separator

	return key
}

func extractOnlineAccountBalanceAddress(key []byte) (addr basics.Address) {
	const offset int = prefixLength + separatorLength + 8 + separatorLength + 8 + separatorLength
	copy(addr[:], key[offset:])
	return
}

func extractOnlineAccountBalanceRound(key []byte) basics.Round {
	const offset int = prefixLength + separatorLength
	u64Rnd := binary.BigEndian.Uint64(key[offset : offset+roundLength])
	return basics.Round(u64Rnd)
}

func onlineAccountBalanceKey(round basics.Round, normBalance uint64, address basics.Address) [53]byte {
	var key [prefixLength + separatorLength + 8 + separatorLength + 8 + separatorLength + addressLength]byte

	round8 := bigEndianUint64(uint64(round))
	normBalance8 := bigEndianUint64(normBalance)

	copy(key[0:], kvPrefixOnlineAccountBalance)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], round8[:])
	key[prefixLength+separatorLength+8] = separator
	copy(key[prefixLength+separatorLength+8+separatorLength:], normBalance8[:])
	key[prefixLength+separatorLength+8+separatorLength+8] = separator
	copy(key[prefixLength+separatorLength+8+separatorLength+8+separatorLength:], address[:])

	return key
}

func onlineAccountBalanceForRoundRangePrefix(round basics.Round) ([3]byte, [12]byte) {
	var low [prefixLength + separatorLength]byte
	copy(low[0:], kvPrefixOnlineAccountBalance)
	low[prefixLength] = separator

	var high [prefixLength + separatorLength + 8 + separatorLength]byte

	round8 := bigEndianUint64(uint64(round))

	copy(high[0:], kvPrefixOnlineAccountBalance)
	high[prefixLength] = separator
	copy(high[prefixLength+separatorLength:], round8[:])
	high[prefixLength+separatorLength+8] = endRangeSeparator

	return low, high
}

func roundKey() [2]byte {
	var key [prefixLength]byte
	copy(key[0:], kvRoundKey)
	return key
}

func schemaVersionKey() [2]byte {
	var key [prefixLength]byte
	copy(key[0:], kvSchemaVersionKey)
	return key
}

func totalsKey(catchpointStaging bool) [4]byte {
	var key [prefixLength + separatorLength + 1]byte

	copy(key[0:], kvTotalsKey)
	key[prefixLength] = separator
	if catchpointStaging {
		key[prefixLength+separatorLength] = 's'
	} else {
		key[prefixLength+separatorLength] = 'l'
	}

	return key
}

func extractTxTailRoundPart(key []byte) basics.Round {
	const offset int = prefixLength + separatorLength
	u64Rnd := binary.BigEndian.Uint64(key[offset : offset+roundLength])
	return basics.Round(u64Rnd)
}

func txTailKey(rnd basics.Round) [11]byte {
	var key [prefixLength + separatorLength + 8]byte

	rnd8 := bigEndianUint64(uint64(rnd))

	copy(key[0:], kvTxTail)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], rnd8[:])

	return key
}

func txTailRoundRangePrefix(rnd basics.Round) ([3]byte, [11]byte) {
	var low [prefixLength + separatorLength]byte

	copy(low[0:], kvTxTail)
	low[prefixLength] = separator

	high := txTailKey(rnd)

	return low, high
}

func txTailFullRangePrefix() ([3]byte, [3]byte) {
	var low, high [prefixLength + separatorLength]byte

	copy(low[0:], kvTxTail)
	low[prefixLength] = separator

	copy(high[0:], kvTxTail)
	high[prefixLength] = endRangeSeparator

	return low, high
}

func extractOnlineAccountRoundParamsRoundPart(key []byte) basics.Round {
	const offset int = prefixLength + separatorLength
	u64Rnd := binary.BigEndian.Uint64(key[offset : offset+roundLength])
	return basics.Round(u64Rnd)
}

func onlineAccountRoundParamsKey(rnd basics.Round) [11]byte {
	var key [prefixLength + separatorLength + 8]byte

	rnd8 := bigEndianUint64(uint64(rnd))

	copy(key[0:], kvOnlineAccountRoundParams)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], rnd8[:])

	return key
}

func onlineAccountRoundParamsRoundRangePrefix(rnd basics.Round) ([3]byte, [11]byte) {
	var low [prefixLength + separatorLength]byte

	copy(low[0:], kvOnlineAccountRoundParams)
	low[prefixLength] = separator

	high := onlineAccountRoundParamsKey(rnd)

	return low, high
}

func onlineAccountRoundParamsFullRangePrefix() ([3]byte, [3]byte) {
	var low, high [prefixLength + separatorLength]byte

	copy(low[0:], kvOnlineAccountRoundParams)
	low[prefixLength] = separator

	copy(high[0:], kvOnlineAccountRoundParams)
	high[prefixLength] = endRangeSeparator

	return low, high
}

func stateproofKey(rnd basics.Round) [11]byte {
	var key [prefixLength + separatorLength + 8]byte

	rnd8 := bigEndianUint64(uint64(rnd))

	copy(key[0:], kvPrefixStateproof)
	key[prefixLength] = separator
	copy(key[prefixLength+separatorLength:], rnd8[:])

	return key
}

func stateproofRoundRangePrefix(rnd basics.Round) ([3]byte, [11]byte) {
	var low [prefixLength + separatorLength]byte

	copy(low[0:], kvPrefixStateproof)
	low[prefixLength] = separator

	high := stateproofKey(rnd)

	return low, high
}

func stateproofFullRangePrefix() ([3]byte, [3]byte) {
	var low, high [prefixLength + separatorLength]byte

	copy(low[0:], kvPrefixStateproof)
	low[prefixLength] = separator

	copy(high[0:], kvPrefixStateproof)
	high[prefixLength] = endRangeSeparator

	return low, high
}
