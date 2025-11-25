// Copyright (C) 2019-2025 Algorand, Inc.
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

package statecommit

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/data/basics"
)

// Key prefixes to distinguish different types of state in the trie.
const (
	keyPrefixAccount       byte = 'a'
	keyPrefixAssetHolding  byte = 'h'
	keyPrefixAssetParams   byte = 'p'
	keyPrefixAppLocalState byte = 'L'
	keyPrefixAppParams     byte = 'P'
	keyPrefixKvPair        byte = 'k'
)

// EncodeAccountKey returns the trie key for an account's base data.
// Format: [prefix='a'][32-byte address]
func EncodeAccountKey(addr basics.Address) []byte {
	return encodePrefixedKey(keyPrefixAccount, addr[:])
}

// EncodeAssetHoldingKey returns the trie key for an asset holding.
// Format: [prefix='h'][32-byte address][8-byte asset ID]
func EncodeAssetHoldingKey(addr basics.Address, assetID basics.AssetIndex) []byte {
	return encodeResourceKey(keyPrefixAssetHolding, addr, uint64(assetID))
}

// EncodeAssetParamsKey returns the trie key for asset parameters.
// Format: [prefix='p'][32-byte address][8-byte asset ID]
func EncodeAssetParamsKey(addr basics.Address, assetID basics.AssetIndex) []byte {
	return encodeResourceKey(keyPrefixAssetParams, addr, uint64(assetID))
}

// EncodeAppLocalStateKey returns the trie key for app local state.
// Format: [prefix='S'][32-byte address][8-byte app ID]
func EncodeAppLocalStateKey(addr basics.Address, appID basics.AppIndex) []byte {
	return encodeResourceKey(keyPrefixAppLocalState, addr, uint64(appID))
}

// EncodeAppParamsKey returns the trie key for app parameters.
// Format: [prefix='P'][32-byte address][8-byte app ID]
func EncodeAppParamsKey(addr basics.Address, appID basics.AppIndex) []byte {
	return encodeResourceKey(keyPrefixAppParams, addr, uint64(appID))
}

// EncodeKvPairKey returns the trie key for a box storage key-value pair.
// Format: [prefix='k'][variable-length key bytes]
//
// Note: KV keys can vary in length, unlike other key types. The application ID
// is encoded in the key string itself according to the box storage format.
func EncodeKvPairKey(key string) []byte {
	return encodePrefixedKey(keyPrefixKvPair, []byte(key))
}

// encodePrefixedKey creates a key with format: [prefix byte][data bytes]
func encodePrefixedKey(prefix byte, data []byte) []byte {
	key := make([]byte, 1+len(data))
	key[0] = prefix
	copy(key[1:], data)
	return key
}

// encodeResourceKey creates a resource key with format: [prefix byte][32-byte address][8-byte resource ID]
func encodeResourceKey(prefix byte, addr basics.Address, resourceID uint64) []byte {
	key := make([]byte, 1+32+8)
	key[0] = prefix
	copy(key[1:], addr[:])
	binary.BigEndian.PutUint64(key[33:], resourceID)
	return key
}
