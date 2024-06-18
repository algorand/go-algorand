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

package trackerdb

import (
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

// HashKind enumerates the possible data types hashed into a catchpoint merkle
// trie. Each merkle trie hash includes the HashKind byte at a known-offset.
// By encoding HashKind at a known-offset, it's possible for hash readers to
// disambiguate the hashed resource.
//
//go:generate stringer -type=HashKind
//msgp:ignore HashKind
type HashKind byte

// Defines known kinds of hashes. Changing an enum ordinal value is a
// breaking change.
const (
	AccountHK HashKind = iota
	AssetHK
	AppHK
	KvHK
)

// HashKindEncodingIndex defines the []byte offset where the hash kind is
// encoded.
const HashKindEncodingIndex = 4

// AccountHashBuilder calculates the hash key used for the trie by combining the account address and the account data
func AccountHashBuilder(addr basics.Address, accountData basics.AccountData, encodedAccountData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, rewards := 3, accountData.RewardsBase; i >= 0; i, rewards = i-1, rewards>>8 {
		// the following takes the rewards & 255 -> hash[i]
		hash[i] = byte(rewards)
	}
	entryHash := crypto.Hash(append(addr[:], encodedAccountData[:]...))
	copy(hash[4:], entryHash[:])
	return hash[:]
}

// AccountHashBuilderV6 calculates the hash key used for the trie by combining the account address and the account data
func AccountHashBuilderV6(addr basics.Address, accountData *BaseAccountData, encodedAccountData []byte) []byte {
	hashIntPrefix := accountData.UpdateRound
	if hashIntPrefix == 0 {
		hashIntPrefix = accountData.RewardsBase
	}
	hash := hashBufV6(hashIntPrefix, AccountHK)
	// write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.

	prehash := make([]byte, crypto.DigestSize+len(encodedAccountData))
	copy(prehash[:], addr[:])
	copy(prehash[crypto.DigestSize:], encodedAccountData[:])

	return finishV6(hash, prehash)
}

// ResourcesHashBuilderV6 calculates the hash key used for the trie by combining the creatable's resource data and its index
func ResourcesHashBuilderV6(rd *ResourcesData, addr basics.Address, cidx basics.CreatableIndex, updateRound uint64, encodedResourceData []byte) ([]byte, error) {
	hk, err := rdGetCreatableHashKind(rd, addr, cidx)
	if err != nil {
		return nil, err
	}

	hash := hashBufV6(updateRound, hk)

	prehash := make([]byte, 8+crypto.DigestSize+len(encodedResourceData))
	copy(prehash[:], addr[:])
	binary.LittleEndian.PutUint64(prehash[crypto.DigestSize:], uint64(cidx))
	copy(prehash[crypto.DigestSize+8:], encodedResourceData[:])

	return finishV6(hash, prehash), nil
}

func rdGetCreatableHashKind(rd *ResourcesData, a basics.Address, ci basics.CreatableIndex) (HashKind, error) {
	if rd.IsAsset() {
		return AssetHK, nil
	} else if rd.IsApp() {
		return AppHK, nil
	}
	return AccountHK, fmt.Errorf("unknown creatable for addr %s, aidx %d, data %v", a.String(), ci, rd)
}

// KvHashBuilderV6 calculates the hash key used for the trie by combining the key and value
func KvHashBuilderV6(key string, value []byte) []byte {
	hash := hashBufV6(0, KvHK)

	prehash := make([]byte, len(key)+len(value))
	copy(prehash[:], key)
	copy(prehash[len(key):], value)

	return finishV6(hash, prehash)
}

func hashBufV6(affinity uint64, kind HashKind) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// write out the lowest 32 bits of the affinity value. This should improve
	// the caching of the trie by allowing recent updates to be in-cache, and
	// "older" nodes will be left alone.
	for i, prefix := 3, affinity; i >= 0; i, prefix = i-1, prefix>>8 {
		// the following takes the prefix & 255 -> hash[i]
		hash[i] = byte(prefix)
	}
	hash[HashKindEncodingIndex] = byte(kind)
	return hash
}

func finishV6(v6hash []byte, prehash []byte) []byte {
	entryHash := crypto.Hash(prehash)
	copy(v6hash[5:], entryHash[1:])
	return v6hash[:]

}
