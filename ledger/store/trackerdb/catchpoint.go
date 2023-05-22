// Copyright (C) 2019-2023 Algorand, Inc.
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
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
)

// TrieMemoryConfig is the memory configuration setup used for the merkle trie.
var TrieMemoryConfig = merkletrie.MemoryConfig{
	NodesCountPerPage:         MerkleCommitterNodesPerPage,
	CachedNodesCount:          TrieCachedNodesCount,
	PageFillFactor:            0.95,
	MaxChildrenPagesThreshold: 64,
}

// MerkleCommitterNodesPerPage controls how many nodes will be stored in a single page
// value was calibrated using BenchmarkCalibrateNodesPerPage
var MerkleCommitterNodesPerPage = int64(116)

// TrieCachedNodesCount defines how many balances trie nodes we would like to keep around in memory.
// value was calibrated using BenchmarkCalibrateCacheNodeSize
var TrieCachedNodesCount = 9000

// NormalizedAccountBalance is a staging area for a catchpoint file account information before it's being added to the catchpoint staging tables.
type NormalizedAccountBalance struct {
	// The public key address to which the account belongs.
	Address basics.Address
	// accountData contains the baseAccountData for that account.
	AccountData BaseAccountData
	// resources is a map, where the key is the creatable index, and the value is the resource data.
	Resources map[basics.CreatableIndex]ResourcesData
	// encodedAccountData contains the baseAccountData encoded bytes that are going to be written to the accountbase table.
	EncodedAccountData []byte
	// accountHashes contains a list of all the hashes that would need to be added to the merkle trie for that account.
	// on V6, we could have multiple hashes, since we have separate account/resource hashes.
	AccountHashes [][]byte
	// normalizedBalance contains the normalized balance for the account.
	NormalizedBalance uint64
	// encodedResources provides the encoded form of the resources
	EncodedResources map[basics.CreatableIndex][]byte
	// partial balance indicates that the original account balance was split into multiple parts in catchpoint creation time
	PartialBalance bool
}
