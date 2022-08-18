// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledger

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"

	"github.com/algorand/go-deadlock"
)

const latestHeaderCacheSize = 512
const blockHeadersLRUCacheSize = 10

// blockHeaderCache is a wrapper for all block header cache mechanisms used within the Ledger.
type blockHeaderCache struct {
	lruCache          heapLRUCache
	latestHeaderCache latestBlockHeaderCache
}

type latestBlockHeaderCache struct {
	blockHeaders [latestHeaderCacheSize]bookkeeping.BlockHeader
	mutex        deadlock.RWMutex
}

func (c *blockHeaderCache) initialize() {
	c.lruCache.maxEntries = blockHeadersLRUCacheSize
}

func (c *blockHeaderCache) get(round basics.Round) (blockHeader bookkeeping.BlockHeader, exists bool) {
	// check latestHeaderCache first
	blockHeader, exists = c.latestHeaderCache.get(round)
	if exists {
		return
	}

	// if not found in latestHeaderCache, check LRUCache
	value, exists := c.lruCache.Get(round)
	if exists {
		blockHeader = value.(bookkeeping.BlockHeader)
	}

	return
}

func (c *blockHeaderCache) put(blockHeader bookkeeping.BlockHeader) {
	c.latestHeaderCache.put(blockHeader)
	c.lruCache.Put(blockHeader.Round, blockHeader)
}

func (c *latestBlockHeaderCache) get(round basics.Round) (blockHeader bookkeeping.BlockHeader, exists bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	idx := round % latestHeaderCacheSize
	if round == 0 || c.blockHeaders[idx].Round != round { // blockHeader is empty or not requested round
		return bookkeeping.BlockHeader{}, false
	}
	blockHeader = c.blockHeaders[idx]

	return blockHeader, true
}

func (c *latestBlockHeaderCache) put(blockHeader bookkeeping.BlockHeader) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	idx := blockHeader.Round % latestHeaderCacheSize
	if blockHeader.Round > c.blockHeaders[idx].Round { // provided blockHeader is more recent than cached one
		c.blockHeaders[idx] = blockHeader
	}
}
