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

const latestCacheSize = 512

// blockHeaderCache is a wrapper for all block header cache mechanisms used within the Ledger.
type blockHeadersCache struct {
	lruCache           heapLRUCache
	latestHeadersCache latestBlockHeadersCache
}

type latestBlockHeadersCache struct {
	blockHeaders [latestCacheSize]bookkeeping.BlockHeader
	mutex        deadlock.RWMutex
}

func (c *blockHeadersCache) Get(round basics.Round) (blockHeader bookkeeping.BlockHeader, exists bool) {
	// check latestHeadersCache first
	blockHeader, exists = c.latestHeadersCache.Get(round)
	if exists {
		return
	}

	// if not found in latestHeadersCache, check LRUCache
	value, exists := c.lruCache.Get(round)
	blockHeader = value.(bookkeeping.BlockHeader)

	return
}

func (c *blockHeadersCache) Put(round basics.Round, blockHeader bookkeeping.BlockHeader) {
	c.latestHeadersCache.Put(round, blockHeader)
	c.lruCache.Put(round, blockHeader)
}

func (c *latestBlockHeadersCache) Get(round basics.Round) (blockHeader bookkeeping.BlockHeader, exists bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	idx := round % latestCacheSize
	blockHeader = c.blockHeaders[idx]
	if blockHeader.Round == 0 || blockHeader.Round != round { // blockHeader is empty or not request round
		exists = false
	} else {
		exists = true
	}

	return
}

func (c *latestBlockHeadersCache) Put(round basics.Round, blockHeader bookkeeping.BlockHeader) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	idx := round % latestCacheSize
	cachedHdr := c.blockHeaders[idx]
	if round > cachedHdr.Round { // provided blockHeader is more recent than cached one
		c.blockHeaders[idx] = blockHeader
	}
}
