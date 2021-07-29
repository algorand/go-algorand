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
	"container/list"

	"github.com/algorand/go-algorand/crypto"
)

type proposalFilterCache struct {
	store       map[crypto.Digest]*list.Element
	orderedMsgs *list.List
	limit       int
}

func makeProposalFilterCache(limit int) proposalFilterCache {
	c := proposalFilterCache{}
	c.store = make(map[crypto.Digest]*list.Element)
	c.orderedMsgs = list.New()
	c.limit = limit
	return c
}

func (c *proposalFilterCache) insert(proposalHash crypto.Digest) {
	element, found := c.store[proposalHash]
	if found {
		c.orderedMsgs.MoveToBack(element)
	} else {
		element := c.orderedMsgs.PushBack(proposalHash)
		c.store[proposalHash] = element
		for c.orderedMsgs.Len() > c.limit {
			key := c.orderedMsgs.Front()
			delete(c.store, key.Value.(crypto.Digest))
			c.orderedMsgs.Remove(key)
		}
	}
}

func (c *proposalFilterCache) exists(proposalHash crypto.Digest) bool {
	_, exists := c.store[proposalHash]
	return exists
}
