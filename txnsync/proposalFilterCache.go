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

func (c *proposalFilterCache) insert(proposalBytes []byte) {
	key := crypto.Hash(proposalBytes)
	element, found := c.store[key]
	if found {
		c.orderedMsgs.MoveToBack(element)
	} else {
		element := c.orderedMsgs.PushBack(key)
		c.store[key] = element
		for c.orderedMsgs.Len() > c.limit {
			key := c.orderedMsgs.Front()
			delete(c.store, key.Value.(crypto.Digest))
			c.orderedMsgs.Remove(key)
		}
	}
}

func (c *proposalFilterCache) exists(proposalBytes []byte) bool {
	key := crypto.Hash(proposalBytes)
	_, exists := c.store[key]
	return exists
}
