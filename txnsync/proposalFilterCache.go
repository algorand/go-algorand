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
