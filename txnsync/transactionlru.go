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
	"github.com/algorand/go-algorand/data/transactions"
)

// transactionLru keeps the most recently accessed transactions ids, allowing to limit the size of the historical kept transactions.
// implementation is a simple cyclic-buffer with a map to accelerate lookups.
type transactionLru struct {
	size            int
	transactionsIDs []transactions.Txid
	transactionsMap map[transactions.Txid]bool
	oldest          int
}

func makeTransactionLru(size int) *transactionLru {
	return &transactionLru{
		size:            size,
		transactionsIDs: make([]transactions.Txid, size, size),
		transactionsMap: make(map[transactions.Txid]bool, size),
	}
}

func (lru *transactionLru) add(txid transactions.Txid) {
	if lru.transactionsMap[txid] {
		return
	}
	mapLen := len(lru.transactionsMap)
	if mapLen >= lru.size {
		// we reached size, delete the oldest entry.
		delete(lru.transactionsMap, lru.transactionsIDs[lru.oldest])
		lru.transactionsIDs[lru.oldest] = txid
		lru.transactionsMap[txid] = true
		lru.oldest = (lru.oldest + 1) % lru.size
		return
	}
	lru.transactionsIDs[mapLen] = txid
	lru.transactionsMap[txid] = true
}

func (lru *transactionLru) contained(txid transactions.Txid) bool {
	return lru.transactionsMap[txid]
}

func (lru *transactionLru) reset() {
	lru.transactionsMap = make(map[transactions.Txid]bool, lru.size)
	lru.oldest = 0
}
