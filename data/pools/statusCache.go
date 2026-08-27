// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package pools

import (
	"slices"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type statusCacheEntry struct {
	tx    []byte
	txErr string
}

type statusCache struct {
	cur  map[transactions.Txid]statusCacheEntry
	prev map[transactions.Txid]statusCacheEntry
	sz   int
}

func makeStatusCache(sz int) *statusCache {
	sc := &statusCache{
		sz: sz,
	}
	sc.reset()
	return sc
}

func (sc *statusCache) check(txid transactions.Txid) (tx transactions.SignedTxn, txErr string, found bool) {
	ent, found := sc.cur[txid]
	if !found {
		ent, found = sc.prev[txid]
	}
	if !found {
		return
	}

	if _, err := tx.UnmarshalMsg(ent.tx); err != nil {
		logging.Base().Errorf("Error decoding statusCache transaction: %v", err)
		return transactions.SignedTxn{}, "", false
	}
	txErr = ent.txErr
	return
}

func (sc *statusCache) put(tx transactions.SignedTxn, txErr string) {
	if len(sc.cur) >= sc.sz {
		sc.prev = sc.cur
		sc.cur = make(map[transactions.Txid]statusCacheEntry, sc.sz)
	}

	buf := protocol.GetEncodingBuf()
	enc := tx.MarshalMsg(buf.Bytes())
	encoded := slices.Clone(enc) // trim max buf to actual encoded size, and release the buf
	protocol.PutEncodingBuf(buf.Update(enc))

	sc.cur[tx.ID()] = statusCacheEntry{
		tx:    encoded,
		txErr: txErr,
	}
}

func (sc *statusCache) reset() {
	sc.cur = make(map[transactions.Txid]statusCacheEntry, sc.sz)
	sc.prev = nil
}
