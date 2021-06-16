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
	"sync"

	"github.com/algorand/go-algorand/data/transactions"
)

const messageBufferDefaultInitialSize = 10240

// msgBuffersPool holds temporary byte slice buffers used for encoding messages.
var msgBuffersPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, messageBufferDefaultInitialSize)
	},
}

// GetEncodingBuf returns a byte slice that can be used for encoding a
// temporary message.  The byte slice has zero length but potentially
// non-zero capacity.  The caller gets full ownership of the byte slice,
// but is encouraged to return it using releaseMessageBuffer().
func getMessageBuffer() []byte {
	return msgBuffersPool.Get().([]byte)[:0]
}

// releaseMessageBuffer places a byte slice into the pool of temporary buffers
// for encoding.  The caller gives up ownership of the byte slice when
// passing it to releaseMessageBuffer().
func releaseMessageBuffer(s []byte) {
	msgBuffersPool.Put(s)
}

// txidSlicePool holds temporary byte slice buffers used for encoding messages.
var txidSlicePool = sync.Pool{}

// getTxIDSliceBuffer returns a slice that can be used for storing a
// list of transaction IDs. The slice has zero length but potentially
// non-zero capacity.  The caller gets full ownership of the slice,
// but is encouraged to return it using releaseTxIDSliceBuffer().
func getTxIDSliceBuffer(minSize int) []transactions.Txid {
	alloc := txidSlicePool.Get()
	if alloc == nil {
		return make([]transactions.Txid, 0, minSize)
	}
	buf := alloc.([]transactions.Txid)[:0]
	if cap(buf) >= minSize {
		return buf
	}
	txidSlicePool.Put(alloc)
	return make([]transactions.Txid, 0, minSize)
}

// releaseTxIDSliceBuffer places a slice into the pool of buffers
// for storage.  The caller gives up ownership of the byte slice when
// passing it to releaseMessageBuffer().
func releaseTxIDSliceBuffer(s []transactions.Txid) {
	if cap(s) > 0 {
		txidSlicePool.Put(s)
	}
}
