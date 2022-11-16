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

package data

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

type txidCacheIf interface {
	check(d *crypto.Digest) bool
	put(d *crypto.Digest)
	checkAndPut(d *crypto.Digest) bool
	len() int
}

func TestTxHandlerTxidCache(t *testing.T) {
	const size = 20
	impls := []txidCacheIf{
		makeTxidCache(size),
		makeTxidCacheSyncMap(size),
	}
	for _, cache := range impls {
		t.Run(fmt.Sprintf("%T", cache), func(t *testing.T) {
			require.Zero(t, cache.len())

			// add some unique random
			var ds [size]crypto.Digest
			for i := 0; i < size; i++ {
				crypto.RandBytes([]byte(ds[i][:]))
				exist := cache.checkAndPut(&ds[i])
				require.False(t, exist)
			}

			require.Equal(t, size, cache.len())

			// check they exist
			for i := 0; i < size; i++ {
				exist := cache.check(&ds[i])
				require.True(t, exist)
			}

			// try to re-add, ensure not added
			for i := 0; i < size; i++ {
				exist := cache.checkAndPut(&ds[i])
				require.True(t, exist)
			}

			require.Equal(t, size, cache.len())

			// add some more and ensure capacity switch
			var ds2 [size]crypto.Digest
			for i := 0; i < size; i++ {
				crypto.RandBytes(ds2[i][:])
				exist := cache.checkAndPut(&ds2[i])
				require.False(t, exist)
			}

			require.Equal(t, 2*size, cache.len())

			var d crypto.Digest
			crypto.RandBytes(d[:])
			exist := cache.checkAndPut(&d)
			require.False(t, exist)

			require.Equal(t, size+1, cache.len())

		})
	}
}
