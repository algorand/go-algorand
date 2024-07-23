// Copyright (C) 2019-2024 Algorand, Inc.
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

package prefetcher

import (
	"testing"
)

func BenchmarkChannelWrites(b *testing.B) {
	b.Run("groupTaskDone", func(b *testing.B) {
		c := make(chan groupTaskDone, b.N)
		for i := 0; i < b.N; i++ {
			c <- groupTaskDone{groupIdx: int64(i)}
		}
	})

	b.Run("int64", func(b *testing.B) {
		c := make(chan int64, b.N)
		for i := int64(0); i < int64(b.N); i++ {
			c <- i
		}
	})
}
