// Copyright (C) 2019 Algorand, Inc.
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

package auction

// SortUint64 implements sorting by uint64 keys for
// canonical encoding of maps in msgpack format.
//msgp:ignore SortUint64
//msgp:sort uint64 SortUint64
type SortUint64 []uint64

func (a SortUint64) Len() int           { return len(a) }
func (a SortUint64) Less(i, j int) bool { return a[i] < a[j] }
func (a SortUint64) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

//msgp:sort crypto.Digest crypto.SortDigest
