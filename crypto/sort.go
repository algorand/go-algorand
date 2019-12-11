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

package crypto

// SortDigest implements sorting by Digest keys for
// canonical encoding of maps in msgpack format.
//msgp:ignore SortDigest
type SortDigest []Digest

func (a SortDigest) Len() int      { return len(a) }
func (a SortDigest) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (a SortDigest) Less(i, j int) bool {
	for pos := 0; pos < len(a[i]); pos++ {
		if a[i][pos] < a[j][pos] {
			return true
		}
		if a[i][pos] > a[j][pos] {
			return false
		}
	}
	return false
}
