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

package db

// Pair represents two accessors - read and write
type Pair struct {
	Rdb Accessor
	Wdb Accessor
}

// Close the read and write accessors
func (p Pair) Close() {
	if p.Rdb.Handle != nil {
		p.Rdb.Close()
	}
	if p.Wdb.Handle != nil {
		p.Wdb.Close()
	}
}

// OpenPair opens the filename with both reading and writing accessors.
func OpenPair(filename string, memory bool) (p Pair, err error) {
	p.Rdb, err = MakeAccessor(filename, true, memory)
	if err != nil {
		return
	}

	p.Wdb, err = MakeAccessor(filename, false, memory)
	if err != nil {
		p.Rdb.Close()
		return
	}

	return
}
