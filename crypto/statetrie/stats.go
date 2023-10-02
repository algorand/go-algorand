// Copyright (C) 2019-2023 Algorand, Inc.
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

package statetrie

import (
	"fmt"
)

// Helper class for keeping track of stats on the trie.

type triestats struct {
	dbsets         int
	dbgets         int
	dbdeletes      int
	cryptohashes   int
	makeleaves     int
	makeextensions int
	makebranches   int
	makepanodes    int
	makebanodes    int
	newrootnode    int
	addnode        int
	delnode        int
	getnode        int
	evictions      int
}

var stats triestats

func (s triestats) diff(s1 triestats) triestats {
	return triestats{
		dbsets:         s.dbsets - s1.dbsets,
		dbgets:         s.dbgets - s1.dbgets,
		dbdeletes:      s.dbdeletes - s1.dbdeletes,
		cryptohashes:   s.cryptohashes - s1.cryptohashes,
		makeleaves:     s.makeleaves - s1.makeleaves,
		makeextensions: s.makeextensions - s1.makeextensions,
		makebranches:   s.makebranches - s1.makebranches,
		makepanodes:    s.makepanodes - s1.makepanodes,
		makebanodes:    s.makebanodes - s1.makebanodes,
		newrootnode:    s.newrootnode - s1.newrootnode,
		addnode:        s.addnode - s1.addnode,
		delnode:        s.delnode - s1.delnode,
		getnode:        s.getnode - s1.getnode,
		evictions:      s.evictions - s1.evictions,
	}
}
func (s triestats) String() string {
	return fmt.Sprintf("dbsets: %d, dbgets: %d, dbdeletes: %d, cryptohashes: %d, makeleaves: %d, makeextensions: %d, makebranches: %d, makepanodes: %d, makebanodes: %d, newrootnode: %d, addnode: %d, delnode: %d, getnode: %d, evictions: %d",
		s.dbsets, s.dbgets, s.dbdeletes, s.cryptohashes, s.makeleaves, s.makeextensions, s.makebranches, s.makepanodes, s.makebanodes, s.newrootnode, s.addnode, s.delnode, s.getnode, s.evictions)
}
