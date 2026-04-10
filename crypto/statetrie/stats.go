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

package statetrie

import (
	"fmt"
	"sync/atomic"
)

// Helper class for keeping track of stats on the trie.

type triestats struct {
	dbsets         atomic.Uint64
	dbgets         atomic.Uint64
	dbdeletes      atomic.Uint64
	cryptohashes   atomic.Uint64
	makeleaves     atomic.Uint64
	makeextensions atomic.Uint64
	makebranches   atomic.Uint64
	makepanodes    atomic.Uint64
	makebanodes    atomic.Uint64
	newrootnode    atomic.Uint64
	addnode        atomic.Uint64
	delnode        atomic.Uint64
	getnode        atomic.Uint64
	evictions      atomic.Uint64
}

var stats triestats

func (s *triestats) diff(s1 *triestats) triestats {
	var result triestats
	result.dbsets.Store(s.dbsets.Load() - s1.dbsets.Load())
	result.dbgets.Store(s.dbgets.Load() - s1.dbgets.Load())
	result.dbdeletes.Store(s.dbdeletes.Load() - s1.dbdeletes.Load())
	result.cryptohashes.Store(s.cryptohashes.Load() - s1.cryptohashes.Load())
	result.makeleaves.Store(s.makeleaves.Load() - s1.makeleaves.Load())
	result.makeextensions.Store(s.makeextensions.Load() - s1.makeextensions.Load())
	result.makebranches.Store(s.makebranches.Load() - s1.makebranches.Load())
	result.makepanodes.Store(s.makepanodes.Load() - s1.makepanodes.Load())
	result.makebanodes.Store(s.makebanodes.Load() - s1.makebanodes.Load())
	result.newrootnode.Store(s.newrootnode.Load() - s1.newrootnode.Load())
	result.addnode.Store(s.addnode.Load() - s1.addnode.Load())
	result.delnode.Store(s.delnode.Load() - s1.delnode.Load())
	result.getnode.Store(s.getnode.Load() - s1.getnode.Load())
	result.evictions.Store(s.evictions.Load() - s1.evictions.Load())
	return result
}

func (s *triestats) String() string {
	return fmt.Sprintf("dbsets: %d, dbgets: %d, dbdeletes: %d, cryptohashes: %d, makeleaves: %d, makeextensions: %d, makebranches: %d, makepanodes: %d, makebanodes: %d, newrootnode: %d, addnode: %d, delnode: %d, getnode: %d, evictions: %d",
		s.dbsets.Load(), s.dbgets.Load(), s.dbdeletes.Load(), s.cryptohashes.Load(), s.makeleaves.Load(), s.makeextensions.Load(), s.makebranches.Load(), s.makepanodes.Load(), s.makebanodes.Load(), s.newrootnode.Load(), s.addnode.Load(), s.delnode.Load(), s.getnode.Load(), s.evictions.Load())
}
