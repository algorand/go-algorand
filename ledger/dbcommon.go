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

package ledger

import (
	"github.com/algorand/go-algorand/util/db"
)

type dbPair struct {
	rdb db.Accessor
	wdb db.Accessor
}

func (p dbPair) close() {
	if p.rdb.Handle != nil {
		p.rdb.Close()
	}
	if p.wdb.Handle != nil {
		p.wdb.Close()
	}
}

func dbOpen(filename string, memory bool) (p dbPair, err error) {
	p.rdb, err = db.MakeAccessor(filename, true, memory)
	if err != nil {
		return
	}

	p.wdb, err = db.MakeAccessor(filename, false, memory)
	if err != nil {
		p.rdb.Close()
		return
	}

	return
}
