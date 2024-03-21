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

package sqlitedriver

import (
	"database/sql"

	"github.com/algorand/go-algorand/util/db"
)

//msgp:ignore MerkleCommitter
type merkleCommitter struct {
	e          db.Executable
	deleteStmt *sql.Stmt
	insertStmt *sql.Stmt
	selectStmt *sql.Stmt
}

// MakeMerkleCommitter creates a MerkleCommitter object that implements the merkletrie.Committer interface allowing storing and loading
// merkletrie pages from a sqlite database.
func MakeMerkleCommitter(e db.Executable, staging bool) (mc *merkleCommitter, err error) {
	mc = &merkleCommitter{e: e}
	accountHashesTable := "accounthashes"
	if staging {
		accountHashesTable = "catchpointaccounthashes"
	}
	mc.deleteStmt, err = e.Prepare("DELETE FROM " + accountHashesTable + " WHERE id=?")
	if err != nil {
		return nil, err
	}
	mc.insertStmt, err = e.Prepare("INSERT OR REPLACE INTO " + accountHashesTable + "(id, data) VALUES(?, ?)")
	if err != nil {
		return nil, err
	}
	mc.selectStmt, err = e.Prepare("SELECT data FROM " + accountHashesTable + " WHERE id = ?")
	if err != nil {
		return nil, err
	}
	return mc, nil
}

// StorePage is the merkletrie.Committer interface implementation, stores a single page in a sqlite database table.
func (mc *merkleCommitter) StorePage(page uint64, content []byte) error {
	if len(content) == 0 {
		_, err := mc.deleteStmt.Exec(page)
		return err
	}
	_, err := mc.insertStmt.Exec(page, content)
	return err
}

// LoadPage is the merkletrie.Committer interface implementation, load a single page from a sqlite database table.
func (mc *merkleCommitter) LoadPage(page uint64) (content []byte, err error) {
	err = mc.selectStmt.QueryRow(page).Scan(&content)
	if err == sql.ErrNoRows {
		content = nil
		err = nil
		return
	} else if err != nil {
		return nil, err
	}
	return content, nil
}
