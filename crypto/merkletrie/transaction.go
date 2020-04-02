// Copyright (C) 2019-2020 Algorand, Inc.
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

package merkletrie

import (
	"errors"
)

type transactionOperation byte

const (
	txOpAdd transactionOperation = iota
	txOpDelete
)

var errTransactionRollbackFailed = errors.New("unable to rollback merkle tree operation")

// Transaction is used as a way to allow the merkle trie user to perfofrm series of operations
// on the trie while allowing hi/her to rollback the changes. Transactions are not thread-safe,
// and only a single transaction is allowed at any given time. Moreover, a transaction that is not
// complete ( by calling to Rollback/Commit ), will default to the Commit behaviour.
type Transaction struct {
	mt                 *Trie
	log                []loggedOperation
	previousCommitter  Committer
	previousRoot       storedNodeIdentifier
	previousNextNodeID storedNodeIdentifier
}

type loggedOperation struct {
	txOp transactionOperation
	hash []byte
}

func makeTransaction(mt *Trie, committer Committer) *Transaction {
	return &Transaction{
		mt:                 mt,
		previousCommitter:  mt.SetCommitter(committer),
		previousRoot:       mt.root,
		previousNextNodeID: mt.nextNodeID,
	}
}

// Delete deletes the given hash to the trie, if such element exists.
// if no such element exists, return false
func (t *Transaction) Delete(d []byte) (deleted bool, err error) {
	deleted, err = t.mt.Delete(d)
	if deleted {
		t.log = append([]loggedOperation{loggedOperation{txOp: txOpDelete, hash: d}}, t.log...)
	}
	return
}

// Add adds the given hash to the trie.
// returns false if the item already exists.
func (t *Transaction) Add(d []byte) (added bool, err error) {
	added, err = t.mt.Add(d)
	if added {
		t.log = append(t.log, loggedOperation{txOp: txOpAdd, hash: d})
	}
	return added, err
}

// Commit commits the applied Delete/Add operations and returns the number of applied changes.
func (t *Transaction) Commit() int {
	defer t.mt.SetCommitter(t.previousCommitter)
	return len(t.log)
}

// Rollback rolls back the pending operations, and returns the number of operations that were rolled back.
func (t *Transaction) Rollback() (int, error) {
	defer t.mt.SetCommitter(t.previousCommitter)
	undoRollingBack := func(startIdx int) {
		var rollbackErr error
		for j := startIdx; j >= 0 && rollbackErr == nil; j-- {
			switch t.log[j].txOp {
			case txOpAdd:
				_, rollbackErr = t.mt.Add(t.log[j].hash)
			case txOpDelete:
				_, rollbackErr = t.mt.Delete(t.log[j].hash)
			}
		}
		if rollbackErr != nil {
			// we were not able to roll back due to committer persistance issues.
			t.mt.reset(t.previousRoot, t.previousNextNodeID)
		}
	}
	for i, op := range t.log {
		switch op.txOp {
		case txOpAdd:
			deleted, err := t.mt.Delete(op.hash)
			if err != nil || !deleted {
				undoRollingBack(i - 1)
				if err != nil {
					return i, err
				}
				return i, errTransactionRollbackFailed
			}
		case txOpDelete:
			added, err := t.mt.Add(op.hash)
			if err != nil || !added {
				undoRollingBack(i - 1)
				if err != nil {
					return i, err
				}
				return i, errTransactionRollbackFailed
			}
		}
	}
	l := len(t.log)
	t.log = nil
	return l, nil
}
