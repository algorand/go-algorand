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

package agreement

// A proposalTable stores proposals which need to be authenticated
// after their prior votes have been processed.
type proposalTable struct {
	Pending     map[int]*messageEvent
	PendingNext int
}

// push adds a proposal to the proposalTable.
func (t *proposalTable) push(e *messageEvent) int {
	t.PendingNext++
	if t.Pending == nil {
		t.Pending = make(map[int]*messageEvent)
	}
	t.Pending[t.PendingNext] = e
	return t.PendingNext
}

// pop takes a proposal from the proposalTable.
func (t *proposalTable) pop(taskIndex int) *messageEvent {
	res := t.Pending[taskIndex]
	delete(t.Pending, taskIndex)
	return res
}
