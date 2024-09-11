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

package ledger

import (
	"bytes"

	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// onlineTopHeap implements heap.Interface for tracking top N online accounts.
type onlineTopHeap struct {
	accts []*ledgercore.OnlineAccount
}

// Len implements sort.Interface
func (h *onlineTopHeap) Len() int {
	return len(h.accts)
}

// Less implements sort.Interface
func (h *onlineTopHeap) Less(i, j int) bool {
	// For the heap, "less" means the element is returned earlier by Pop(),
	// so we actually implement "greater-than" here.
	ibal := h.accts[i].NormalizedOnlineBalance
	jbal := h.accts[j].NormalizedOnlineBalance

	if ibal > jbal {
		return true
	}
	if ibal < jbal {
		return false
	}

	bcmp := bytes.Compare(h.accts[i].Address[:], h.accts[j].Address[:])
	return bcmp > 0
}

// Swap implements sort.Interface
func (h *onlineTopHeap) Swap(i, j int) {
	h.accts[i], h.accts[j] = h.accts[j], h.accts[i]
}

// Push implements heap.Interface
func (h *onlineTopHeap) Push(x interface{}) {
	h.accts = append(h.accts, x.(*ledgercore.OnlineAccount))
}

// Pop implements heap.Interface
func (h *onlineTopHeap) Pop() interface{} {
	res := h.accts[len(h.accts)-1]
	h.accts[len(h.accts)-1] = nil
	h.accts = h.accts[:len(h.accts)-1]
	return res
}
