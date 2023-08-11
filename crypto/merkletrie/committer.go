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

package merkletrie

import "golang.org/x/exp/slices"

// Committer is the interface supporting serializing tries into persistent storage.
type Committer interface {
	StorePage(page uint64, content []byte) error
	LoadPage(page uint64) (content []byte, err error)
}

const (
	inMemoryCommitterPageSize = int64(512)
)

// InMemoryCommitter is a fully functional in-memory committer, supporting
// persistence of pages.
type InMemoryCommitter struct {
	memStore map[uint64][]byte
}

// StorePage stores a single page in an in-memory persistence.
func (mc *InMemoryCommitter) StorePage(page uint64, content []byte) error {
	if mc.memStore == nil {
		mc.memStore = make(map[uint64][]byte)
	}
	if content == nil {
		delete(mc.memStore, page)
	} else {
		mc.memStore[page] = slices.Clone(content)
	}
	return nil
}

// LoadPage load a single page from an in-memory persistence.
func (mc *InMemoryCommitter) LoadPage(page uint64) (content []byte, err error) {
	if mc.memStore == nil {
		mc.memStore = make(map[uint64][]byte)
	}
	content = mc.memStore[page]
	return content, nil
}
