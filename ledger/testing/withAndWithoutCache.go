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

package testing

import (
	"testing"

	"github.com/algorand/go-algorand/config"
)

// WithAndWithoutLRUCache allows for running a test with ledger LRU cache activated and deactivated.
func WithAndWithoutLRUCache(t *testing.T, cfg config.Local, test func(t *testing.T, cfg config.Local)) {
	cfg.DisableLedgerLRUCache = false
	t.Run("test with lru cache", func(t *testing.T) {
		test(t, cfg)
	})
	cfg.DisableLedgerLRUCache = true
	t.Run("test without lru cache", func(t *testing.T) {
		test(t, cfg)
	})
}
