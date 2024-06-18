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

package protocol

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
)

// TestHashIDPrefix checks if any HashID const declared in hash.go is a prefix of another.
func TestHashIDPrefix(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	values := getConstValues(t, "hash.go", "HashID", false)
	for i, v1 := range values {
		for j, v2 := range values {
			if i == j {
				continue
			}
			assert.False(t, strings.HasPrefix(v1, v2), "HashID %s is a prefix of %s", v2, v1)
		}
	}
}
