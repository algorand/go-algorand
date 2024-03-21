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

package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPrint(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testcases := []struct {
		Input    interface{}
		expected string
	}{
		{
			Input:    "string",
			expected: "string",
		},
		{
			Input:    uint64(1234),
			expected: "1234",
		},
		{
			Input:    int64(-1234),
			expected: "-1234",
		},
		{
			Input:    true,
			expected: "true",
		},
		{
			Input:    time.Second,
			expected: "1s",
		},
	}
	for i, tc := range testcases {
		tc := tc
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			ret, err := serializeObjectProperty(tc, "Input")
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, ret)
		})
	}
}
