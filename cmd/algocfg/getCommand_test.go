// Copyright (C) 2019-2022 Algorand, Inc.
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
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPrint(t *testing.T) {
	partitiontest.PartitionTest(t)

	testcases := []struct {
		input    interface{}
		expected string
	}{
		{
			input:    uint64(1234),
			expected: "1234",
		},
		{
			input:    int64(-1234),
			expected: "-1234",
		},
		{
			input:    true,
			expected: "true",
		},
		{
			input:    time.Second,
			expected: "1s",
		},
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%v", tc.input)
			assert.Equal(t, tc.expected, buf.String())
		})
	}
}
