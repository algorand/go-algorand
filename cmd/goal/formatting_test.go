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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnicodePrintable(t *testing.T) {
	testUnicodePrintableStrings := []struct {
		testString      string
		isPrintable     bool
		printableString string
	}{
		{"abc", true, "abc"},
		{"", true, ""},
		{"אבג", true, "אבג"},
		{"\u001b[31mABC\u001b[0m", false, "[31mABC[0m"},
		{"ab\nc", false, "abc"},
	}
	for _, testElement := range testUnicodePrintableStrings {
		isPrintable, printableString := unicodePrintable(testElement.testString)
		require.Equalf(t, testElement.isPrintable, isPrintable, "test string:%s", testElement.testString)
		require.Equalf(t, testElement.printableString, printableString, "test string:%s", testElement.testString)
	}
}
