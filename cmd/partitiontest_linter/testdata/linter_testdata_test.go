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

/*
This file is input file for analyzer_test.go
That's why we are using relative path in import below
It is also why we named this file _test.go, since linter only looks at files that end in _test.go
*/

package linter_testdata

import (
	"testing"

	"../../../test/partitiontest"
)

func notTestFunction() {}

func notTestFunctionWithWrongParam(t string) {}

func notTestFunctionWithCorrectParam(t *testing.T) {}

func notTestFunctionWithCorrectParamCorrectLine(t *testing.T) {
	partitiontest.PartitionTest(t)
}

func notTestFunctionWithCorrectParamWrongLine(t *testing.T) {
	println("something")
}

func TestFunctionWithCorrectParamOnly(t *testing.T) {} // want "function is missing partitiontest.PartitionTest"

func TestFunctionWithCorrectParamCorrectLine(t *testing.T) {
	partitiontest.PartitionTest(t)
}

func TestFunctionWithCorrectParamBadLine(t *testing.T) { // want "function is missing partitiontest.PartitionTest"
	println("something")
}

func TestFunctionWithDifferentName(n *testing.T) {
	partitiontest.PartitionTest(n)
}

func TestFunctionWithCorrectParamNotFirstCorrectLine(t *testing.T) {
	println("something")
	partitiontest.PartitionTest(t)
}

func TestFunctionWithCorrectParamNotLastCorrectLine(t *testing.T) {
	partitiontest.PartitionTest(t)
	println("something")
}

func TestFunctionWithCorrectParamMiddleCorrectLine(t *testing.T) {
	println("something")
	partitiontest.PartitionTest(t)
	println("something")
}
