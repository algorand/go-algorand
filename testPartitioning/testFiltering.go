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

package testPartitioning

import (
	"os"
	"strconv"
	"testing"
)

func PartitionTest(t *testing.T) {
	pt, found := os.LookupEnv("PARTITION_TOTAL")
	if !found {
		return
	}
	partitions, err := strconv.Atoi(pt)
	if err != nil {
		return
	}
	pid := os.Getenv("PARTITION_ID")
	partitionId, err := strconv.Atoi(pid)
	if err != nil {
		return
	}
	name := t.Name()
	nameNumber := stringToUint64(name)
	if nameNumber % uint64(partitions) != uint64(partitionId) {
		t.Skip()
	}
}


func stringToUint64(str string) uint64 {
	sum := uint64(0)
	for _, x := range str {
		sum += uint64(x)
	}
	return sum
}
