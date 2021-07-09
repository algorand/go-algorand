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

package testpartitioning

import (
	"hash/fnv"
	"os"
	"runtime"
	"strconv"
	"testing"
)

// PartitionTest checks if the current partition should run this test, and skips it if not.
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
	partitionID, err := strconv.Atoi(pid)
	if err != nil {
		return
	}
	name := t.Name()
	_, file, _, _ := runtime.Caller(1) // get filename of caller to PartitionTest
	nameNumber := stringToUint64(file + ":" + name)
	idx := nameNumber%uint64(partitions)
	if idx != uint64(partitionID) {
		t.Skip("skipping due to partitioning, assigned to partition %d", idx)
	}
}

func stringToUint64(str string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(str))
	return h.Sum64()
}
