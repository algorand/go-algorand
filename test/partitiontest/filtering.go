// Copyright (C) 2019-2025 Algorand, Inc.
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

package partitiontest

import (
	"encoding/json"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
)

// testTiming represents the duration of a test
type testTiming struct {
	testName string
	duration float64
}

// partitionState holds the computed partition assignments for a given partition count
type partitionState struct {
	partitionCount int
	assignments    map[string]int
}

// partitionAssignments caches the computed partition assignments
var (
	assignmentsLock sync.Mutex
	assignmentsCache *partitionState
)

// PartitionTest checks if the current partition should run this test, and skips it if not.
func PartitionTest(t testing.TB) {
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

	// Get or compute partition assignments for this partition count
	assignmentsLock.Lock()
	if assignmentsCache == nil || assignmentsCache.partitionCount != partitions {
		assignmentsCache = &partitionState{
			partitionCount: partitions,
			assignments:    computePartitionAssignments(partitions),
		}
	}
	assignments := assignmentsCache.assignments
	assignmentsLock.Unlock()

	name := t.Name()
	_, file, _, _ := runtime.Caller(1)

	// Try to find a timing-based assignment by test name
	idx, found := assignments[name]
	if !found {
		// Fall back to hash-based partitioning using file:name as before
		testKey := file + ":" + name
		nameNumber := stringToUint64(testKey)
		idx = int(nameNumber % uint64(partitions))
	}

	if idx != partitionID {
		t.Skipf("skipping %s due to partitioning: assigned to %d but I am %d of %d", name, idx, partitionID, partitions)
	}
}

// computePartitionAssignments uses timing data to compute partition assignments using greedy bin-packing.
// Falls back to hash-based partitioning for tests without timing data.
func computePartitionAssignments(partitions int) map[string]int {
	timings := loadTestTimings()
	if len(timings) == 0 {
		// No timing data available, return empty map to use hash-based fallback
		return make(map[string]int)
	}

	// Sort tests by duration (largest first) for greedy bin-packing
	sort.Slice(timings, func(i, j int) bool {
		return timings[i].duration > timings[j].duration
	})

	// Initialize partition bins with their total time
	partitionTimes := make([]float64, partitions)
	assignments := make(map[string]int)

	// Greedy bin-packing: assign each test to the partition with the smallest total time
	for _, timing := range timings {
		// Find partition with minimum total time
		minPartition := 0
		minTime := partitionTimes[0]
		for p := 1; p < partitions; p++ {
			if partitionTimes[p] < minTime {
				minTime = partitionTimes[p]
				minPartition = p
			}
		}

		// Assign test to this partition
		assignments[timing.testName] = minPartition
		partitionTimes[minPartition] += timing.duration
	}

	return assignments
}

// loadTestTimings loads test timing data from JSON files in the results directory
func loadTestTimings() []testTiming {
	// Check for custom timing file path
	timingPath := os.Getenv("PARTITION_TIMING_PATH")
	if timingPath == "" {
		// Default to results directory
		timingPath = "results"
	}

	var timings []testTiming
	seenTests := make(map[string]float64)

	// Walk through the timing path to find all testresults.json files
	err := filepath.Walk(timingPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}
		if info.IsDir() || filepath.Base(path) != "testresults.json" {
			return nil
		}

		// Parse the JSON file
		file, err := os.Open(path)
		if err != nil {
			return nil // Skip files we can't open
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		for {
			var entry struct {
				Action  string  `json:"Action"`
				Package string  `json:"Package"`
				Test    string  `json:"Test"`
				Elapsed float64 `json:"Elapsed"`
			}

			if err := decoder.Decode(&entry); err != nil {
				break // End of file or parse error
			}

			// Only consider "pass" entries with elapsed time and test names
			if entry.Action == "pass" && entry.Test != "" && entry.Elapsed > 0 {
				// Aggregate test durations across multiple runs (take max to be conservative)
				if existingDuration, exists := seenTests[entry.Test]; exists {
					if entry.Elapsed > existingDuration {
						seenTests[entry.Test] = entry.Elapsed
					}
				} else {
					seenTests[entry.Test] = entry.Elapsed
				}
			}
		}

		return nil
	})

	if err != nil {
		// If we can't walk the directory, return empty timings
		return nil
	}

	// Convert map to slice
	for testName, duration := range seenTests {
		timings = append(timings, testTiming{
			testName: testName,
			duration: duration,
		})
	}

	return timings
}

func stringToUint64(str string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(str))
	return h.Sum64()
}
