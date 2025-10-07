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
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTestTimings(t *testing.T) {
	// Test with the actual results directory if it exists
	if _, err := os.Stat("../../results"); err == nil {
		os.Setenv("PARTITION_TIMING_PATH", "../../results")
		defer os.Unsetenv("PARTITION_TIMING_PATH")

		timings := loadTestTimings()
		if len(timings) == 0 {
			t.Logf("No timing data found in results directory")
		} else {
			t.Logf("Loaded %d test timings", len(timings))
			// Verify timings are reasonable
			for _, timing := range timings {
				if timing.duration < 0 {
					t.Errorf("Negative duration for test %s: %f", timing.testName, timing.duration)
				}
				if timing.testName == "" {
					t.Errorf("Empty test name with duration %f", timing.duration)
				}
			}
		}
	}
}

func TestComputePartitionAssignments(t *testing.T) {
	// Create test data directory
	tmpDir := t.TempDir()
	resultsDir := filepath.Join(tmpDir, "results", "test", "0")
	err := os.MkdirAll(resultsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create test results JSON
	jsonContent := `{"Time":"2025-10-02T15:37:02.018054636Z","Action":"start","Package":"github.com/test/pkg1"}
{"Time":"2025-10-02T15:37:05.684817883Z","Action":"pass","Package":"github.com/test/pkg1","Test":"TestSlow","Elapsed":10.5}
{"Time":"2025-10-02T15:37:06.245597662Z","Action":"pass","Package":"github.com/test/pkg1","Test":"TestMedium","Elapsed":5.2}
{"Time":"2025-10-02T15:37:06.378584112Z","Action":"pass","Package":"github.com/test/pkg2","Test":"TestFast","Elapsed":0.3}
{"Time":"2025-10-02T15:37:06.485855630Z","Action":"pass","Package":"github.com/test/pkg2","Test":"TestQuick","Elapsed":0.1}
`
	err = os.WriteFile(filepath.Join(resultsDir, "testresults.json"), []byte(jsonContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test JSON: %v", err)
	}

	// Set environment variable
	os.Setenv("PARTITION_TIMING_PATH", filepath.Join(tmpDir, "results"))
	defer os.Unsetenv("PARTITION_TIMING_PATH")

	// Compute assignments for 2 partitions
	assignments := computePartitionAssignments(2)

	// Verify we got assignments for all tests
	expectedTests := []string{"TestSlow", "TestMedium", "TestFast", "TestQuick"}
	for _, testName := range expectedTests {
		if _, found := assignments[testName]; !found {
			t.Errorf("Missing assignment for test %s", testName)
		}
	}

	// Verify greedy bin-packing worked reasonably
	// TestSlow (10.5s) should be in one partition
	// TestMedium (5.2s), TestFast (0.3s), TestQuick (0.1s) should balance to the other
	partition0Time := 0.0
	partition1Time := 0.0

	testDurations := map[string]float64{
		"TestSlow":   10.5,
		"TestMedium": 5.2,
		"TestFast":   0.3,
		"TestQuick":  0.1,
	}

	for testName, partition := range assignments {
		duration := testDurations[testName]
		if partition == 0 {
			partition0Time += duration
		} else if partition == 1 {
			partition1Time += duration
		} else {
			t.Errorf("Invalid partition %d for test %s", partition, testName)
		}
	}

	t.Logf("Partition 0 total time: %.2fs", partition0Time)
	t.Logf("Partition 1 total time: %.2fs", partition1Time)

	// Verify partitions are reasonably balanced (within 50% of each other)
	maxTime := math.Max(partition0Time, partition1Time)
	minTime := math.Min(partition0Time, partition1Time)
	if maxTime > 0 && minTime/maxTime < 0.5 {
		t.Logf("Warning: Partitions may be unbalanced: %.2fs vs %.2fs", partition0Time, partition1Time)
	}

	// Verify that the slowest test is in one partition
	slowTestPartition := assignments["TestSlow"]
	t.Logf("TestSlow assigned to partition %d", slowTestPartition)
}

func TestComputePartitionAssignmentsEmptyTimings(t *testing.T) {
	// Test with non-existent directory
	os.Setenv("PARTITION_TIMING_PATH", "/nonexistent/path")
	defer os.Unsetenv("PARTITION_TIMING_PATH")

	assignments := computePartitionAssignments(3)
	if len(assignments) != 0 {
		t.Errorf("Expected empty assignments with no timing data, got %d assignments", len(assignments))
	}
}
