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

package roundtrip

import (
	"reflect"
	"testing"
)

// Check verifies that converting from A -> B -> A yields the original value.
// It tests the provided example value, then tests all NearZeros variants (setting one field at a time).
// NearZeros is tested first because failures clearly identify which field is problematic.
func Check[A any, B any](t *testing.T, example A, toB func(A) B, toA func(B) A) {
	t.Helper()

	// Test the provided example
	if !checkOne(t, example, toB, toA) {
		t.Fatalf("Round-trip failed for provided example: %+v", example)
	}

	// Test NearZeros (one test per field) - comprehensive and deterministic
	// This comes first because failures clearly show which field is the problem
	nearZeroValues := NearZeros(t, example)
	for i, nzA := range nearZeroValues {
		if !checkOne(t, nzA, toB, toA) {
			t.Fatalf("Round-trip failed for NearZero variant %d: %+v", i, nzA)
		}
	}
}

func checkOne[A any, B any](t *testing.T, a A, toB func(A) B, toA func(B) A) bool {
	t.Helper()
	b := toB(a)
	a2 := toA(b)
	if !reflect.DeepEqual(a, a2) {
		t.Logf("Round-trip mismatch:\n  Original: %+v\n  After:    %+v", a, a2)
		return false
	}
	return true
}
