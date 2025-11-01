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

package testing

import (
	"reflect"
	"testing"
)

// RoundTrip checks that converting an A -> B -> A gives the original value.
// Returns true if equal, false otherwise.
func RoundTrip[A any, B any](t *testing.T, a A, toB func(A) B, toA func(B) A) bool {
	b := toB(a)
	a2 := toA(b)
	return reflect.DeepEqual(a, a2)
}
