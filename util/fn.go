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

package util

/* Functions inspired by functional languages. Don't go crazy with these. Maybe
   keep it to calls where the fn parameter is named function, rather than
   creating a bunch of anonymous functions. If it's not worth naming, maybe just
   stick to for loops. */

// Map applies a function to each element of the input slice and returns a new
// slice with the transformed elements. A nil slice returns nil.
func Map[X any, Y any](input []X, fn func(X) Y) []Y {
	// preserve nil-ness
	if input == nil {
		return nil
	}

	output := make([]Y, len(input))
	for i := range input {
		output[i] = fn(input[i])
	}
	return output
}
