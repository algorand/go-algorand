// Copyright (C) 2019-2024 Algorand, Inc.
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

// Set is a type alias for map with empty struct{}, where keys are comparable
// We don't attempt to move even forward for the generics,
// for keys being comparable should be sufficient for most cases.
// (Though we actually want compare byte slices, but seems not achievable at this moment)
type Set[T comparable] map[T]struct{}

// Add adds variate number of elements to the set.
func (s Set[T]) Add(elems ...T) Set[T] {
	for _, elem := range elems {
		s[elem] = struct{}{}
	}
	return s
}

// MakeSet constructs a set instance directly from elements.
func MakeSet[T comparable](elems ...T) Set[T] {
	return make(Set[T]).Add(elems...)
}

// Contains checks the membership of an element in the set.
func (s Set[T]) Contains(elem T) (exists bool) {
	_, exists = s[elem]
	return
}
