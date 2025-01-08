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

// Empty returns true if the set is empty.
func (s Set[T]) Empty() bool {
	return len(s) == 0
}

// Contains checks the membership of an element in the set.
func (s Set[T]) Contains(elem T) (exists bool) {
	_, exists = s[elem]
	return
}

// Union constructs a new set, containing all elements from the given sets. nil
// is never returned
func Union[T comparable](sets ...Set[T]) Set[T] {
	union := make(Set[T])
	for _, set := range sets {
		for elem := range set {
			union.Add(elem)
		}
	}
	return union
}

// Intersection constructs a new set, containing all elements that appear in all
// given sets. nil is never returned. Intersection of no sets is an empty set
// because that seems more useful, regardless of your very reasonable arguments
// otherwise.
func Intersection[T comparable](sets ...Set[T]) Set[T] {
	var intersection = make(Set[T])
	if len(sets) == 0 {
		return intersection
	}
	for elem := range sets[0] {
		inAll := true
		for _, set := range sets[1:] {
			if _, exists := set[elem]; !exists {
				inAll = false
				break
			}
		}
		if inAll {
			intersection.Add(elem)
		}
	}
	return intersection
}
