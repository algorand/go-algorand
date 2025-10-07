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
	"time"
)

// NearZeros takes a sample in order to retrieve its type. It returns a slice of
// the same type in which each element of the slice is the same type as the
// sample, but exactly one field (or sub-field) is set to a non-zero value. It
// returns one example for every sub-field.
func NearZeros(t *testing.T, sample any) []any {
	typ := reflect.TypeOf(sample)
	// If sample is a pointer, work with the underlying type.
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatalf("NearZeros: sample must be a struct, got %s", typ.Kind())
	}
	paths := CollectPaths(typ, []int{})
	var results []any
	for _, path := range paths {
		inst := makeInstanceWithNonZeroField(typ, path)
		results = append(results, inst)
	}
	return results
}

// CollectPaths walks over the struct type (recursively) and returns a slice of
// index paths. Each path points to exactly one (exported) sub-field.
func CollectPaths(typ reflect.Type, prefix []int) [][]int {
	var paths [][]int

	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		// Look through container to the element
		return CollectPaths(typ.Elem(), prefix)

	case reflect.Map:
		// Record as a leaf because we will just make a single entry in the map
		paths = append(paths, prefix)

	case reflect.Struct:
		// Special case: skip known value-type structs like time.Time
		if typ == reflect.TypeOf(time.Time{}) {
			return [][]int{prefix}
		}

		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			newPath := append(append([]int(nil), prefix...), i)
			subPaths := CollectPaths(field.Type, newPath)

			// If recursion yielded deeper paths, use them
			if len(subPaths) > 0 {
				paths = append(paths, subPaths...)
			} else {
				// Otherwise, it's a leaf field — include it
				paths = append(paths, newPath)
			}
		}

	default:
		// Primitive type — record this as a leaf
		paths = append(paths, prefix)
	}

	return paths
}

// makeInstanceWithNonZeroField creates a new instance of type typ and sets exactly one
// field (identified by the fieldPath) to a non-zero value.
func makeInstanceWithNonZeroField(typ reflect.Type, fieldPath []int) any {
	// Create a new instance (as a value, not pointer).
	inst := reflect.New(typ).Elem()
	setFieldToNonZero(inst, fieldPath)
	return inst.Interface()
}

// setFieldToNonZero navigates along the given path in the value v and sets that
// field to a non-zero value. The path is a slice of field indices.
func setFieldToNonZero(v reflect.Value, path []int) {
	// Walk down the struct fields until the final field.
	for i := 0; i < len(path)-1; i++ {
		v = v.Field(path[i])
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		case reflect.Slice:
			if v.Len() == 0 {
				slice := reflect.MakeSlice(v.Type(), 1, 1)
				v.Set(slice)
			}
			v = v.Index(0)
		case reflect.Array:
			v = v.Index(0) // Already allocated, just descend
		}
	}
	// Set the final field to an appropriate non-zero value.
	field := v.Field(path[len(path)-1])
	if field.CanSet() {
		field.Set(exampleValue(field.Type()))
	}
}

// exampleValue returns a non-zero value for a given type.
// For composite types (like arrays), it sets one element.
func exampleValue(t reflect.Type) reflect.Value {
	switch t.Kind() {
	case reflect.String:
		return reflect.ValueOf("non-zero").Convert(t)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflect.ValueOf(1).Convert(t)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflect.ValueOf(1).Convert(t)
	case reflect.Bool:
		return reflect.ValueOf(true).Convert(t)
	case reflect.Float32, reflect.Float64:
		return reflect.ValueOf(1.23).Convert(t)
	case reflect.Ptr:
		// For pointers, allocate a new element and set it to non-zero.
		elem := reflect.New(t.Elem())
		elem.Elem().Set(exampleValue(t.Elem()))
		return elem
	case reflect.Slice:
		// Create a slice with one element.
		slice := reflect.MakeSlice(t, 1, 1)
		slice.Index(0).Set(exampleValue(t.Elem()))
		return slice
	case reflect.Map:
		// Create a map with one key-value pair.
		m := reflect.MakeMap(t)
		// We put in an _empty_ value, because we want to ensure that a map with
		// a value is considered non-zero.  The fact that the value is zero is
		// irrelevant.
		e := reflect.New(t.Elem()).Elem()
		m.SetMapIndex(exampleValue(t.Key()), e)
		return m
	case reflect.Array:
		// Create an array and set the first element.
		arr := reflect.New(t).Elem()
		if t.Len() > 0 {
			arr.Index(0).Set(exampleValue(t.Elem()))
		}
		return arr
	case reflect.Struct:
		// For structs, set the first exported field (if any).
		s := reflect.New(t).Elem()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.IsExported() {
				fv := s.Field(i)
				if fv.CanSet() {
					fv.Set(exampleValue(f.Type))
					break
				}
			}
		}
		return s
	default:
		panic("unable to make a non-zero: " + t.String())
	}
}
