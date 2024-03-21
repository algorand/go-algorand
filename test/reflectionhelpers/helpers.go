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

package reflectionhelpers

import (
	"fmt"
	"reflect"
	"strings"

	"golang.org/x/exp/slices"
)

// TypeSegmentKind is a enum for the types of TypeSegment
type TypeSegmentKind int

const (
	// FieldSegmentKind represents a referenced field type on a Go type
	FieldSegmentKind TypeSegmentKind = iota
	// MapKeySegmentKind represents the key type of a Go map
	MapKeySegmentKind
	// ValueSegmentKind represents the value type of a Go map, array, or slice
	ValueSegmentKind
)

// TypeSegment represents a single segment in a TypePath. This segment is a single reference from
// one reflect.Type to another reflect.Type.
type TypeSegment struct {
	Kind TypeSegmentKind
	// If Kind is FieldSegmentKind, then FieldName contains the name of the referenced field.
	FieldName string
}

func (s TypeSegment) String() string {
	switch s.Kind {
	case FieldSegmentKind:
		return "field " + s.FieldName
	case MapKeySegmentKind:
		return "map_key"
	case ValueSegmentKind:
		return "value"
	default:
		panic(fmt.Sprintf("Unknown TypeSegmentKind: %v", s.Kind))
	}
}

// TypePath represents a path of referenced types starting from an origin reflect.Type. Note the
// origin reflect.Type is not contained in TypePath.
type TypePath []TypeSegment

// Clone creates a deep copy of a TypePath
func (p TypePath) Clone() TypePath {
	return slices.Clone(p)
}

// AddMapKey adds a map key segment to a TypePath. The modification is done using append, so this
// action may mutate the input TypePath.
//
// NOTE: There is no guarantee that this constructed TypePath is valid. Use ResolveType to verify
// that after construction.
func (p TypePath) AddMapKey() TypePath {
	return append(p, TypeSegment{Kind: MapKeySegmentKind})
}

// AddValue adds a map, array, or slice value segment to a TypePath. The modification is done using
// append, so this action may mutate the input TypePath.
//
// NOTE: There is no guarantee that this constructed TypePath is valid. Use ResolveType to verify
// that after construction.
func (p TypePath) AddValue() TypePath {
	return append(p, TypeSegment{Kind: ValueSegmentKind})
}

// AddField adds a named field segment to a TypePath. The modification is done using append, so this
// action may mutate the input TypePath.
//
// NOTE: There is no guarantee that this constructed TypePath is valid. Use ResolveType to verify
// that after construction.
func (p TypePath) AddField(fieldName string) TypePath {
	return append(p, TypeSegment{Kind: FieldSegmentKind, FieldName: fieldName})
}

// ResolveType follows the TypePath to its end and returns the reflect.Type of the last referenced
// type. The initial type, base, must be provided, since TypePath is a relative path. If the
// TypePath represents a chain of type references that is not valid, this will panic.
func (p TypePath) ResolveType(base reflect.Type) reflect.Type {
	resolved := base
	for _, segment := range p {
		switch segment.Kind {
		case MapKeySegmentKind:
			resolved = resolved.Key()
		case ValueSegmentKind:
			resolved = resolved.Elem()
		case FieldSegmentKind:
			fieldType, ok := resolved.FieldByName(segment.FieldName)
			if !ok {
				panic(fmt.Errorf("Type '%v' does not have the field '%s'", resolved, segment.FieldName))
			}
			resolved = fieldType.Type
		default:
			panic(fmt.Errorf("Unexpected segment kind: %v", segment.Kind))
		}
	}
	return resolved
}

// ResolveValues follows the TypePath to its end and returns a slice of all the values at that
// location. The initial value, base, must have the type of the origin reflect.Type this TypePath
// was made for. If the TypePath represents a chain of type references that is not valid, this will
// panic.
//
// This function returns a slice of values because some segments may map to many values. Field
// segments always map to a single value, but map key and (map, slice, or array) value segments may
// map to zero or more values, depending on the value of the input argument.
func (p TypePath) ResolveValues(base reflect.Value) []reflect.Value {
	if len(p) == 0 {
		return nil
	}

	var resolved []reflect.Value

	segment := p[0]
	switch segment.Kind {
	case MapKeySegmentKind:
		resolved = base.MapKeys()
	case ValueSegmentKind:
		switch base.Kind() {
		case reflect.Map:
			iter := base.MapRange()
			for iter.Next() {
				resolved = append(resolved, iter.Value())
			}
		case reflect.Array, reflect.Slice:
			for i := 0; i < base.Len(); i++ {
				resolved = append(resolved, base.Index(i))
			}
		default:
			panic(fmt.Errorf("Unexpected kind %v", base.Kind()))
		}
	case FieldSegmentKind:
		_, ok := base.Type().FieldByName(segment.FieldName)
		if !ok {
			panic(fmt.Errorf("Type '%v' does not have the field '%s'", base.Type(), segment.FieldName))
		}
		resolved = []reflect.Value{base.FieldByName(segment.FieldName)}
	default:
		panic(fmt.Errorf("Unexpected segment kind: %v", segment.Kind))
	}

	if len(p) > 1 {
		rest := p[1:]
		intermediateResolved := resolved
		resolved = nil

		for _, ir := range intermediateResolved {
			resolvedToEnd := rest.ResolveValues(ir)
			resolved = append(resolved, resolvedToEnd...)
		}
	}

	return resolved
}

// Equals returns true if and only if the input TypePath has the exact same segments as this
// TypePath.
func (p TypePath) Equals(other TypePath) bool {
	return slices.Equal(p, other)
}

func (p TypePath) String() string {
	segments := make([]string, len(p))
	for i, s := range p {
		segments[i] = s.String()
	}
	return strings.Join(segments, "->")
}

// ReferencedTypesIterationAction represents an action to be taken on each iteration of
// IterateReferencedTypes. This function should return true to go deeper into the current type's
// referenced types, or false to look no deeper at the current type's referenced types.
//
// NOTE: The TypePath argument this function receives is passed by reference. If you intend to save
// this value for use after this function returns, you MUST call the Clone() method to keep a copy
// of the TypePath as you currently see it.
type ReferencedTypesIterationAction func(path TypePath, stack []reflect.Type) bool

// IterateReferencedTypes recursively iterates over all referenced types from an initial
// reflect.Type. The ReferencedTypesIterationAction argument is called for each referenced type.
// This argument can also control whether the iteration goes deeper into a type or not.
func IterateReferencedTypes(start reflect.Type, action ReferencedTypesIterationAction) {
	seen := make(map[reflect.Type]bool)
	iterateReferencedTypes(seen, nil, []reflect.Type{start}, action)
}

func iterateReferencedTypes(seen map[reflect.Type]bool, path TypePath, typeStack []reflect.Type, action ReferencedTypesIterationAction) {
	currentType := typeStack[len(typeStack)-1]

	if _, seenType := seen[currentType]; seenType {
		return
	}

	if !action(path, typeStack) {
		// if action returns false, don't visit its children
		return
	}

	// add currentType to seen set, to avoid infinite recursion if currentType references itself
	seen[currentType] = true

	// after currentType's children are visited, "forget" the type, so we can examine it again if needed
	// if this didn't happen, we would ignore any additional occurrences of this type
	defer delete(seen, currentType)

	switch currentType.Kind() {
	case reflect.Map:
		newPath := path.AddMapKey()
		newStack := append(typeStack, currentType.Key())
		iterateReferencedTypes(seen, newPath, newStack, action)
		fallthrough
	case reflect.Array, reflect.Slice, reflect.Ptr:
		newPath := path.AddValue()
		newStack := append(typeStack, currentType.Elem())
		iterateReferencedTypes(seen, newPath, newStack, action)
	case reflect.Struct:
		for i := 0; i < currentType.NumField(); i++ {
			field := currentType.Field(i)
			newPath := path.AddField(field.Name)
			newStack := append(typeStack, field.Type)
			iterateReferencedTypes(seen, newPath, newStack, action)
		}
	}
}
