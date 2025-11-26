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

package test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// getCodecTag extracts the base name from a codec tag, ignoring any additional parameters
func getCodecTag(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("codec")
	if !ok {
		return ""
	}
	// Split by comma and take the first part (the name)
	return strings.Split(tag, ",")[0]
}

// getJSONTag extracts the json tag name
func getJSONTag(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	return strings.Split(tag, ",")[0]
}

// TestGenesisTypeCompatibility verifies that model.Genesis matches the field structure
// of bookkeeping.Genesis, using the codec tags from bookkeeping as the source of truth.
func TestGenesisTypeCompatibility(t *testing.T) {
	partitiontest.PartitionTest(t)
	// Test Genesis struct compatibility
	verifyStructCompatibility(t, reflect.TypeFor[bookkeeping.Genesis](), reflect.TypeFor[model.Genesis]())

	// Test GenesisAllocation struct compatibility
	verifyStructCompatibility(t, reflect.TypeFor[bookkeeping.GenesisAllocation](), reflect.TypeFor[model.GenesisAllocation]())
}

// isStructOrPtrToStruct returns true if the type is a struct or pointer to struct
func isStructOrPtrToStruct(typ reflect.Type) bool {
	if typ.Kind() == reflect.Struct {
		return true
	}
	if typ.Kind() == reflect.Ptr && typ.Elem().Kind() == reflect.Struct {
		return true
	}
	return false
}

// verifyStructCompatibility checks that modelType has json tags matching the codec tags of bkType
func verifyStructCompatibility(t *testing.T, bkType, modelType reflect.Type) {
	t.Logf("Verifying compatibility between %s and %s", bkType.Name(), modelType.Name())

	if !isStructOrPtrToStruct(bkType) {
		t.Logf("Skipping non-struct type %v", bkType)
		return
	}

	if bkType.Kind() == reflect.Ptr {
		bkType = bkType.Elem()
	}
	if modelType.Kind() == reflect.Ptr {
		modelType = modelType.Elem()
	}

	// Build map of expected tags from bookkeeping type
	expectedFields := make(map[string]reflect.Type) // map[codec_tag]field_type
	for i := 0; i < bkType.NumField(); i++ {
		field := bkType.Field(i)
		if tag := getCodecTag(field); tag != "" {
			expectedFields[tag] = field.Type

			// If this is a struct field and the corresponding model field is also a struct,
			// recursively verify its fields
			if isStructOrPtrToStruct(field.Type) {
				modelField := getMatchingField(t, modelType, tag)
				if isStructOrPtrToStruct(modelField.Type) {
					t.Logf("Recursively checking field %s", field.Name)
					verifyStructCompatibility(t, field.Type, modelField.Type)
				}
			}
		}
	}

	// Build map of actual tags from model type
	actualFields := make(map[string]reflect.Type) // map[json_tag]field_type
	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)
		if tag := getJSONTag(field); tag != "" {
			actualFields[tag] = field.Type
		}
	}

	// Verify each expected tag exists in the model
	for tag, expectedType := range expectedFields {
		actualType, exists := actualFields[tag]
		require.True(t, exists, "%s: model type missing field for codec tag %q",
			modelType.Name(), tag)

		// For non-struct fields, verify type compatibility
		if !isStructOrPtrToStruct(expectedType) {
			t.Logf("Verifying type compatibility for field %s: expected %v, got %v", tag, expectedType, actualType)
			verifyTypeCompatibility(t, expectedType, actualType, tag)
		}

		t.Logf("Field verified - tag: %s", tag)
	}

	// Verify no extra tags in model that aren't in bookkeeping
	for jsonTag := range actualFields {
		_, exists := expectedFields[jsonTag]
		require.True(t, exists, "%s: model type has extra field with json tag %q that doesn't exist in bookkeeping",
			modelType.Name(), jsonTag)
	}
}

// getMatchingField finds a field in the given type that has a json tag matching the given tag
func getMatchingField(t *testing.T, typ reflect.Type, tag string) reflect.StructField {
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if jsonTag := getJSONTag(field); jsonTag == tag {
			return field
		}
	}
	t.Fatalf("Could not find field with json tag %q in type %s", tag, typ.Name())
	return reflect.StructField{} // never reached
}

// verifyTypeCompatibility checks if two types are compatible for serialization
func verifyTypeCompatibility(t *testing.T, bkType, modelType reflect.Type, tag string) {
	switch modelType.Kind() {
	case reflect.String:
		// Special case: if the model uses string for byte slice or protocol types, that's okay
		switch {
		case bkType.Kind() == reflect.Slice && bkType.Elem().Kind() == reflect.Uint8:
			return
		case strings.HasPrefix(bkType.String(), "protocol."):
			return
		}

	case reflect.Uint64:
		// Special case: We represent all numeric types as uint64
		switch {
		case bkType.Kind() == reflect.Uint64,
			bkType.Kind() == reflect.Int64:
			return
		case bkType.String() == "basics.MicroAlgos",
			bkType.String() == "basics.Status",
			bkType.String() == "basics.Round":
			return
		}

	case reflect.Int:
		// Special case: Simple integer is fine for basics.Status which is a
		// byte.  You might think that we should also allow bkType to be an int
		// here, and that makes some sense, but we don't use simple ints in
		// go-algorand, so it seems more likely to indicate a bug somewhere.
		switch {
		case bkType.String() == "basics.Status":
			return
		}

	case reflect.Ptr:
		switch modelType.Elem().Kind() {
		case reflect.String:
			// Special case: if the model uses *string for string or crypto types, that's okay
			switch {
			case bkType.Kind() == reflect.String:
				return
			case bkType.String() == "crypto.OneTimeSignatureVerifier",
				bkType.String() == "merklesignature.Commitment",
				bkType.String() == "crypto.VRFVerifier",
				bkType.String() == "crypto.VrfPubkey",
				bkType.String() == "protocol.ConsensusVersion",
				bkType.String() == "protocol.NetworkID":
				return
			}

		case reflect.Bool:
			// Special case: if the model uses *bool for bool, that's okay
			if bkType.Kind() == reflect.Bool {
				return
			}

		case reflect.Uint64:
			// Special case: We represent all numeric types as uint64
			switch {
			case bkType.Kind() == reflect.Uint64,
				bkType.Kind() == reflect.Int64:
				return
			case bkType.String() == "basics.MicroAlgos",
				bkType.String() == "basics.Status",
				bkType.String() == "basics.Round":
				return
			}

		default:
			// For other pointer types, check the underlying type
			if bkType.Kind() == reflect.Ptr {
				verifyTypeCompatibility(t, bkType.Elem(), modelType.Elem(), tag)
				return
			}
		}

	case reflect.Slice:
		// For slice types, check the element type
		if bkType.Kind() == reflect.Slice {
			// Special case: allow []model.GenesisAllocation for []bookkeeping.GenesisAllocation
			if strings.HasSuffix(bkType.Elem().String(), "GenesisAllocation") &&
				strings.HasSuffix(modelType.Elem().String(), "GenesisAllocation") {
				return
			}
			verifyTypeCompatibility(t, bkType.Elem(), modelType.Elem(), tag)
			return
		}
	}

	// For all other cases, types should match exactly
	if bkType != modelType {
		t.Errorf("Type mismatch for field %q: expected %v, got %v", tag, bkType, modelType)
	}
}
