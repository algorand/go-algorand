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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/test/reflectionhelpers"
	"github.com/stretchr/testify/assert"
)

func TestAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	accountDataType := reflect.TypeFor[basics.AccountData]()

	referencedAccountTypes := make([]reflectionhelpers.TypePath, 0)
	reflectionhelpers.IterateReferencedTypes(accountDataType, func(path reflectionhelpers.TypePath, stack []reflect.Type) bool {
		if len(path) == 0 {
			// Ignore the top-level basics.AccountData type
			return true
		}
		stackTop := stack[len(stack)-1]
		if path[len(path)-1].FieldName == "_struct" && stackTop == reflect.TypeOf(struct{}{}) {
			// Ignore the informational _struct field
			return true
		}
		if stackTop.Kind() == reflect.Struct && stackTop.NumField() != 0 {
			// If this is a struct, whether it's a zero value or not will depend on whether its
			// fields are zero values or not. To avoid redundancy, ignore the containing struct type
			return true
		}
		referencedAccountTypes = append(referencedAccountTypes, path.Clone())
		return true
	})

	// If this test becomes flaky, increase niter
	niter := 1000

	accountFieldSeenZero := make([]bool, len(referencedAccountTypes))
	accountFieldSeenNonzero := make([]bool, len(referencedAccountTypes))

	accounts := RandomAccounts(niter, false)
	for _, account := range accounts {
		accountValue := reflect.ValueOf(account)
		for i, typePath := range referencedAccountTypes {
			values := typePath.ResolveValues(accountValue)

			for _, value := range values {
				isZero := value.IsZero()
				if value.Kind() == reflect.Slice || value.Kind() == reflect.Map {
					fieldLen := value.Len()
					isZero = fieldLen == 0
				}
				if !accountFieldSeenZero[i] && isZero {
					accountFieldSeenZero[i] = true
				}
				if !accountFieldSeenNonzero[i] && !isZero {
					accountFieldSeenNonzero[i] = true
				}
			}
		}
	}

	// It's ok for these fields to never be the zero value. The intuition here is that it would be
	// invalid to write an account to our DB that has the zero value for one of these fields. This
	// could be because the field is non-optional, or the zero value of the field is an unachievable
	// or invalid value.
	zeroValueExceptions := []reflectionhelpers.TypePath{
		reflectionhelpers.TypePath{}.AddField("MicroAlgos").AddField("Raw"),
		reflectionhelpers.TypePath{}.AddField("AssetParams").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("Assets").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddValue().AddField("KeyValue").AddValue().AddField("Type"),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("ApprovalProgram"),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("ClearStateProgram"),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("GlobalState").AddValue().AddField("Type"),
	}

	for _, exception := range zeroValueExceptions {
		// ensure all exceptions can resolve without panicking
		exception.ResolveType(accountDataType)
	}

	// It's ok for these fields to always be the zero value
	nonzeroValueExceptions := []reflectionhelpers.TypePath{
		// It would be great to have these fields NOT always be zero, but ledger/accountdb_test.go
		// currently depends on this.
		reflectionhelpers.TypePath{}.AddField("RewardsBase"),
		reflectionhelpers.TypePath{}.AddField("RewardedMicroAlgos").AddField("Raw"),
	}

	for _, exception := range nonzeroValueExceptions {
		// ensure all exceptions can resolve without panicking
		exception.ResolveType(accountDataType)
	}

	for i, typePath := range referencedAccountTypes {
		skipZeroValueCheck := false
		for _, exception := range zeroValueExceptions {
			if exception.Equals(typePath) {
				skipZeroValueCheck = true
				break
			}
		}

		skipNonZeroValueCheck := false
		for _, exception := range nonzeroValueExceptions {
			if exception.Equals(typePath) {
				skipNonZeroValueCheck = true
				break
			}
		}

		referencedType := typePath.ResolveType(accountDataType)
		if !skipZeroValueCheck {
			assert.Truef(t, accountFieldSeenZero[i], "Path '%s' (type %v) was never seen with a zero value", typePath, referencedType)
		}
		if !skipNonZeroValueCheck {
			assert.Truef(t, accountFieldSeenNonzero[i], "Path '%s' (type %v) was always seen with a zero value", typePath, referencedType)
		}
	}
}
