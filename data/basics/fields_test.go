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

package basics_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/test/reflectionhelpers"
)

func makeTypeCheckFunction(t *testing.T, exceptions []reflectionhelpers.TypePath, startType reflect.Type) reflectionhelpers.ReferencedTypesIterationAction {
	for _, exception := range exceptions {
		// ensure all exceptions can resolve without panicking
		exception.ResolveType(startType)
	}

	return func(path reflectionhelpers.TypePath, stack []reflect.Type) bool {
		currentType := stack[len(stack)-1]

		if slices.ContainsFunc(exceptions, path.Equals) {
			t.Logf("Skipping exception for path: %s", path)
			return true
		}

		switch currentType.Kind() {
		case reflect.String:
			t.Errorf("Invalid string type referenced from %v. Use []byte instead. Full path: %s", startType, path)
			return false
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
			// raise an error if one of these strange types is referenced too
			t.Errorf("Invalid type %v referenced from %v. Full path: %s", currentType, startType, path)
			return false
		default:
			return true
		}
	}
}

func TestBlockFields(t *testing.T) {
	partitiontest.PartitionTest(t)

	typeToCheck := reflect.TypeFor[bookkeeping.Block]()

	// These exceptions are for pre-existing usages of string. Only add to this list if you really need to use string.
	exceptions := []reflectionhelpers.TypePath{
		reflectionhelpers.TypePath{}.AddField("BlockHeader").AddField("GenesisID"),
		reflectionhelpers.TypePath{}.AddField("BlockHeader").AddField("UpgradeState").AddField("CurrentProtocol"),
		reflectionhelpers.TypePath{}.AddField("BlockHeader").AddField("UpgradeState").AddField("NextProtocol"),
		reflectionhelpers.TypePath{}.AddField("BlockHeader").AddField("UpgradeVote").AddField("UpgradePropose"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("SignedTxn").AddField("Txn").AddField("Type"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("SignedTxn").AddField("Txn").AddField("Header").AddField("GenesisID"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("SignedTxn").AddField("Txn").AddField("AssetConfigTxnFields").AddField("AssetParams").AddField("UnitName"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("SignedTxn").AddField("Txn").AddField("AssetConfigTxnFields").AddField("AssetParams").AddField("AssetName"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("SignedTxn").AddField("Txn").AddField("AssetConfigTxnFields").AddField("AssetParams").AddField("URL"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("ApplyData").AddField("EvalDelta").AddField("GlobalDelta").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("ApplyData").AddField("EvalDelta").AddField("GlobalDelta").AddValue().AddField("Bytes"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("ApplyData").AddField("EvalDelta").AddField("LocalDeltas").AddValue().AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("ApplyData").AddField("EvalDelta").AddField("LocalDeltas").AddValue().AddValue().AddField("Bytes"),
		reflectionhelpers.TypePath{}.AddField("Payset").AddValue().AddField("SignedTxnWithAD").AddField("ApplyData").AddField("EvalDelta").AddField("Logs").AddValue(),
	}

	reflectionhelpers.IterateReferencedTypes(typeToCheck, makeTypeCheckFunction(t, exceptions, typeToCheck))
}

func TestAccountDataFields(t *testing.T) {
	partitiontest.PartitionTest(t)

	typeToCheck := reflect.TypeFor[basics.AccountData]()

	// These exceptions are for pre-existing usages of string. Only add to this list if you really need to use string.
	exceptions := []reflectionhelpers.TypePath{
		reflectionhelpers.TypePath{}.AddField("AssetParams").AddValue().AddField("UnitName"),
		reflectionhelpers.TypePath{}.AddField("AssetParams").AddValue().AddField("AssetName"),
		reflectionhelpers.TypePath{}.AddField("AssetParams").AddValue().AddField("URL"),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddValue().AddField("KeyValue").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddValue().AddField("KeyValue").AddValue().AddField("Bytes"),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("GlobalState").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("GlobalState").AddValue().AddField("Bytes"),
	}

	reflectionhelpers.IterateReferencedTypes(typeToCheck, makeTypeCheckFunction(t, exceptions, typeToCheck))
}
