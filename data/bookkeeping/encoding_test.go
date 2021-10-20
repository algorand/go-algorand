// Copyright (C) 2019-2021 Algorand, Inc.
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

package bookkeeping

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestEmptyEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var b Block
	require.Equal(t, 1, len(protocol.Encode(&b)))

	var bh BlockHeader
	require.Equal(t, 1, len(protocol.Encode(&bh)))
}

func TestBlockWithTxnEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Amount: basics.MicroAlgos{Raw: 1},
		},
	}

	sigtxn := transactions.SignedTxn{
		Txn: txn,
	}

	var b Block
	b.Payset = []transactions.SignedTxnInBlock{
		{
			SignedTxnWithAD: transactions.SignedTxnWithAD{
				SignedTxn: sigtxn,
			},
		},
	}
	enc := protocol.Encode(&b)

	var b2 Block
	err := protocol.Decode(enc, &b2)
	require.NoError(t, err)
	require.Equal(t, b, b2)
}

type typePath []string

func (p typePath) addMapKey() typePath {
	return append(p, "map_key")
}

func (p typePath) addValue() typePath {
	return append(p, "value")
}

func (p typePath) addField(fieldName string) typePath {
	return append(p, "field "+fieldName)
}

func (p typePath) validatePathFrom(t reflect.Type) error {
	if len(p) == 0 {
		// path is empty, so it's vacuously valid
		return nil
	}

	value := p[0]
	switch {
	case value == "map_key":
		return p[1:].validatePathFrom(t.Key())
	case value == "value":
		return p[1:].validatePathFrom(t.Elem())
	case strings.HasPrefix(value, "field "):
		fieldName := value[len("field "):]
		fieldType, ok := t.FieldByName(fieldName)
		if !ok {
			return fmt.Errorf("Type '%s' does not have the field '%s'", t.Name(), fieldName)
		}
		return p[1:].validatePathFrom(fieldType.Type)
	default:
		return fmt.Errorf("Unexpected item in path: %s", value)
	}
}

func (p typePath) Equals(other typePath) bool {
	if len(p) != len(other) {
		return false
	}
	for i := range p {
		if p[i] != other[i] {
			return false
		}
	}
	return true
}

func (p typePath) String() string {
	return strings.Join(p, "->")
}

func checkReferencedTypes(seen map[reflect.Type]bool, path typePath, typeStack []reflect.Type, check func(path typePath, stack []reflect.Type) bool) {
	currentType := typeStack[len(typeStack)-1]

	if _, seenType := seen[currentType]; seenType {
		return
	}

	if !check(path, typeStack) {
		// if currentType is not ok, don't visit its children
		return
	}

	// add currentType to seen set, to avoid infinite recursion if currentType references itself
	seen[currentType] = true

	// after currentType's children are visited, "forget" the type, so we can examine it again if needed
	// if this didn't happen, only 1 error per invalid type would get reported
	defer delete(seen, currentType)

	switch currentType.Kind() {
	case reflect.Map:
		newPath := path.addMapKey()
		newStack := append(typeStack, currentType.Key())
		checkReferencedTypes(seen, newPath, newStack, check)
		fallthrough
	case reflect.Array, reflect.Slice, reflect.Ptr:
		newPath := path.addValue()
		newStack := append(typeStack, currentType.Elem())
		checkReferencedTypes(seen, newPath, newStack, check)
	case reflect.Struct:
		for i := 0; i < currentType.NumField(); i++ {
			field := currentType.Field(i)
			newPath := path.addField(field.Name)
			newStack := append(typeStack, field.Type)
			checkReferencedTypes(seen, newPath, newStack, check)
		}
	}
}

func TestBlockFields(t *testing.T) {
	partitiontest.PartitionTest(t)

	blockType := reflect.TypeOf(Block{})

	// These exceptions are for pre-existing usages of string. Only add to this list if you really need to use string.
	exceptions := []typePath{
		typePath{}.addField("BlockHeader").addField("GenesisID"),
		typePath{}.addField("BlockHeader").addField("UpgradeState").addField("CurrentProtocol"),
		typePath{}.addField("BlockHeader").addField("UpgradeState").addField("NextProtocol"),
		typePath{}.addField("BlockHeader").addField("UpgradeVote").addField("UpgradePropose"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("SignedTxn").addField("Txn").addField("Type"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("SignedTxn").addField("Txn").addField("Header").addField("GenesisID"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("SignedTxn").addField("Txn").addField("AssetConfigTxnFields").addField("AssetParams").addField("UnitName"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("SignedTxn").addField("Txn").addField("AssetConfigTxnFields").addField("AssetParams").addField("AssetName"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("SignedTxn").addField("Txn").addField("AssetConfigTxnFields").addField("AssetParams").addField("URL"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("ApplyData").addField("EvalDelta").addField("GlobalDelta").addMapKey(),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("ApplyData").addField("EvalDelta").addField("GlobalDelta").addValue().addField("Bytes"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("ApplyData").addField("EvalDelta").addField("LocalDeltas").addValue().addMapKey(),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("ApplyData").addField("EvalDelta").addField("LocalDeltas").addValue().addValue().addField("Bytes"),
		typePath{}.addField("Payset").addValue().addField("SignedTxnWithAD").addField("ApplyData").addField("EvalDelta").addField("Logs").addValue(),
	}

	for _, exception := range exceptions {
		err := exception.validatePathFrom(blockType)
		require.NoError(t, err)
	}

	seen := make(map[reflect.Type]bool)

	checkReferencedTypes(seen, nil, []reflect.Type{blockType}, func(path typePath, stack []reflect.Type) bool {
		currentType := stack[len(stack)-1]

		for _, exception := range exceptions {
			if path.Equals(exception) {
				t.Logf("Skipping exception for path: %s", path.String())
				return true
			}
		}

		switch currentType.Kind() {
		case reflect.String:
			t.Errorf("Invalid string type referenced from Block. Use []byte instead. Full path: %s", path.String())
			return false
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
			// raise an error if one of these strange types is referenced too
			t.Errorf("Invalid type %s referenced from Block. Full path: %s", currentType.Name(), path.String())
			return false
		default:
			return true
		}
	})
}
