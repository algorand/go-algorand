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

package v2

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplicationBoxesMaxKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Response size limited by request supplied value.
	require.Equal(t, uint64(5), applicationBoxesMaxKeys(5, 7))
	require.Equal(t, uint64(5), applicationBoxesMaxKeys(5, 0))

	// Response size limited by algod max.
	require.Equal(t, uint64(2), applicationBoxesMaxKeys(5, 1))
	require.Equal(t, uint64(2), applicationBoxesMaxKeys(0, 1))

	// Response size _not_ limited
	require.Equal(t, uint64(math.MaxUint64), applicationBoxesMaxKeys(0, 0))
}

type tagNode struct {
	children map[string]*tagNode
}

func (node *tagNode) addChild(name string, value *tagNode) {
	if _, ok := node.children[name]; ok {
		panic(fmt.Sprintf("child already present: %s", name))
	}
	node.children[name] = value
}

func (node *tagNode) assertEquals(t *testing.T, other *tagNode, path []string, seen map[*tagNode]bool) {
	t.Helper()

	if seen[node] {
		return
	}

	seen[node] = true

	nodeTags := make(map[string]bool)
	otherTags := make(map[string]bool)
	commonTags := make(map[string]bool)

	for tag := range node.children {
		nodeTags[tag] = true
		_, ok := other.children[tag]
		if ok {
			commonTags[tag] = true
		}
	}

	for tag := range other.children {
		otherTags[tag] = true
	}

	assert.Equal(t, nodeTags, otherTags, "different tags at path [%s]", strings.Join(path, ", "))

	for tag := range commonTags {
		childPath := append(path, tag)
		node.children[tag].assertEquals(t, other.children[tag], childPath, seen)
	}
}

func (node *tagNode) AssertEquals(t *testing.T, other *tagNode) {
	t.Helper()
	node.assertEquals(t, other, nil, make(map[*tagNode]bool))
}

// makeTagGraph creates a graph of encoding keys that an object uses when encoded as JSON or
// msgpack. TODO: also represent if fields have "omitempty"
func makeTagGraph(rootType reflect.Type, seen map[reflect.Type]*tagNode) *tagNode {
	if value, ok := seen[rootType]; ok {
		return value
	}

	node := &tagNode{
		children: make(map[string]*tagNode),
	}
	seen[rootType] = node

	switch rootType.Kind() {
	case reflect.Map:
		keyGraph := makeTagGraph(rootType.Key(), seen)
		node.addChild("<map-key>", keyGraph)
		fallthrough
	case reflect.Array, reflect.Slice:
		valueGraph := makeTagGraph(rootType.Elem(), seen)
		node.addChild("<value>", valueGraph)
	case reflect.Ptr:
		// Directly embed value type graph
		node = makeTagGraph(rootType.Elem(), seen)
		// the node in seen for rootType should be refreshed from calculation.
		seen[rootType] = node
	case reflect.Struct:
		for i := 0; i < rootType.NumField(); i++ {
			field := rootType.Field(i)
			subgraph := makeTagGraph(field.Type, seen)
			if field.Anonymous {
				// merge subgraph into this node
				for name, value := range subgraph.children {
					node.addChild(name, value)
				}
			} else {
				codecTagValue, codecOk := field.Tag.Lookup("codec")
				jsonTagValue, jsonOk := field.Tag.Lookup("json")
				var tagValue string
				if codecOk {
					components := strings.Split(codecTagValue, ",")
					// remove any ,omitempty or other modifiers
					tagValue = components[0]
				} else if jsonOk {
					components := strings.Split(jsonTagValue, ",")
					// remove any ,omitempty or other modifiers
					tagValue = components[0]
				} else {
					tagValue = field.Name
				}
				if len(tagValue) != 0 && tagValue != "-" {
					// ignore any empty tags and skipping fields
					node.addChild(tagValue, subgraph)
				}
			}
		}
	}

	return node
}

// TestPendingTransactionResponseStruct ensures that the hand-written PreEncodedTxInfo has the same
// encoding structure as the generated model.PendingTransactionResponse
func TestPendingTransactionResponseStruct(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	generatedResponseType := reflect.TypeFor[model.PendingTransactionResponse]()
	generatedResponseGraph := makeTagGraph(generatedResponseType, make(map[reflect.Type]*tagNode))

	customResponseType := reflect.TypeFor[PreEncodedTxInfo]()
	customResponseGraph := makeTagGraph(customResponseType, make(map[reflect.Type]*tagNode))

	expectedGeneratedTxnGraph := map[string]*tagNode{
		"<map-key>": {children: make(map[string]*tagNode)},
		"<value>":   {children: make(map[string]*tagNode)},
	}
	if assert.Equal(t, expectedGeneratedTxnGraph, generatedResponseGraph.children["txn"].children) {
		// The generated response type uses map[string]interface{} to represent a transaction, while
		// the custom response type uses transactions.SignedTxn. Let's copy that into the generated
		// type.
		generatedResponseGraph.children["txn"].children = customResponseGraph.children["txn"].children
	}

	generatedResponseGraph.AssertEquals(t, customResponseGraph)
}

// TestSimulateResponseStruct ensures that the hand-written PreEncodedSimulateResponse has the same
// encoding structure as the generated model.SimulateResponse
func TestSimulateResponseStruct(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	generatedResponseType := reflect.TypeFor[model.SimulateResponse]()
	generatedResponseGraph := makeTagGraph(generatedResponseType, make(map[reflect.Type]*tagNode))

	customResponseType := reflect.TypeFor[PreEncodedSimulateResponse]()
	customResponseGraph := makeTagGraph(customResponseType, make(map[reflect.Type]*tagNode))

	expectedGeneratedTxnGraph := map[string]*tagNode{
		"<map-key>": {children: make(map[string]*tagNode)},
		"<value>":   {children: make(map[string]*tagNode)},
	}
	preEncodedTxPath := func(graph *tagNode) *tagNode {
		// Resolve the field model.SimulationResponse{}.TxnGroups[0].TxnResults[0].TxnResult.Txn
		return graph.children["txn-groups"].children["<value>"].children["txn-results"].children["<value>"].children["txn-result"].children["txn"]
	}
	if assert.Equal(t, expectedGeneratedTxnGraph, preEncodedTxPath(generatedResponseGraph).children) {
		// The generated response type uses map[string]interface{} to represent a transaction, while
		// the custom response type uses transactions.SignedTxn. Let's copy that into the generated
		// type.
		preEncodedTxPath(generatedResponseGraph).children = preEncodedTxPath(customResponseGraph).children
	}

	generatedResponseGraph.AssertEquals(t, customResponseGraph)
}

// TestSimulateRequestStruct ensures that the hand-written PreEncodedSimulateRequest has the same
// encoding structure as the generated model.SimulateRequest
func TestSimulateRequestStruct(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	generatedResponseType := reflect.TypeFor[model.SimulateRequest]()
	generatedResponseGraph := makeTagGraph(generatedResponseType, make(map[reflect.Type]*tagNode))

	customResponseType := reflect.TypeFor[PreEncodedSimulateRequest]()
	customResponseGraph := makeTagGraph(customResponseType, make(map[reflect.Type]*tagNode))

	expectedGeneratedTxnGraph := map[string]*tagNode{
		"<value>": {children: make(map[string]*tagNode)},
	}
	preEncodedTxPath := func(graph *tagNode) *tagNode {
		// Resolve the field model.SimulateRequest{}.TxnGroups[0].Txns[0]
		return graph.children["txn-groups"].children["<value>"].children["txns"].children["<value>"]
	}
	if assert.Equal(t, expectedGeneratedTxnGraph, preEncodedTxPath(generatedResponseGraph).children) {
		// The generated response type uses json.RawMessage to represent a transaction, while
		// the custom response type uses transactions.SignedTxn. Let's copy that into the generated
		// type.
		preEncodedTxPath(generatedResponseGraph).children = preEncodedTxPath(customResponseGraph).children
	}

	generatedResponseGraph.AssertEquals(t, customResponseGraph)
}
