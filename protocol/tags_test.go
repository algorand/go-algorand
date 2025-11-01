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

package protocol

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// getConstValues uses the AST to get a list of the values of declared const
// variables of the provided typeName in a specified fileName.
// if namesOnly is true, it returns the names of the const variables instead.
func getConstValues(t *testing.T, fileName string, typeName string, namesOnly bool) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fileName, nil, 0)
	require.NoError(t, err)

	var ret []string

	// Iterate through the declarations in the file
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		// Check if the declaration is a constant
		if !ok || gen.Tok != token.CONST {
			continue
		}
		// Iterate through the specifications in the declaration
		for _, spec := range gen.Specs {
			// Check if the spec is a value spec
			v, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Check if the typeName specified is being declared
			if v.Type == nil || v.Type.(*ast.Ident).Name != typeName {
				continue
			}

			if namesOnly {
				ret = append(ret, v.Names[0].Name)
				continue
			}
			// Iterate through the expressions in the value spec
			for _, expr := range v.Values {
				val, ok := expr.(*ast.BasicLit)
				// Check if the expression is a basic literal and if not, continue
				if !ok {
					continue
				}
				// Unquote the value of the basic literal to remove the quotes
				tagVal, err := strconv.Unquote(val.Value)
				require.NoError(t, err)
				ret = append(ret, tagVal)
			}
		}
	}
	return ret
}

func getDeprecatedTags(t *testing.T) map[string]bool {
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, "tags.go", nil, 0)

	deprecatedTags := make(map[string]bool)
	for _, d := range f.Decls {
		genDecl, ok := d.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok && len(valueSpec.Names) > 0 &&
				valueSpec.Names[0].Name == "DeprecatedTagList" {
				for _, v := range valueSpec.Values {
					cl, ok := v.(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, elt := range cl.Elts {
						if ce, ok := elt.(*ast.Ident); ok {
							deprecatedTags[ce.Name] = true
						}
					}
				}
			}
		}
	}

	return deprecatedTags
}

// TestTagList checks that the TagList global variable contains
// all the constant Tag variables declared in tags.go.
func TestTagList(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	constTags := getConstValues(t, "tags.go", "Tag", false)

	// Verify that TagList is not empty and has the same length as constTags
	require.NotEmpty(t, TagList)
	require.Len(t, TagList, len(constTags)-len(DeprecatedTagMap), "TagList is not complete")
	tagListMap := make(map[Tag]bool)
	for _, tag := range TagList {
		tagListMap[tag] = true
	}
	for tag := range DeprecatedTagMap {
		// ensure deprecated tags are not in TagList
		require.False(t, tagListMap[tag])
		tagListMap[tag] = true
	}
	// Iterate through constTags and check that each element exists in tagListMap
	for _, constTag := range constTags {
		if tagListMap[Tag(constTag)] {
			delete(tagListMap, Tag(constTag)) // check off as seen
		} else {
			require.Fail(t, "const Tag %s is not in TagList", constTag)
		}
	}
	require.Empty(t, tagListMap, "Unseen tags remain in TagList")
}

func TestMaxSizesDefined(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)
	// Verify that we have a nonzero max message size for each tag in the TagList
	for _, tag := range TagList {
		require.Greater(t, tag.MaxMessageSize(), uint64(0))
	}
}

// TestMaxSizesTested checks that each Tag in the TagList has a corresponding line in the TestMaxSizesCorrect test in node_test.go
func TestMaxSizesTested(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	constTags := getConstValues(t, "tags.go", "Tag", true)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../node/node_test.go", nil, 0)
	require.NoError(t, err)
	// Iterate through the declarations in the file

	tagsFound := make(map[string]bool)
	for _, d := range f.Decls {
		gen, ok := d.(*ast.FuncDecl)
		// Check if the declaration is a Function Declaration and if it is the TestMaxMessageSize function
		if !ok || gen.Name.Name != "TestMaxSizesCorrect" {
			continue
		}
		// Iterate through stmt in the function
		for _, stmt := range gen.Body.List {
			// Check if the spec is a value spec
			_ = stmt
			switch stmt := stmt.(type) {
			case *ast.ExprStmt:
				expr, ok := stmt.X.(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := expr.Fun.(*ast.SelectorExpr)
				if !ok || fmt.Sprintf("%s.%s", sel.X, sel.Sel.Name) != "require.Equal" {
					continue
				}
				// we are in the require.Equal function call and need to check the third argument
				call, ok := expr.Args[2].(*ast.CallExpr)
				if !ok {
					continue
				}
				tagSel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || tagSel.Sel.Name != "MaxMessageSize" {
					continue
				}
				tagSel, ok = tagSel.X.(*ast.SelectorExpr)
				if !ok || fmt.Sprintf("%s", tagSel.X) != "protocol" {
					continue
				}
				// We have found the tag name on which MaxMessageSize() is called and used in require.Equal
				// add it to the map
				tagsFound[tagSel.Sel.Name] = true
			default:
				continue
			}
		}
	}

	deprecatedTags := getDeprecatedTags(t)
	for _, tag := range constTags {
		if tag == "TxnTag" {
			// TxnTag is tested in a looser way in TestMaxSizesCorrect
			continue
		}
		if deprecatedTags[tag] {
			continue
		}

		require.Truef(t, tagsFound[tag], "Tag %s does not have a corresponding test in TestMaxSizesCorrect", tag)
	}
}

// Switch vs Map justification
// BenchmarkTagsMaxMessageSizeSwitch-8   	11358924	       104.0 ns/op
// BenchmarkTagsMaxMessageSizeMap-8      	10242530	       117.4 ns/op
func BenchmarkTagsMaxMessageSizeSwitch(b *testing.B) {
	// warmup like the Map benchmark below
	tagsmap := make(map[Tag]uint64, len(TagList))
	for _, tag := range TagList {
		tagsmap[tag] = tag.MaxMessageSize()
	}

	b.ResetTimer()

	var total uint64
	for i := 0; i < b.N; i++ {
		for _, tag := range TagList {
			total += tag.MaxMessageSize()
		}
	}
	require.Greater(b, total, uint64(0))
}

func BenchmarkTagsMaxMessageSizeMap(b *testing.B) {
	tagsmap := make(map[Tag]uint64, len(TagList))
	for _, tag := range TagList {
		tagsmap[tag] = tag.MaxMessageSize()
	}

	b.ResetTimer()
	var total uint64
	for i := 0; i < b.N; i++ {
		for _, tag := range TagList {
			total += tagsmap[tag]
		}
	}
	require.Greater(b, total, uint64(0))
}

// TestLockdownTagList locks down the list of tags in the code.
//
// The node will drop the connection when the connecting node requests
// a message of interest which is not in this list. This is a backward
// compatibility problem. When a new tag is introduced, the nodes with
// older version will not connect to the nodes running the new
// version.
//
// It is necessary to check the version of the other node before
// sending a request for a newly added tag. Currently, version
// checking is not implemented.
//
// Similarly, When removing a tag, it is important to support requests
// for the removed tag from nodes running an older version.
func TestLockdownTagList(t *testing.T) {
	partitiontest.PartitionTest(t)
	/************************************************
	 * ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! *
	 *  Read the comment before touching this test!  *
	 * ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! *
	 *************************************************
	 */ ////////////////////////////////////////////////
	var tagList = []Tag{
		AgreementVoteTag,
		MsgOfInterestTag,
		MsgDigestSkipTag,
		NetIDVerificationTag,
		NetPrioResponseTag,
		ProposalPayloadTag,
		StateProofSigTag,
		TopicMsgRespTag,
		TxnTag,
		UniEnsBlockReqTag,
		VoteBundleTag,
		VotePackedTag,
	}
	require.Equal(t, len(tagList), len(TagList))
	tagMap := make(map[Tag]bool)
	for _, tag := range tagList {
		tagMap[tag] = true
		_, has := TagMap[tag]
		require.True(t, has)
	}
	for _, tag := range TagList {
		require.True(t, tagMap[tag])
	}
}
