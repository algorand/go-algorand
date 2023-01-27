// Copyright (C) 2019-2023 Algorand, Inc.
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
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestTagList checks that the TagList global variable contains
// all the constant Tag variables declared in tags.go.
func TestTagList(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tags.go", nil, 0)
	require.NoError(t, err)

	var constTags []Tag
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}

		for _, spec := range gen.Specs {
			v, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, expr := range v.Values {
				val, ok := expr.(*ast.BasicLit)
				if !ok {
					continue
				}
				tagVal, err := strconv.Unquote(val.Value)
				require.NoError(t, err)
				constTags = append(constTags, Tag(tagVal))
			}
		}
	}
	require.NotEmpty(t, TagList)
	require.Len(t, TagList, len(constTags), "TagList is not complete")
	tagMap := make(map[Tag]bool)
	for _, tag := range TagList {
		tagMap[tag] = true
	}
	for _, tag := range constTags {
		if !tagMap[tag] {
			t.Errorf("Tag %s is not in TagList", tag)
		}
	}
}
