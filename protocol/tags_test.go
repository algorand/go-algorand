package protocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTagList checks that the TagList global variable contains
// all the constant Tag variables declared in tags.go.
func TestTagList(t *testing.T) {
	t.Parallel()

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
				constTags = append(constTags, Tag(val.Value))
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
