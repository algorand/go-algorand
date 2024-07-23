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

package main // cannot use main_type for main package?

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestEdgeFromLabel(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		label       string
		expected    ChildName
		expectError bool
	}{
		{
			label:       "[foo](bar)",
			expected:    ChildName{Name: "foo", Tag: "bar"},
			expectError: false,
		},
		{
			label:       "[foo]()",
			expected:    ChildName{Name: "foo", Tag: ""},
			expectError: false,
		},
		{
			label:       "[](bar)",
			expected:    ChildName{Name: "", Tag: "bar"},
			expectError: false,
		},
		{
			label:       "[]()",
			expected:    ChildName{Name: "", Tag: ""},
			expectError: false,
		},
		{
			label:       "[f[]()oo](()(()",
			expected:    ChildName{Name: "f[]()oo", Tag: "()(("},
			expectError: false,
		},
		{
			label:       "foo:bar",
			expected:    ChildName{},
			expectError: true,
		},
		{
			label:       "[f[]()oo](()((",
			expected:    ChildName{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.label, func(t *testing.T) {
			t.Parallel()
			edge, err := ChildNameFromLabel(tc.label)
			if tc.expectError {
				require.Error(t, err)
				require.Equal(t, ChildName{}, edge)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, edge)
				require.Equal(t, tc.label, edge.String())
			}
		})
	}
}

type Node struct {
	Name string
	Next *Node
}

type Senior struct {
	Children []Parent
}

type Parent struct {
	Granddaughter *Child
}

type Child struct {
	Grandpa Senior
}

type Family struct {
	Brother, Sister Kid
}

type Kid struct {
	Age  int
	Name string
}

func TestBuild(t *testing.T) {
	partitiontest.PartitionTest(t)

	testcases := []struct {
		name  string
		x     interface{}
		depth int
	}{
		{
			name:  "recursive 0",
			x:     Node{},
			depth: 2,
		},
		{
			name:  "recursive 1",
			x:     Senior{},
			depth: 5,
		},
		{
			name:  "recursive 2",
			x:     Child{},
			depth: 5,
		},
		{
			name:  "basic struct",
			x:     struct{ A int }{},
			depth: 1,
		},
		{
			name: "basic codec",
			x: struct {
				B int `codec:"A"`
			}{},
			depth: 1,
		},
		{
			name: "deeper unexported",
			x: struct {
				a []string
				B string
			}{},
			depth: 1,
		},
		{
			name: "deeper exported",
			x: struct {
				A []string
				b int
			}{},
			depth: 2,
		},
		{
			name: "embed flattened",
			x: func() interface{} {
				type Embedded struct{ A int }
				return struct{ Embedded }{}
			}(),
			depth: 1,
		},
		{
			name: "primitive alias",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			}(),
			depth: 0,
		},
		{
			name:  "primitive type",
			x:     5,
			depth: 0,
		},
		{
			name: "nested embeds 1",
			x: func() interface{} {
				type Embedded struct{ A int }
				type Embedded2 struct{ Embedded }
				return struct{ Embedded2 }{}
			}(),
			depth: 1,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			xRoot := MakeType(tc.x)
			xRoot.Build()
			tgt := Target{TypeNode: xRoot}
			tgt.PrintSerializable()
			require.Equal(t, tc.depth, MaxDepthReport(tgt), "test case: %s", tc.name)
		})
	}
}

func TestDiffErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	testcases := []struct {
		name  string
		x     interface{}
		y     interface{}
		equal bool
	}{
		{
			name:  "basic equal",
			x:     struct{ A int }{},
			y:     struct{ A int }{},
			equal: true,
		},
		{
			name: "basic codec equal",
			x:    struct{ A int }{},
			y: struct {
				B int `codec:"A"`
			}{},
			equal: true,
		},
		{
			name: "equal because only care about exported",
			x: struct {
				a int
				B string
			}{},
			y:     struct{ c, B string }{},
			equal: true,
		},
		{
			name: "basic codec not equal",
			x:    struct{ A int }{},
			y: struct {
				A int `codec:"B"`
			}{},
			equal: false,
		},
		{
			name:  "basic field not equal",
			x:     struct{ A int }{},
			y:     struct{ B int }{},
			equal: false,
		},
		{
			name: "embed flattened",
			x:    struct{ A int }{},
			y: func() interface{} {
				type Embedded struct{ A int }
				return struct{ Embedded }{}
			}(),
			equal: true,
		},
		{
			name: "embed flattened not equal",
			x:    struct{ A int }{},
			y: func() interface{} {
				type Embedded struct{ B int }
				return struct{ Embedded }{}
			}(),
			equal: false,
		},
		{
			name: "primitive types equal",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			}(),
			y: func() interface{} {
				type MYOTHERINT int
				var i MYOTHERINT
				return i
			}(),
			equal: true,
		},
		{
			name: "primitive type and primitive equal",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			}(),
			y:     5,
			equal: true,
		},
		{
			name: "primitives not equal",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			}(),
			y:     uint(5),
			equal: false,
		},
		{
			name: "nested embeds 2",
			x: func() interface{} {
				type Embedded struct{ A int }
				type Embedded2 struct{ Embedded }
				return struct{ Embedded2 }{}
			}(),
			y:     struct{ A int }{},
			equal: true,
		},
		{
			name:  "field order",
			x:     struct{ A, B int }{},
			y:     struct{ B, A int }{},
			equal: true,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			xRoot, yRoot, diff, err := StructDiff(tc.x, tc.y, nil)
			require.NoError(t, err)
			require.Equal(t, tc.equal, diff.Empty(), "test case: %s, report: %s", tc.name, Report(xRoot, yRoot, diff))
		})
	}
}

func TestBuildWithCyclicCheck(t *testing.T) {
	partitiontest.PartitionTest(t)

	testcases := []struct {
		name string
		x    interface{}
		path []string
	}{
		{
			name: "recursive 0",
			x:    Node{},
			path: []string{
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Node\" (struct)",
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Node\" (struct)",
			},
		},
		{
			name: "recursive 1",
			x:    Senior{},
			path: []string{
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Senior\" (struct)",
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Parent\" (struct)",
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Child\" (struct)",
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Senior\" (struct)",
			},
		},
		{
			name: "recursive 2",
			x:    Child{},
			path: []string{
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Child\" (struct)",
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Senior\" (struct)",
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Parent\" (struct)",
				"github.com/algorand/go-algorand/tools/x-repo-types/typeAnalyzer :: \"main.Child\" (struct)",
			},
		},
		{
			name: "basic struct",
			x:    struct{ A int }{},
			path: []string{},
		},
		{
			name: "basic codec",
			x: struct {
				B int `codec:"A"`
			}{},
			path: []string{},
		},
		{
			name: "deeper unexported",
			x: struct {
				a []string
				B string
			}{},
			path: []string{},
		},
		{
			name: "deeper exported",
			x: struct {
				A []string
				b int
			}{},
			path: []string{},
		},
		{
			name: "embed flattened",
			x: func() interface{} {
				type Embedded struct{ A int }
				return struct{ Embedded }{}
			}(),
			path: []string{},
		},
		{
			name: "primitive alias",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			}(),
			path: []string{},
		},
		{
			name: "primitive type",
			x:    5,
			path: []string{},
		},
		{
			name: "types may reappear with no cycles",
			x:    Family{},
			path: []string{},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			xRoot := MakeType(tc.x)
			cycle := xRoot.Build()
			hasCycle := len(cycle) > 0
			expectedHasCycle := len(tc.path) > 0
			require.Equal(t, expectedHasCycle, hasCycle, `test case: %s
			cycle: %s
			expected: %#v`, tc.name, cycle, tc.path)
			require.Equal(t, fmt.Sprintf("%#v", tc.path), cycle.String(), `test case: %s
				cycle: %s
				expected: %#v`, tc.name, cycle, tc.path,
			)
		})
	}
}
