package main // cannot use main_type for main package?

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestEdgeFromLabel(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		label       string
		expected    Edge
		expectError bool
	}{
		{
			label:       "[foo](bar)",
			expected:    Edge{Name: "foo", Tag: "bar"},
			expectError: false,
		},
		{
			label:       "[foo]()",
			expected:    Edge{Name: "foo", Tag: ""},
			expectError: false,
		},
		{
			label:       "[](bar)",
			expected:    Edge{Name: "", Tag: "bar"},
			expectError: false,
		},
		{
			label:       "[]()",
			expected:    Edge{Name: "", Tag: ""},
			expectError: false,
		},
		{
			label:       "[f[]()oo](()(()",
			expected:    Edge{Name: "f[]()oo", Tag: "()(("},
			expectError: false,
		},
		{
			label:       "foo:bar",
			expected:    Edge{},
			expectError: true,
		},
		{
			label:       "[f[]()oo](()((",
			expected:    Edge{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.label, func(t *testing.T) {
			t.Parallel()
			edge, err := EdgeFromLabel(tc.label)
			if tc.expectError {
				require.Error(t, err)
				require.Equal(t, Edge{}, edge)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, edge)
				require.Equal(t, tc.label, edge.String())
			}
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
