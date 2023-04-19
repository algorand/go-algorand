package main // cannot use main_type for main package?

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func makeTarget(name string, i interface{}) Target {
	t := reflect.TypeOf(i)
	root := Type{Type: t, Kind: t.Kind()}
	root.Build()
	return Target{Edge{Name: name}, root}
}

func TestDiffErrors(t *testing.T) {
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
			},
			equal: true,
		},
		{
			name: "embed flattened not equal",
			x:    struct{ A int }{},
			y: func() interface{} {
				type Embedded struct{ B int }
				return struct{ Embedded }{}
			},
			equal: false,
		},
		{
			name: "primitive types equal",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			},
			y: func() interface{} {
				type MYOTHERINT int
				var i MYOTHERINT
				return i
			},
			equal: true,
		},
		{
			name: "primitive type and primitive equal",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			},
			y:     5,
			equal: true,
		},
		{
			name: "primitives not equal",
			x: func() interface{} {
				type MYINT int
				var i MYINT
				return i
			},
			y:     uint(5),
			equal: false,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			x := makeTarget("x", tc.x)
			y := makeTarget("y", tc.y)
			diff, err := SerializationDiff(x, y, nil)
			require.NoError(t, err)
			require.Equal(t, tc.equal, diff.Empty())
		})
	}
}
