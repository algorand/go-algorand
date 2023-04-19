package main

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestEdgeFromLabel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type testCase struct {
		label       string
		expected    Edge
		expectError bool
	}

	testCases := []testCase{
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
