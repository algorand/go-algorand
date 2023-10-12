package participation

import (
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/stretchr/testify/require"

	"testing"
)

func TestGenParticipationKeysTo_Install(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testcases := []struct {
		name      string
		outDir    string
		installed bool
	}{
		{
			name:      "install",
			installed: true,
		},
		{
			name:      "do not install",
			outDir:    t.TempDir(),
			installed: false,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var err error
			var called bool
			installFunc := func(keyPath string) error {
				called = true
				return nil
			}
			var addr basics.Address
			addr[1] = 1

			_, _, err = GenParticipationKeysTo(addr.String(), 1000, 2000, 0, tc.outDir, installFunc)
			require.NoError(t, err)
			require.Equal(t, tc.installed, called, "The install function should only be called when outDir is not set.")
		})
	}
}

func TestGenParticipationKeysTo_DefaultKeyDilution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var addr basics.Address
	addr[1] = 1
	first := uint64(1000)
	last := uint64(2000)

	testcases := []struct {
		name     string
		dilution uint64
		expected uint64
	}{
		{
			name:     "default",
			dilution: 0,
			expected: account.DefaultKeyDilution(basics.Round(first), basics.Round(last)),
		}, {
			name:     "override",
			dilution: 5,
			expected: 5,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			part, _, err := GenParticipationKeysTo(addr.String(), first, last, tc.dilution, t.TempDir(), nil)
			require.NoError(t, err)
			require.Equal(t, tc.expected, part.KeyDilution)
		})
	}
}
