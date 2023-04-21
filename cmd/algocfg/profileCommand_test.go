package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func Test_getConfigForArg(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("invalid config test", func(t *testing.T) {
		t.Parallel()
		_, err := getConfigForArg("invalid")

		var names []string
		for name := range profileNames {
			names = append(names, name)
		}
		require.ErrorContains(t, err, strings.Join(names, ", "))

	})

	t.Run("valid config test", func(t *testing.T) {
		t.Parallel()
		cfg, err := getConfigForArg("conduit")
		require.NoError(t, err)
		require.True(t, cfg.EnableFollowMode)
	})

}
