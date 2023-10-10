package libgoal

import (
	"github.com/algorand/go-algorand/data/basics"

	"github.com/stretchr/testify/require"

	"testing"
)

func TestGenParticipationKeysTo(t *testing.T) {
	var called bool
	installFunc := func(keyPath string) error {
		called = true
		return nil
	}
	var addr basics.Address
	addr[1] = 1

	_, _, err := GenParticipationKeysTo(addr.String(), 1000, 2000, 0, "", installFunc)
	require.NoError(t, err)
	require.True(t, called, "the install function should have been called")
}
