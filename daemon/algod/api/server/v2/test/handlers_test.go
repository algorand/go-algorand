package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimple(t *testing.T) {
	numAccounts := 10
	numTransactions := 10
	offlineAccounts := true
	_, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	//mockNode := makeMockNode(mockLedger, t.Name())

	require.NoError(t, nil)
}
