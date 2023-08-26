package agreement

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSampleIndexIsValid(t *testing.T) {
	require.Less(t, dynamicFilterTimeoutCredentialArrivalHistoryIdx, dynamicFilterCredentialArrivalHistory)
}

func TestLowerBound(t *testing.T) {
	require.Less(t, 20*time.Millisecond, dynamicFilterTimeoutLowerBound)
}
