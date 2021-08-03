package account

import (
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParticipation_NewParticipationRegistry(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	rootDB, err := db.MakeAccessor(t.Name(), false, true)
	a.NoError(err)

	registry, err := MakeParticipationRegistry(rootDB)
	a.NoError(err)
	a.NotNil(registry)

}
