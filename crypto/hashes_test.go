package crypto

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashFactoryCreatingNewHashes(t *testing.T) {
	a := require.New(t)

	hfactory := HashFactory{HashType: Sha512_256}
	h, err := hfactory.NewHash()
	a.NoError(err)
	a.NotNil(h)
	a.Equal(32, h.Size())

	hfactory = HashFactory{HashType: Subsetsum}
	h, err = hfactory.NewHash()
	a.NoError(err)
	a.NotNil(h)
	a.Equal(112, h.Size())

	hfactory = HashFactory{HashType: HashType(math.MaxUint64)}
	h, err = hfactory.NewHash()
	a.Error(err)
	a.Nil(h)
}

func TestHashSum(t *testing.T) {
	a := require.New(t)

	hfactory := HashFactory{HashType: Sha512_256}
	h, err := hfactory.NewHash()
	a.NoError(err)
	a.NotNil(h)
	a.Equal(32, h.Size())

	dgst := HashObj(TestingHashable{})
	a.Equal(HashSum(h, TestingHashable{}), dgst[:])
}
