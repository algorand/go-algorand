package p2p

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

func testP2PWithConfig(t *testing.T, cfgname string) {
	r := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", cfgname))
	defer fixture.ShutdownImpl(true) // preserve logs in testdir

	_, err := fixture.NC.AlgodClient()
	r.NoError(err)

	err = fixture.WaitForRound(10, 60*time.Second)
	r.NoError(err)
}

func TestP2PTwoNodes(t *testing.T) {
	testP2PWithConfig(t, "TwoNodes50EachP2P.json")
}

func TestP2PFiveNodes(t *testing.T) {
	testP2PWithConfig(t, "P2pFiveNodes.json")
}
