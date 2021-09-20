package pipeline

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

func testPipelineWithConfig(t *testing.T, cfgname string) {
	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	cp := config.Consensus[protocol.ConsensusCurrentVersion]
	cp.AgreementMessagesContainBranch = true
	cp.AgreementPipelining = true
	cp.AgreementPipelineDepth = 10
	cp.AgreementPipelineDelayHistory = 32
	cp.AgreementPipelineDelay = 4
	configurableConsensus[protocol.ConsensusVersion("vPipeline")] = cp

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", cfgname))
	defer fixture.ShutdownImpl(true) // preserve logs in testdir

	_, err := fixture.NC.AlgodClient()
	r.NoError(err)

	// Without pipelining, we are limited to approximately 1 block per 4 seconds.
	// Make sure that we can agree on much more than that.  In the absence of
	// pipelining, 50 rounds would take at least 200 seconds.
	err = fixture.WaitForRound(50, 60 * time.Second)
	r.NoError(err)
}

func TestPipelineTwoNodes(t *testing.T) {
	testPipelineWithConfig(t, "PipelineTwoNodes.json")
}

func TestPipelineFiveNodes(t *testing.T) {
	testPipelineWithConfig(t, "PipelineFiveNodes.json")
}
