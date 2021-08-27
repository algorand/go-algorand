package pipeline

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

func TestPipeline(t *testing.T) {
	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	cp := config.Consensus[protocol.ConsensusCurrentVersion]
	cp.AgreementPipelining = true
	cp.AgreementPipelineDepth = 5
	cp.AgreementPipelineDelayHistory = 32
	// vFuture.AgreementPipelineDelay = 30
	cp.AgreementPipelineDelay = 0
	configurableConsensus[protocol.ConsensusVersion("vPipeline")] = cp

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "PipelineFiveNodes.json"))
	defer fixture.Shutdown()

	_, err := fixture.NC.AlgodClient()
	r.NoError(err)

}
