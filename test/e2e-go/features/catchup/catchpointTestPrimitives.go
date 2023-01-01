package catchup

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"net/http"
	"os/exec"
	"syscall"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-deadlock"
)

// TODO: Rename file

func denyRoundRequestsWebProxy(a *require.Assertions, listeningAddress string, round basics.Round) *fixtures.WebProxy {
	log := logging.NewLogger()
	log.SetLevel(logging.Info)

	wp, err := fixtures.MakeWebProxy(listeningAddress, log, func(response http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
		// prevent requests for the given block to go through.
		if request.URL.String() == fmt.Sprintf("/v1/test-v1/block/%d", round) {
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte(fmt.Sprintf("webProxy prevents block %d from serving", round)))
			return
		}
		next(response, request)
	})
	a.NoError(err)
	log.Infof("web proxy listens at %s\n", wp.GetListenAddress())
	return wp
}

func GetFirstCatchpointRound(consensusParams *config.ConsensusParams, catchpointInterval uint64) basics.Round {
	// fast catchup downloads some blocks back from catchpoint round - CatchpointLookback
	expectedBlocksToDownload := consensusParams.MaxTxnLife + consensusParams.DeeperBlockHeaderHistory
	const restrictedBlockRound = 2 // block number that is rejected to be downloaded to ensure fast catchup and not regular catchup is running
	// calculate the target round: this is the next round after catchpoint
	// that is greater than expectedBlocksToDownload before the restrictedBlock block number
	minRound := restrictedBlockRound + consensusParams.CatchpointLookback
	return basics.Round(((expectedBlocksToDownload+minRound)/catchpointInterval + 1) * catchpointInterval)
}

func ApplyCatchpointConsensusChanges(consensusParams *config.ConsensusParams) {
	// MaxBalLookback  =  2 x SeedRefreshInterval x SeedLookback
	// ref. https://github.com/algorandfoundation/specs/blob/master/dev/abft.md
	consensusParams.SeedLookback = 2
	consensusParams.SeedRefreshInterval = 2
	consensusParams.MaxBalLookback = 2 * consensusParams.SeedLookback * consensusParams.SeedRefreshInterval // 8
	consensusParams.MaxTxnLife = 13
	consensusParams.CatchpointLookback = consensusParams.MaxBalLookback
	consensusParams.EnableOnlineAccountCatchpoints = true
}

func ConfigureCatchpointGeneration(a *require.Assertions, nodeController *nodecontrol.NodeController, catchpointInterval uint64) {
	cfg, err := config.LoadConfigFromDisk(nodeController.GetDataDir())
	a.NoError(err)

	cfg.CatchpointInterval = catchpointInterval
	cfg.MaxAcctLookback = 2
	err = cfg.SaveToDisk(nodeController.GetDataDir())
	a.NoError(err)
}

// TODO: Rename
func ConfigureCatchpointHandling(a *require.Assertions, nodeController *nodecontrol.NodeController) {
	cfg, err := config.LoadConfigFromDisk(nodeController.GetDataDir())
	a.NoError(err)

	cfg.MaxAcctLookback = 2
	cfg.Archival = false
	cfg.CatchpointInterval = 0
	cfg.NetAddress = ""
	cfg.EnableLedgerService = false
	cfg.EnableBlockService = false
	cfg.BaseLoggerDebugLevel = uint32(logging.Debug)
	err = cfg.SaveToDisk(nodeController.GetDataDir())
	a.NoError(err)
}

type NodeExitErrorCollector struct {
	errors   []error
	messages []string
	mu       deadlock.Mutex
	a        *require.Assertions
}

func (ec *NodeExitErrorCollector) nodeExitWithError(nc *nodecontrol.NodeController, err error) {
	if err == nil {
		return
	}

	exitError, ok := err.(*exec.ExitError)
	if !ok {
		if err != nil {
			ec.mu.Lock()
			ec.errors = append(ec.errors, err)
			ec.messages = append(ec.messages, "Node at %s has terminated with an error", nc.GetDataDir())
			ec.mu.Unlock()
		}
		return
	}
	ws := exitError.Sys().(syscall.WaitStatus)
	exitCode := ws.ExitStatus()

	if err != nil {
		ec.mu.Lock()
		ec.errors = append(ec.errors, err)
		ec.messages = append(ec.messages, fmt.Sprintf("Node at %s has terminated with error code %d", nc.GetDataDir(), exitCode))
		ec.mu.Unlock()
	}
}

func (ec *NodeExitErrorCollector) Print() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	for i, err := range ec.errors {
		ec.a.NoError(err, ec.messages[i])
	}
}

func StartCatchpointGeneratingNode(a *require.Assertions, fixture *fixtures.RestClientFixture, nodeName string, catchpointInterval uint64) (nodecontrol.NodeController, *NodeExitErrorCollector) {
	nodeController, err := fixture.GetNodeController(nodeName)
	a.NoError(err)

	ConfigureCatchpointGeneration(a, &nodeController, catchpointInterval)

	errorsCollector := NodeExitErrorCollector{a: a}
	_, err = nodeController.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       "",
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
		ExitErrorCallback: errorsCollector.nodeExitWithError,
	})
	a.NoError(err)
	return nodeController, &errorsCollector
}

func StartCatchpointUsingNode(a *require.Assertions, fixture *fixtures.RestClientFixture, nodeName string, peerAddress string) (nodecontrol.NodeController, *fixtures.WebProxy, *NodeExitErrorCollector) {
	nodeController, err := fixture.GetNodeController(nodeName)
	a.NoError(err)

	ConfigureCatchpointHandling(a, &nodeController)

	wp := denyRoundRequestsWebProxy(a, peerAddress, 2)
	errorsCollector := NodeExitErrorCollector{a: a}
	_, err = nodeController.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       wp.GetListenAddress(),
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
		ExitErrorCallback: errorsCollector.nodeExitWithError,
	})
	a.NoError(err)
	return nodeController, wp, &errorsCollector
}
