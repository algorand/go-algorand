package catchup

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// TODO: Rename file
const waitTimePerBlock = 10 * time.Second

func denyRoundRequestsWebProxy(t *testing.T, listeningAddress string, round basics.Round) *fixtures.WebProxy {
	log := logging.TestingLog(t)
	a := require.New(fixtures.SynchronizedTest(t))

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

func waitForCatchpoint(t *testing.T, nodeRestClient *client.RestClient, targetCatchpointRound basics.Round) string {
	a := require.New(fixtures.SynchronizedTest(t))

	// ensure the catchpoint is created for targetCatchpointRound
	var status model.NodeStatusResponse
	var err error
	timer := time.NewTimer(10 * time.Second)
outer:
	for {
		status, err = nodeRestClient.Status()
		a.NoError(err)

		var round basics.Round
		if status.LastCatchpoint != nil && len(*status.LastCatchpoint) > 0 {
			round, _, err = ledgercore.ParseCatchpointLabel(*status.LastCatchpoint)
			a.NoError(err)
			if round >= targetCatchpointRound {
				break
			}
		}
		select {
		case <-timer.C:
			a.Failf("timeout waiting a catchpoint", "target: %d, got %d", targetCatchpointRound, round)
			break outer
		default:
			time.Sleep(250 * time.Millisecond)
		}
	}

	return *status.LastCatchpoint
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

func ConfigureCatchpointGeneration(t *testing.T, nodeController *nodecontrol.NodeController, catchpointInterval uint64) {
	a := require.New(fixtures.SynchronizedTest(t))
	cfg, err := config.LoadConfigFromDisk(nodeController.GetDataDir())
	a.NoError(err)

	cfg.CatchpointInterval = catchpointInterval
	cfg.MaxAcctLookback = 2
	err = cfg.SaveToDisk(nodeController.GetDataDir())
	a.NoError(err)
}

// TODO: Rename
func ConfigureCatchpointHandling(t *testing.T, nodeController *nodecontrol.NodeController) {
	a := require.New(fixtures.SynchronizedTest(t))
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
