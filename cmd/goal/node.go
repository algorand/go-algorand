// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/tokens"
)

var peerDial string
var listenIP string
var targetDir string
var noLedger bool
var runUnderHost bool
var telemetryOverride string
var maxPendingTransactions uint64
var waitSec uint32
var newNodeNetwork string
var newNodeDestination string
var newNodeArchival bool
var newNodeIndexer bool
var newNodeRelay string
var watchMillisecond uint64
var abortCatchup bool

func init() {
	nodeCmd.AddCommand(startCmd)
	nodeCmd.AddCommand(stopCmd)
	nodeCmd.AddCommand(statusCmd)
	nodeCmd.AddCommand(lastroundCmd)
	nodeCmd.AddCommand(restartCmd)
	nodeCmd.AddCommand(cloneCmd)
	nodeCmd.AddCommand(generateTokenCmd)
	nodeCmd.AddCommand(pendingTxnsCmd)
	nodeCmd.AddCommand(waitCmd)
	nodeCmd.AddCommand(createCmd)
	nodeCmd.AddCommand(catchupCmd)
	// Once the server-side implementation of the shutdown command is ready, we should enable this one.
	//nodeCmd.AddCommand(shutdownCmd)

	startCmd.Flags().StringVarP(&peerDial, "peer", "p", "", "Peer address to dial for initial connection")
	startCmd.Flags().StringVarP(&listenIP, "listen", "l", "", "Endpoint / REST address to listen on")
	startCmd.Flags().BoolVarP(&runUnderHost, "hosted", "H", false, "Run algod hosted by algoh")
	startCmd.Flags().StringVarP(&telemetryOverride, "telemetry", "t", "", `Enable telemetry if supported (Use "true", "false", "0" or "1")`)

	restartCmd.Flags().StringVarP(&peerDial, "peer", "p", "", "Peer address to dial for initial connection")
	restartCmd.Flags().StringVarP(&listenIP, "listen", "l", "", "Endpoint / REST address to listen on")
	restartCmd.Flags().BoolVarP(&runUnderHost, "hosted", "H", false, "Run algod hosted by algoh")
	restartCmd.Flags().StringVarP(&telemetryOverride, "telemetry", "t", "", `Enable telemetry if supported (Use "true", "false", "0" or "1")`)

	cloneCmd.Flags().StringVarP(&targetDir, "targetdir", "t", "", "Target directory for the clone")
	cloneCmd.Flags().BoolVarP(&noLedger, "noledger", "n", false, "Don't include ledger when copying (No Ledger)")

	localDefaults := config.GetDefaultLocal()
	createCmd.Flags().StringVar(&newNodeNetwork, "network", "", "Network the new node should point to")
	createCmd.Flags().StringVar(&newNodeDestination, "destination", "", "Destination path for the new node")
	createCmd.Flags().BoolVarP(&newNodeArchival, "archival", "a", localDefaults.Archival, "Make the new node archival, storing all blocks")
	createCmd.Flags().BoolVarP(&runUnderHost, "hosted", "H", localDefaults.RunHosted, "Configure the new node to run hosted by algoh")
	createCmd.Flags().BoolVarP(&newNodeIndexer, "indexer", "i", localDefaults.IsIndexerActive, "Configure the new node to enable the indexer feature (implies --archival)")
	createCmd.Flags().StringVar(&newNodeRelay, "relay", localDefaults.NetAddress, "Configure as a relay with specified listening address (NetAddress)")
	createCmd.Flags().StringVar(&listenIP, "api", "", "REST API Endpoint")
	createCmd.MarkFlagRequired("destination")
	createCmd.MarkFlagRequired("network")

	pendingTxnsCmd.Flags().Uint64VarP(&maxPendingTransactions, "maxPendingTxn", "m", 0, "Cap the number of txns to fetch")
	waitCmd.Flags().Uint32VarP(&waitSec, "waittime", "w", 5, "Time (in seconds) to wait for node to make progress")
	statusCmd.Flags().Uint64VarP(&watchMillisecond, "watch", "w", 0, "Time (in milliseconds) between two successive status updates")

	catchupCmd.Flags().BoolVarP(&abortCatchup, "abort", "x", false, "Aborts the current catchup process")

}

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage a specified algorand node",
	Long:  `Collection of commands to support the creation and management of Algorand node instances, where each instance corresponds to a unique data directory.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		//Fall back
		cmd.HelpFunc()(cmd, args)
	},
}

var catchupCmd = &cobra.Command{
	Use:     "catchup",
	Short:   "Catchup the Algorand node to a specific catchpoint",
	Long:    "Catchup allows making large jumps over round ranges without the need to incrementally validate each individual round.",
	Example: "goal node catchup 6500000#1234567890ABCDEF01234567890ABCDEF0\tStart catching up to round 6500000 with the provided catchpoint\ngoal node catchup --abort\t\t\t\t\tAbort the current catchup",
	Args:    catchpointCmdArgument,
	Run: func(cmd *cobra.Command, args []string) {
		if abortCatchup == false && len(args) == 0 {
			fmt.Println(errorCatchpointLabelMissing)
			os.Exit(1)
		}
		onDataDirs(func(datadir string) { catchup(datadir, args) })
	},
}

func catchpointCmdArgument(cmd *cobra.Command, args []string) error {
	catchpointsCount := 0
	for _, arg := range args {
		_, _, err := ledger.ParseCatchpointLabel(arg)
		switch err {
		case nil:
			if catchpointsCount > 0 {
				return errors.New(errorTooManyCatchpointLabels)
			}
			catchpointsCount++
			continue
		case ledger.ErrCatchpointParsingFailed:
			// this isn't a valid catchpoint label.
			// return a nice formatted error
			return errors.New(errorCatchpointLabelParsingFailed)
		default:
			return err
		}
	}
	return nil
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Initialize the specified Algorand node",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		if !verifyPeerDialArg() {
			return
		}
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}
		onDataDirs(func(dataDir string) {
			if libgoal.AlgorandDaemonSystemdManaged(dataDir) {
				reportErrorf(errorNodeManagedBySystemd, "start")
			}

			nc := nodecontrol.MakeNodeController(binDir, dataDir)
			nodeArgs := nodecontrol.AlgodStartArgs{
				PeerAddress:       peerDial,
				ListenIP:          listenIP,
				RedirectOutput:    false,
				RunUnderHost:      runUnderHost,
				TelemetryOverride: telemetryOverride,
			}

			if getRunHostedConfigFlag(dataDir) {
				nodeArgs.RunUnderHost = true
			}

			algodAlreadyRunning, err := nc.StartAlgod(nodeArgs)
			if algodAlreadyRunning {
				reportInfoln(infoNodeAlreadyStarted)
			}

			if err != nil {
				reportErrorf(errorNodeFailedToStart, err)
			} else {
				reportInfoln(infoNodeStart)
			}
		})
	},
}

var shutdownCmd = &cobra.Command{
	Use:   "shutdown",
	Short: "Shut down the node",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}
		onDataDirs(func(dataDir string) {
			nc := nodecontrol.MakeNodeController(binDir, dataDir)
			err := nc.Shutdown()

			if err == nil {
				reportInfoln(infoNodeShuttingDown)
			} else {
				reportErrorf(errorNodeFailedToShutdown, err)
			}
		})
	},
}

func getRunHostedConfigFlag(dataDir string) bool {
	// See if this instance wants to run Hosted, even if '-H' wasn't specified on our cmdline
	cfg, err := config.LoadConfigFromDisk(dataDir)
	if err != nil && !os.IsNotExist(err) {
		reportErrorf(errLoadingConfig, dataDir, err)
	}
	return cfg.RunHosted
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the specified Algorand node",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}
		onDataDirs(func(dataDir string) {
			if libgoal.AlgorandDaemonSystemdManaged(dataDir) {
				reportErrorf(errorNodeManagedBySystemd, "stop")
			}

			nc := nodecontrol.MakeNodeController(binDir, dataDir)

			log.Info(infoTryingToStopNode)

			err = nc.FullStop()
			if err != nil {
				reportErrorf(errorKill, err)
			}

			reportInfoln(infoNodeSuccessfullyStopped)
		})
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Stop, and then start, the specified Algorand node",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		if !verifyPeerDialArg() {
			return
		}
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}
		onDataDirs(func(dataDir string) {
			if libgoal.AlgorandDaemonSystemdManaged(dataDir) {
				reportErrorf(errorNodeManagedBySystemd, "restart")
			}

			nc := nodecontrol.MakeNodeController(binDir, dataDir)

			_, err = nc.GetAlgodPID()

			if err != nil {
				reportInfof(errorNodeNotDetected, err)
				fmt.Println("Attempting to start the Algorand node anyway...")
			} else {
				log.Info(infoTryingToStopNode)
				err = nc.FullStop()
				if err != nil {
					reportInfof(errorKill, err)
					fmt.Println("Attempting to start the Algorand node anyway...")
				} else {
					reportInfoln(infoNodeSuccessfullyStopped)
				}
			}
			// brief sleep to allow the node to finish shutting down
			time.Sleep(time.Duration(time.Second))

			nodeArgs := nodecontrol.AlgodStartArgs{
				PeerAddress:       peerDial,
				ListenIP:          listenIP,
				RedirectOutput:    false,
				RunUnderHost:      runUnderHost,
				TelemetryOverride: telemetryOverride,
			}

			if getRunHostedConfigFlag(dataDir) {
				nodeArgs.RunUnderHost = true
			}

			algodAlreadyRunning, err := nc.StartAlgod(nodeArgs)
			if algodAlreadyRunning {
				reportInfoln(infoNodeAlreadyStarted)
			}

			if err != nil {
				reportErrorf(errorNodeFailedToStart, err)
			} else {
				reportInfoln(infoNodeStart)
			}
		})
	},
}

var generateTokenCmd = &cobra.Command{
	Use:   "generatetoken",
	Short: "Generate and install a new API token",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		onDataDirs(func(dataDir string) {
			// Ensure the node is stopped -- HealthCheck should fail
			clientConfig := libgoal.ClientConfig{
				AlgodDataDir: dataDir,
				KMDDataDir:   resolveKmdDataDir(dataDir),
				CacheDir:     ensureCacheDir(dataDir),
			}
			client, err := libgoal.MakeClientFromConfig(clientConfig, libgoal.AlgodClient)
			if err == nil {
				err = client.HealthCheck()
				if err == nil {
					reportErrorln(errorNodeRunning)
				}
			}

			// Generate & persist a new token
			apiToken, err := tokens.GenerateAPIToken(dataDir, tokens.AlgodTokenFilename)
			if err != nil {
				reportErrorf(errorNodeFailGenToken, err)
			}

			// Report the new token back to the user
			reportInfof(infoNodeWroteToken, apiToken)
		})
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the current node status",
	Long:  `Show the current status of the running Algorand node.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		onDataDirs(getStatus)
	},
}

func getStatus(dataDir string) {
	const (
		CUU = string("\033[A") // Cursor Up
		DL  = string("\033[M") // Delete Line
	)
	client := ensureAlgodClient(dataDir)
	cleanupFmt := ""
	for {
		stat, err := client.Status()
		if err != nil {
			reportErrorf(errorNodeStatus, err)
		}
		vers, err := client.AlgodVersions()
		if err != nil {
			reportErrorf(errorNodeStatus, err)
		}
		status := cleanupFmt + makeStatusString(stat) + "\n"
		if vers.GenesisID != "" {
			status = fmt.Sprintf("%sGenesis ID: %s\n", status, vers.GenesisID)
		}
		status = fmt.Sprintf("%sGenesis hash: %s", status, base64.StdEncoding.EncodeToString(vers.GenesisHash[:]))
		fmt.Println(status)
		if watchMillisecond == 0 {
			break
		}
		time.Sleep(time.Duration(watchMillisecond) * time.Millisecond)
		cleanupFmt = ""
		for linesCount := len(strings.Split(status, "\n")); linesCount > 0; linesCount-- {
			cleanupFmt += CUU + DL
		}
	}
}

func makeStatusString(stat generatedV2.NodeStatusResponse) string {
	lastRoundTime := fmt.Sprintf("%.1fs", time.Duration(stat.TimeSinceLastRound).Seconds())
	catchupTime := fmt.Sprintf("%.1fs", time.Duration(stat.CatchupTime).Seconds())
	var statusString string
	if stat.Catchpoint == nil || (*stat.Catchpoint) == "" {
		statusString = fmt.Sprintf(
			infoNodeStatus,
			stat.LastRound,
			lastRoundTime,
			catchupTime,
			stat.LastVersion,
			stat.NextVersion,
			stat.NextVersionRound,
			stat.NextVersionSupported)

		if stat.LastCatchpoint != nil {
			statusString = statusString + "\n" + fmt.Sprintf(nodeLastCatchpoint, *stat.LastCatchpoint)
		}

		if stat.StoppedAtUnsupportedRound {
			statusString = statusString + "\n" + fmt.Sprintf(catchupStoppedOnUnsupported, stat.LastRound)
		}
	} else {
		statusString = fmt.Sprintf(
			infoNodeCatchpointCatchupStatus,
			stat.LastRound,
			catchupTime,
			*stat.Catchpoint)

		if stat.CatchpointTotalAccounts != nil && (*stat.CatchpointTotalAccounts > 0) && stat.CatchpointProcessedAccounts != nil {
			statusString = statusString + "\n" + fmt.Sprintf(infoNodeCatchpointCatchupAccounts, *stat.CatchpointTotalAccounts,
				*stat.CatchpointProcessedAccounts, *stat.CatchpointVerifiedAccounts)
		}
		if stat.CatchpointAcquiredBlocks != nil && stat.CatchpointTotalBlocks != nil && (*stat.CatchpointAcquiredBlocks+*stat.CatchpointTotalBlocks > 0) {
			statusString = statusString + "\n" + fmt.Sprintf(infoNodeCatchpointCatchupBlocks, *stat.CatchpointTotalBlocks,
				*stat.CatchpointAcquiredBlocks)
		}
	}

	return statusString
}

var lastroundCmd = &cobra.Command{
	Use:   "lastround",
	Short: "Print the last round number",
	Long:  `Prints the most recent round confirmed by the Algorand node.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		onDataDirs(func(dataDir string) {
			round, err := ensureAlgodClient(dataDir).CurrentRound()
			if err != nil {
				reportErrorf(errorNodeStatus, err)
			}

			reportInfof("%d\n", round)
		})
	},
}

var cloneCmd = &cobra.Command{
	Use:   "clone",
	Short: "Clone the specified node to create another node",
	Long:  `Clone the specified node to create another node. Optionally you can control whether the clone includes the current ledger, or if it starts with an uninitialized one. The default is to clone the ledger as well. Specify -n or --noledger to start with an uninitialized ledger.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}
		nc := nodecontrol.MakeNodeController(binDir, ensureSingleDataDir())
		err = nc.Clone(targetDir, !noLedger)
		if err != nil {
			reportErrorf(errorCloningNode, err)
		} else {
			reportInfof(infoNodeCloned, targetDir)
		}
	},
}

// Simple command to dump a snapshot of current pending transactions in the node's transaction pool
var pendingTxnsCmd = &cobra.Command{
	Use:   "pendingtxns",
	Short: "Get a snapshot of current pending transactions on this node",
	Long:  `Get a snapshot of current pending transactions on this node, cut off at MAX transactions (-m), default 0. If MAX=0, fetches as many transactions as possible.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		onDataDirs(func(dataDir string) {
			client := ensureAlgodClient(dataDir)
			statusTxnPool, err := client.GetPendingTransactions(maxPendingTransactions)
			if err != nil {
				reportErrorf(errorNodeStatus, err)
			}

			pendingTxns := statusTxnPool.TruncatedTxns

			// do this inline for now, break it out when we need to reuse a Txn->String function
			reportInfof(infoNodePendingTxnsDescription, maxPendingTransactions, statusTxnPool.TotalTxns)
			if pendingTxns.Transactions == nil || len(pendingTxns.Transactions) == 0 {
				reportInfof(infoNodeNoPendingTxnsDescription)
			} else {
				for _, pendingTxn := range pendingTxns.Transactions {
					pendingTxnStr, err := json.MarshalIndent(pendingTxn, "", "    ")
					if err != nil {
						// json parsing of the txn failed, so let's just skip printing it
						fmt.Printf("Unparseable Transaction %s\n", pendingTxn.TxID)
						continue
					}
					fmt.Printf("%s\n", string(pendingTxnStr))
				}
			}
		})
	},
}

var waitCmd = &cobra.Command{
	Use:   "wait",
	Short: "Waits for the node to make progress",
	Long:  "Waits for the node to make progress, which includes catching up.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		client := ensureAlgodClient(ensureSingleDataDir())
		stat, err := client.Status()
		if err != nil {
			reportErrorf(errorNodeStatus, err)
		}

		startRound := stat.LastRound
		endTime := time.After(time.Second * time.Duration(waitSec))
		for {
			select {
			case <-endTime:
				reportErrorf("Timed out waiting for node to make progress")
			case <-time.After(500 * time.Millisecond):
				stat, err = client.Status()
				if err != nil {
					reportErrorf(errorNodeStatus, err)
				}
				if startRound != stat.LastRound {
					os.Exit(0)
				}
			}
		}
	},
}

func isValidIP(userInput string) bool {
	host, port, err := net.SplitHostPort(userInput)
	if err != nil {
		return false
	}
	if port == "" {
		return false
	}
	if host == "" {
		return false
	}
	return net.ParseIP(host) != nil
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a node at the desired data directory for the desired network",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {

		// validate network input
		validNetworks := map[string]bool{"mainnet": true, "testnet": true, "devnet": true, "betanet": true}
		if !validNetworks[newNodeNetwork] {
			reportErrorf(errorNodeCreation, "passed network name invalid")
		}

		// validate and store passed options
		localConfig := config.GetDefaultLocal()
		if newNodeRelay != "" {
			if isValidIP(newNodeRelay) {
				localConfig.NetAddress = newNodeRelay
			} else {
				reportErrorf(errorNodeCreationIPFailure, newNodeRelay)
			}
		}
		if listenIP != "" {
			if isValidIP(listenIP) {
				localConfig.EndpointAddress = listenIP
			} else {
				reportErrorf(errorNodeCreationIPFailure, listenIP)
			}
		}
		localConfig.Archival = newNodeArchival || newNodeRelay != "" || newNodeIndexer
		localConfig.IsIndexerActive = newNodeIndexer
		localConfig.RunHosted = runUnderHost
		localConfig.EnableLedgerService = localConfig.Archival
		localConfig.EnableBlockService = localConfig.Archival

		// locate genesis block
		exePath, err := util.ExeDir()
		if err != nil {
			reportErrorln(errorNodeCreation, err)
		}
		firstChoicePath := filepath.Join(exePath, "genesisfiles", newNodeNetwork, "genesis.json")
		secondChoicePath := filepath.Join("var", "lib", "algorand", "genesis", newNodeNetwork, "genesis.json")
		thirdChoicePath := filepath.Join(exePath, "genesisfiles", "genesis", newNodeNetwork, "genesis.json")
		paths := []string{firstChoicePath, secondChoicePath, thirdChoicePath}
		correctPath := ""
		for _, pathCandidate := range paths {
			if util.FileExists(pathCandidate) {
				correctPath = pathCandidate
				break
			}
		}
		if correctPath == "" {
			reportErrorf("Could not find genesis.json file. Paths checked: %v", strings.Join(paths, ","))
		}

		// verify destination does not exist, and attempt to create destination folder
		if util.FileExists(newNodeDestination) {
			reportErrorf(errorNodeCreation, "destination folder already exists")
		}
		destPath := filepath.Join(newNodeDestination, "genesis.json")
		err = os.MkdirAll(newNodeDestination, 0766)
		if err != nil {
			reportErrorf(errorNodeCreation, "could not create destination folder")
		}

		// copy genesis block to destination
		_, err = util.CopyFile(correctPath, destPath)
		if err != nil {
			reportErrorf(errorNodeCreation, err)
		}

		// save config to destination
		err = localConfig.SaveToDisk(newNodeDestination)
		if err != nil {
			reportErrorf(errorNodeCreation, err)
		}
	},
}

func catchup(dataDir string, args []string) {
	client := ensureAlgodClient(ensureSingleDataDir())
	if abortCatchup {
		err := client.AbortCatchup()
		if err != nil {
			reportErrorf(errorNodeStatus, err)
		}
		return
	}
	err := client.Catchup(args[0])
	if err != nil {
		reportErrorf(errorNodeStatus, err)
	}
}

// verifyPeerDialArg verifies that the peers provided in peerDial are valid peers.
func verifyPeerDialArg() bool {
	if peerDial == "" {
		return true
	}

	// make sure that the format of each entry is valid:
	for _, peer := range strings.Split(peerDial, ";") {
		_, err := network.ParseHostOrURL(peer)
		if err != nil {
			reportErrorf("Provided peer '%s' is not a valid peer address : %v", peer, err)
			return false
		}

	}
	return true

}
