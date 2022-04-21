// Copyright (C) 2019-2022 Algorand, Inc.
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
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/gofrs/flock"
	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	toolsnet "github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-algorand/util/tokens"
)

type algodArgs struct {
	dataDirectory     string
	genesisFile       string
	genesisPrint      bool
	versionCheck      bool
	branchCheck       bool
	channelCheck      bool
	initAndExit       bool
	logToStdout       bool
	peerOverride      string
	listenIP          string
	sessionGUID       string
	telemetryOverride string
	seed              string
}

var command *cobra.Command

func init() {
	var args algodArgs

	command = &cobra.Command{
		Use:   "algod",
		Short: "Algorand daemon",
		Long:  `algod allows a node to participate in the agreement protocol, submit and confirm transactions, and view the state of the Algorand Ledger.`,
		Run: func(_ *cobra.Command, _ []string) {
			run(args)
		},
	}
	command.Flags().StringVar(&args.dataDirectory, "d", "", "Root Algorand daemon data path")
	command.Flags().StringVar(&args.genesisFile, "g", "", "Genesis configuration file")
	command.Flags().BoolVar(&args.genesisPrint, "G", false, "Print genesis ID")
	command.Flags().BoolVar(&args.versionCheck, "v", false, "Display and write current build version and exit")
	command.Flags().BoolVar(&args.branchCheck, "b", false, "Display the git branch behind the build")
	command.Flags().BoolVar(&args.channelCheck, "c", false, "Display and release channel behind the build")
	command.Flags().BoolVar(&args.initAndExit, "x", false, "Initialize the ledger and exit")
	command.Flags().BoolVarP(&args.logToStdout, "logToStdout", "o", false, "Write to stdout instead of node.log by overriding config.LogSizeLimit to 0")
	command.Flags().StringVar(&args.peerOverride, "p", "", "Override phonebook with peer ip:port (or semicolon separated list: ip:port;ip:port;ip:port...)")
	command.Flags().StringVar(&args.listenIP, "l", "", "Override config.EndpointAddress (REST listening address) with ip:port")
	command.Flags().StringVar(&args.sessionGUID, "s", "", "Telemetry Session GUID to use")
	command.Flags().StringVar(&args.telemetryOverride, "t", "", `Override telemetry setting if supported (Use "true", "false", "0" or "1"`)
	command.Flags().StringVar(&args.seed, "seed", "", "input to math/rand.Seed()")
}

func main() {
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "algod process exiting with error: %s", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func run(args algodArgs) int {
	dataDir := resolveDataDir(args.dataDirectory)
	absolutePath, absPathErr := filepath.Abs(dataDir)
	config.UpdateVersionDataDir(absolutePath)

	if args.seed != "" {
		seedVal, err := strconv.ParseInt(args.seed, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad seed %#v: %s\n", args.seed, err)
			return 1
		}
		rand.Seed(seedVal)
	} else {
		rand.Seed(time.Now().UnixNano())
	}

	if args.versionCheck {
		fmt.Println(config.FormatVersionAndLicense())
		return 0
	}

	version := config.GetCurrentVersion()
	var baseHeartbeatEvent telemetryspec.HeartbeatEventDetails
	baseHeartbeatEvent.Info.Version = version.String()
	baseHeartbeatEvent.Info.VersionNum = strconv.FormatUint(version.AsUInt64(), 10)
	baseHeartbeatEvent.Info.Channel = version.Channel
	baseHeartbeatEvent.Info.Branch = version.Branch
	baseHeartbeatEvent.Info.CommitHash = version.GetCommitHash()

	if args.branchCheck {
		fmt.Println(config.Branch)
		return 0
	}

	if args.channelCheck {
		fmt.Println(config.Channel)
		return 0
	}

	// Don't fallback anymore - if not specified, we want to panic to force us to update our tooling and/or processes
	if len(dataDir) == 0 {
		fmt.Fprintln(os.Stderr, "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment.")
		return 1
	}

	if absPathErr != nil {
		fmt.Fprintf(os.Stderr, "Can't convert data directory's path to absolute, %v\n", dataDir)
		return 1
	}

	genesisPath := args.genesisFile
	if genesisPath == "" {
		genesisPath = filepath.Join(dataDir, config.GenesisJSONFile)
	}

	// Load genesis
	genesisText, err := ioutil.ReadFile(genesisPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read genesis file %s: %v\n", genesisPath, err)
		return 1
	}

	var genesis bookkeeping.Genesis
	err = protocol.DecodeJSON(genesisText, &genesis)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse genesis file %s: %v\n", genesisPath, err)
		return 1
	}

	if args.genesisPrint {
		fmt.Println(genesis.ID())
		return 0
	}

	// If data directory doesn't exist, we can't run. Don't bother trying.
	if _, err := os.Stat(absolutePath); err != nil {
		fmt.Fprintf(os.Stderr, "Data directory %s does not appear to be valid\n", dataDir)
		return 1
	}

	log := logging.Base()
	// before doing anything further, attempt to acquire the algod lock
	// to ensure this is the only node running against this data directory
	lockPath := filepath.Join(absolutePath, "algod.lock")
	fileLock := flock.New(lockPath)
	locked, err := fileLock.TryLock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unexpected failure in establishing algod.lock: %s \n", err.Error())
		return 1
	}
	if !locked {
		fmt.Fprintln(os.Stderr, "failed to lock algod.lock; is an instance of algod already running in this data directory?")
		return 1
	}
	defer fileLock.Unlock()

	cfg, err := config.LoadConfigFromDisk(absolutePath)
	if err != nil && !os.IsNotExist(err) {
		// log is not setup yet, this will log to stderr
		log.Fatalf("Cannot load config: %v", err)
	}

	err = config.LoadConfigurableConsensusProtocols(absolutePath)
	if err != nil {
		// log is not setup yet, this will log to stderr
		log.Fatalf("Unable to load optional consensus protocols file: %v", err)
	}

	// Enable telemetry hook in daemon to send logs to cloud
	// If ALGOTEST env variable is set, telemetry is disabled - allows disabling telemetry for tests
	isTest := os.Getenv("ALGOTEST") != ""
	remoteTelemetryEnabled := false
	if !isTest {
		telemetryConfig, err := logging.EnsureTelemetryConfig(&dataDir, genesis.ID())
		if err != nil {
			fmt.Fprintln(os.Stdout, "error loading telemetry config", err)
		}
		if os.IsPermission(err) {
			fmt.Fprintf(os.Stderr, "Permission error on accessing telemetry config: %v", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "Telemetry configured from '%s'\n", telemetryConfig.FilePath)

		telemetryConfig.SendToLog = telemetryConfig.SendToLog || cfg.TelemetryToLog

		// Apply telemetry override.
		telemetryConfig.Enable = logging.TelemetryOverride(args.telemetryOverride, &telemetryConfig)
		remoteTelemetryEnabled = telemetryConfig.Enable

		if telemetryConfig.Enable || telemetryConfig.SendToLog {
			// If session GUID specified, use it.
			if args.sessionGUID != "" {
				if len(args.sessionGUID) == 36 {
					telemetryConfig.SessionGUID = args.sessionGUID
				}
			}
			err = log.EnableTelemetry(telemetryConfig)
			if err != nil {
				fmt.Fprintln(os.Stdout, "error creating telemetry hook", err)
			}
		}
	}

	s := algod.Server{
		RootPath: absolutePath,
		Genesis:  genesis,
	}

	// Generate a REST API token if one was not provided
	apiToken, wroteNewToken, err := tokens.ValidateOrGenerateAPIToken(s.RootPath, tokens.AlgodTokenFilename)

	if err != nil {
		log.Fatalf("API token error: %v", err)
	}

	if wroteNewToken {
		fmt.Printf("No REST API Token found. Generated token: %s\n", apiToken)
	}

	// Generate a admin REST API token if one was not provided
	adminAPIToken, wroteNewToken, err := tokens.ValidateOrGenerateAPIToken(s.RootPath, tokens.AlgodAdminTokenFilename)

	if err != nil {
		log.Fatalf("Admin API token error: %v", err)
	}

	if wroteNewToken {
		fmt.Printf("No Admin REST API Token found. Generated token: %s\n", adminAPIToken)
	}

	// Allow overriding default listening address
	if args.listenIP != "" {
		cfg.EndpointAddress = args.listenIP
	}

	// If overriding peers, disable SRV lookup
	telemetryDNSBootstrapID := cfg.DNSBootstrapID
	var peerOverrideArray []string
	if args.peerOverride != "" {
		peerOverrideArray = strings.Split(args.peerOverride, ";")
		cfg.DNSBootstrapID = ""

		// The networking code waits until we have GossipFanout
		// connections before declaring the network stack to be
		// ready, which triggers things like catchup.  If the
		// user explicitly specified a set of peers, make sure
		// GossipFanout is no larger than this set, otherwise
		// we will have to wait for a minute-long timeout until
		// the network stack declares itself to be ready.
		if cfg.GossipFanout > len(peerOverrideArray) {
			cfg.GossipFanout = len(peerOverrideArray)
		}

		// make sure that the format of each entry is valid:
		for idx, peer := range peerOverrideArray {
			url, err := network.ParseHostOrURL(peer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Provided command line parameter '%s' is not a valid host:port pair\n", peer)
				return 1
			}
			peerOverrideArray[idx] = url.Host
		}
	}

	// Apply the default deadlock setting before starting the server.
	// It will potentially override it based on the config file DefaultDeadlock setting
	if strings.ToLower(config.DefaultDeadlock) == "enable" {
		deadlock.Opts.Disable = false
	} else if strings.ToLower(config.DefaultDeadlock) == "disable" {
		deadlock.Opts.Disable = true
	} else if config.DefaultDeadlock != "" {
		log.Fatalf("DefaultDeadlock is somehow not set to an expected value (enable / disable): %s", config.DefaultDeadlock)
	}

	var phonebookAddresses []string
	if peerOverrideArray != nil {
		phonebookAddresses = peerOverrideArray
	} else {
		ex, err := os.Executable()
		if err != nil {
			log.Errorf("cannot locate node executable: %s", err)
		} else {
			phonebookDir := filepath.Dir(ex)
			phonebookAddresses, err = config.LoadPhonebook(phonebookDir)
			if err != nil {
				log.Debugf("Cannot load static phonebook: %v", err)
			}
		}
	}

	if args.logToStdout {
		cfg.LogSizeLimit = 0
	}

	err = s.Initialize(cfg, phonebookAddresses, string(genesisText))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		log.Error(err)
		return 1
	}

	if args.initAndExit {
		return 0
	}

	deadlockState := "enabled"
	if deadlock.Opts.Disable {
		deadlockState = "disabled"
	}
	fmt.Fprintf(os.Stdout, "Deadlock detection is set to: %s (Default state is '%s')\n", deadlockState, config.DefaultDeadlock)

	if log.GetTelemetryEnabled() {
		done := make(chan struct{})
		defer close(done)

		// Make a copy of config and reset DNSBootstrapID in case it was disabled.
		cfgCopy := cfg
		cfgCopy.DNSBootstrapID = telemetryDNSBootstrapID

		// If the telemetry URI is not set, periodically check SRV records for new telemetry URI
		if remoteTelemetryEnabled && log.GetTelemetryURI() == "" {
			toolsnet.StartTelemetryURIUpdateService(time.Minute, cfg, s.Genesis.Network, log, done)
		}

		currentVersion := config.GetCurrentVersion()
		startupDetails := telemetryspec.StartupEventDetails{
			Version:      currentVersion.String(),
			CommitHash:   currentVersion.CommitHash,
			Branch:       currentVersion.Branch,
			Channel:      currentVersion.Channel,
			InstanceHash: crypto.Hash([]byte(absolutePath)).String(),
		}

		log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.StartupEvent, startupDetails)

		// Send a heartbeat event every 10 minutes as a sign of life
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()

			sendHeartbeat := func() {
				values := make(map[string]float64)
				metrics.DefaultRegistry().AddMetrics(values)

				heartbeatDetails := baseHeartbeatEvent
				heartbeatDetails.Metrics = values

				log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.HeartbeatEvent, heartbeatDetails)
			}

			// Send initial heartbeat, followed by one every 10 minutes.
			sendHeartbeat()
			for {
				select {
				case <-ticker.C:
					sendHeartbeat()
				case <-done:
					return
				}
			}
		}()
	}

	s.Start()
	return 0
}

func resolveDataDir(dataDirectory string) string {
	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if dataDirectory == "" {
		dir = os.Getenv("ALGORAND_DATA")
	} else {
		dir = dataDirectory
	}
	return dir
}
