// Copyright (C) 2019-2025 Algorand, Inc.
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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network/addr"
	"github.com/algorand/go-algorand/protocol"
	toolsnet "github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-algorand/util/tokens"
	"github.com/gofrs/flock"

	"github.com/algorand/go-deadlock"
)

var dataDirectory = flag.String("d", "", "Root Algorand daemon data path")
var genesisFile = flag.String("g", "", "Genesis configuration file")
var genesisPrint = flag.Bool("G", false, "Print genesis ID")
var versionCheck = flag.Bool("v", false, "Display and write current build version and exit")
var branchCheck = flag.Bool("b", false, "Display the git branch behind the build")
var channelCheck = flag.Bool("c", false, "Display and release channel behind the build")
var initAndExit = flag.Bool("x", false, "Initialize the ledger and exit")
var logToStdout = flag.Bool("o", false, "Write to stdout instead of node.log by overriding config.LogSizeLimit to 0")
var peerOverride = flag.String("p", "", "Override phonebook with peer ip:port (or semicolon separated list: ip:port;ip:port;ip:port...)")
var listenIP = flag.String("l", "", "Override config.EndpointAddress (REST listening address) with ip:port")
var sessionGUID = flag.String("s", "", "Telemetry Session GUID to use")
var telemetryOverride = flag.String("t", "", `Override telemetry setting if supported (Use "true", "false", "0" or "1")`)
var seed = flag.String("seed", "", "input to math/rand.Seed()")

const (
	defaultStaticTelemetryStartupTimeout = 5 * time.Second
	defaultStaticTelemetryBGDialRetry    = 1 * time.Minute
)

func main() {
	flag.Parse()
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	dataDir := resolveDataDir()
	absolutePath, absPathErr := filepath.Abs(dataDir)
	config.DataDirectory = absolutePath

	if *seed != "" {
		seedVal, err := strconv.ParseInt(*seed, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad seed %#v: %s\n", *seed, err)
			return 1
		}
		rand.Seed(seedVal)
	} else {
		rand.Seed(time.Now().UnixNano())
	}

	if *versionCheck {
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

	// -b will print only the git branch and then exit
	if *branchCheck {
		fmt.Println(config.Branch)
		return 0
	}

	// -c will print only the release channel and then exit
	if *channelCheck {
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

	genesisPath := *genesisFile
	genesis, genesisText, err := loadGenesis(dataDir, genesisPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading genesis file (%s): %v", genesisPath, err)
		return 1
	}

	// -G will print only the genesis ID and then exit
	if *genesisPrint {
		fmt.Println(genesis.ID())
		return 0
	}

	// If data directory doesn't exist, we can't run. Don't bother trying.
	if _, err1 := os.Stat(absolutePath); err1 != nil {
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

	// Delete legacy indexer.sqlite files if they happen to exist
	checkAndDeleteIndexerFile := func(fileName string) {
		indexerDBFilePath := filepath.Join(absolutePath, genesis.ID(), fileName)

		if util.FileExists(indexerDBFilePath) {
			if idxFileRemoveErr := os.Remove(indexerDBFilePath); idxFileRemoveErr != nil {
				fmt.Fprintf(os.Stderr, "Error removing %s file from data directory: %v\n", fileName, idxFileRemoveErr)
			} else {
				fmt.Fprintf(os.Stdout, "Removed legacy %s file from data directory\n", fileName)
			}
		}
	}

	checkAndDeleteIndexerFile("indexer.sqlite")
	checkAndDeleteIndexerFile("indexer.sqlite-shm")
	checkAndDeleteIndexerFile("indexer.sqlite-wal")

	cfg, migrationResults, err := config.LoadConfigFromDiskWithMigrations(absolutePath)
	if err != nil && !os.IsNotExist(err) {
		// log is not setup yet, this will log to stderr
		log.Fatalf("Cannot load config: %v", err)
	}

	// log is not setup yet
	fmt.Printf("Config loaded from %s\n", absolutePath)
	fmt.Println("Configuration after loading/defaults merge: ")
	err = json.NewEncoder(os.Stdout).Encode(cfg)
	if err != nil {
		fmt.Println("Error encoding config: ", err)
	}

	// set soft memory limit, if configured
	if cfg.GoMemLimit > 0 {
		debug.SetMemoryLimit(int64(cfg.GoMemLimit))
	}

	_, err = cfg.ValidateDNSBootstrapArray(genesis.Network)
	if err != nil {
		// log is not setup yet, this will log to stderr
		log.Fatalf("Error validating DNSBootstrap input: %v", err)
	}

	// Apply network-specific consensus overrides, noting the configurable consensus protocols file
	// takes precedence over network-specific overrides.
	config.ApplyShorterUpgradeRoundsForDevNetworks(genesis.Network)

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
		root, err1 := config.GetGlobalConfigFileRoot()
		var cfgDir *string
		if err1 == nil {
			cfgDir = &root
		}
		telemetryConfig, err1 := logging.EnsureTelemetryConfig(&dataDir, cfgDir)
		config.AnnotateTelemetry(&telemetryConfig, genesis.ID())
		if err1 != nil {
			if os.IsPermission(err1) {
				fmt.Fprintf(os.Stderr, "permission error on accessing telemetry config: %v", err1)
			} else {
				fmt.Fprintf(os.Stderr, "error loading telemetry config: %v", err1)
			}
			return 1
		}
		fmt.Fprintf(os.Stdout, "Telemetry configured from '%s'\n", telemetryConfig.FilePath)

		telemetryConfig.SendToLog = telemetryConfig.SendToLog || cfg.TelemetryToLog

		// Apply telemetry override.
		telemetryConfig.Enable = logging.TelemetryOverride(*telemetryOverride, &telemetryConfig)
		remoteTelemetryEnabled = telemetryConfig.Enable

		if telemetryConfig.Enable || telemetryConfig.SendToLog {
			// If session GUID specified, use it.
			if *sessionGUID != "" {
				if len(*sessionGUID) == 36 {
					telemetryConfig.SessionGUID = *sessionGUID
				}
			}
			// Try to enable remote telemetry now when URI is defined. Skip for DNS based telemetry.
			ctx, telemetryCancelFn := context.WithTimeout(context.Background(), defaultStaticTelemetryStartupTimeout)
			err1 = log.EnableTelemetryContext(ctx, telemetryConfig)
			telemetryCancelFn()
			if err1 != nil {
				fmt.Fprintln(os.Stdout, "error creating telemetry hook", err1)

				// Remote telemetry init loop
				go func() {
					for {
						time.Sleep(defaultStaticTelemetryBGDialRetry)
						// Try to enable remote telemetry now when URI is defined. Skip for DNS based telemetry.
						err1 := log.EnableTelemetryContext(context.Background(), telemetryConfig)
						// Error occurs only if URI is defined and we need to retry later
						if err1 == nil {
							// Remote telemetry enabled or empty static URI, stop retrying
							return
						}
						fmt.Fprintln(os.Stdout, "error creating telemetry hook", err1)
						// Try to reenable every minute
					}
				}()
			}
		}
	}

	s := algod.Server{
		RootPath: absolutePath,
		Genesis:  genesis,
	}

	if !cfg.DisableAPIAuth {
		// Generate a REST API token if one was not provided
		apiToken, wroteNewToken, err2 := tokens.ValidateOrGenerateAPIToken(s.RootPath, tokens.AlgodTokenFilename)

		if err2 != nil {
			log.Fatalf("API token error: %v", err2)
		}

		if wroteNewToken {
			fmt.Printf("No REST API Token found. Generated token: %s\n", apiToken)
		}
	} else {
		fmt.Printf("Public (non-admin) API authentication disabled. %s not generated\n", tokens.AlgodTokenFilename)
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
	if *listenIP != "" {
		cfg.EndpointAddress = *listenIP
	}

	// If overriding peers, disable SRV lookup
	telemetryDNSBootstrapID := cfg.DNSBootstrapID
	var peerOverrideArray []string
	if *peerOverride != "" {
		peerOverrideArray = strings.Split(*peerOverride, ";")
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
			addr, addrErr := addr.ParseHostOrURLOrMultiaddr(peer)
			if addrErr != nil {
				fmt.Fprintf(os.Stderr, "Provided command line parameter '%s' is not a valid host:port pair\n", peer)
				return 1
			}
			peerOverrideArray[idx] = addr
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
		ex, err1 := os.Executable()
		if err1 != nil {
			log.Errorf("cannot locate node executable: %s", err1)
		} else {
			phonebookDirs := []string{filepath.Dir(ex), dataDir}
			for _, phonebookDir := range phonebookDirs {
				phonebookAddresses, err1 = config.LoadPhonebook(phonebookDir)
				if err1 == nil {
					log.Debugf("Static phonebook loaded from %s", phonebookDir)
					break
				} else {
					log.Debugf("Cannot load static phonebook from %s dir: %v", phonebookDir, err1)
				}
			}
		}
	}

	if logToStdout != nil && *logToStdout {
		cfg.LogSizeLimit = 0
	}

	err = s.Initialize(cfg, phonebookAddresses, string(genesisText), migrationResults)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		log.Error(err)
		return 1
	}

	if *initAndExit {
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
			toolsnet.StartTelemetryURIUpdateService(time.Minute, cfgCopy, s.Genesis.Network, log, done)
		}

		currentVersion := config.GetCurrentVersion()
		var overrides []telemetryspec.NameValue
		for name, val := range config.GetNonDefaultConfigValues(cfg, startupConfigCheckFields) {
			overrides = append(overrides, telemetryspec.NameValue{Name: name, Value: val})
		}
		startupDetails := telemetryspec.StartupEventDetails{
			Version:      currentVersion.String(),
			CommitHash:   currentVersion.CommitHash,
			Branch:       currentVersion.Branch,
			Channel:      currentVersion.Channel,
			InstanceHash: crypto.Hash([]byte(absolutePath)).String(),
			Overrides:    overrides,
		}

		log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.StartupEvent, startupDetails)

		// Send a heartbeat event every 10 minutes as a sign of life
		go func() {
			var interval time.Duration
			defaultIntervalSecs := config.GetDefaultLocal().HeartbeatUpdateInterval
			switch {
			case cfg.HeartbeatUpdateInterval <= 0: // use default
				interval = time.Second * time.Duration(defaultIntervalSecs)
			case cfg.HeartbeatUpdateInterval < 60: // min frequency 1 minute
				interval = time.Minute
			default:
				interval = time.Second * time.Duration(cfg.HeartbeatUpdateInterval)
			}
			ticker := time.NewTicker(interval)
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

var startupConfigCheckFields = []string{
	"AgreementIncomingBundlesQueueLength",
	"AgreementIncomingProposalsQueueLength",
	"AgreementIncomingVotesQueueLength",
	"BroadcastConnectionsLimit",
	"CatchupBlockValidateMode",
	"ConnectionsRateLimitingCount",
	"ConnectionsRateLimitingWindowSeconds",
	"GossipFanout",
	"IncomingConnectionsLimit",
	"IncomingMessageFilterBucketCount",
	"IncomingMessageFilterBucketSize",
	"LedgerSynchronousMode",
	"MaxAcctLookback",
	"MaxConnectionsPerIP",
	"OutgoingMessageFilterBucketCount",
	"OutgoingMessageFilterBucketSize",
	"ProposalAssemblyTime",
	"ReservedFDs",
	"TxPoolExponentialIncreaseFactor",
	"TxPoolSize",
	"VerifiedTranscationsCacheSize",
	"EnableP2P",
	"EnableP2PHybridMode",
}

func resolveDataDir() string {
	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if dataDirectory == nil || *dataDirectory == "" {
		dir = os.Getenv("ALGORAND_DATA")
	} else {
		dir = *dataDirectory
	}
	return dir
}

func loadGenesis(dataDir string, genesisPath string) (bookkeeping.Genesis, string, error) {
	if genesisPath == "" {
		genesisPath = filepath.Join(dataDir, config.GenesisJSONFile)
	}
	genesisText, err := os.ReadFile(genesisPath)
	if err != nil {
		return bookkeeping.Genesis{}, "", err
	}
	var genesis bookkeeping.Genesis
	err = protocol.DecodeJSON(genesisText, &genesis)
	if err != nil {
		return bookkeeping.Genesis{}, "", err
	}
	return genesis, string(genesisText), nil
}
