// Copyright (C) 2019 Algorand, Inc.
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
	"flag"
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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-algorand/util/tokens"
)

var dataDirectory = flag.String("d", "", "Root Algorand daemon data path")
var genesisFile = flag.String("g", "", "Genesis configuration file")
var genesisPrint = flag.Bool("G", false, "Print genesis ID")
var versionCheck = flag.Bool("v", false, "Display and write current build version and exit")
var branchCheck = flag.Bool("b", false, "Display the git branch behind the build")
var channelCheck = flag.Bool("c", false, "Display and release channel behind the build")
var initAndExit = flag.Bool("x", false, "Initialize the ledger and exit")
var peerOverride = flag.String("p", "", "Override phonebook with peer ip:port (or semicolon separated list: ip:port;ip:port;ip:port...)")
var listenIP = flag.String("l", "", "Override config.EndpointAddress (REST listening address) with ip:port")
var sessionGUID = flag.String("s", "", "Telemetry Session GUID to use")
var telemetryOverride = flag.String("t", "", `Override telemetry setting if supported (Use "true", "false", "0" or "1"`)
var seed = flag.String("seed", "", "input to math/rand.Seed()")

func main() {
	flag.Parse()

	dataDir := resolveDataDir()
	absolutePath, absPathErr := filepath.Abs(dataDir)
	config.UpdateVersionDataDir(absolutePath)

	if *seed != "" {
		seedVal, err := strconv.ParseInt(*seed, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad seed %#v: %s\n", *seed, err)
			os.Exit(1)
			return
		}
		rand.Seed(seedVal)
	} else {
		rand.Seed(time.Now().UnixNano())
	}

	version := config.GetCurrentVersion()
	if *versionCheck {
		fmt.Printf("%d\n%s.%s [%s] (commit #%s)\n%s\n", version.AsUInt64(), version.String(),
			version.Channel, version.Branch, version.GetCommitHash(), config.GetLicenseInfo())
		return
	}

	heartbeatGauge := metrics.MakeStringGauge()
	heartbeatGauge.Set("version", version.String())
	heartbeatGauge.Set("version-num", strconv.FormatUint(version.AsUInt64(), 10))
	heartbeatGauge.Set("channel", version.Channel)
	heartbeatGauge.Set("branch", version.Branch)
	heartbeatGauge.Set("commit-hash", version.GetCommitHash())

	if *branchCheck {
		fmt.Println(config.Branch)
		return
	}

	if *channelCheck {
		fmt.Println(config.Channel)
		return
	}

	// Don't fallback anymore - if not specified, we want to panic to force us to update our tooling and/or processes
	if len(dataDir) == 0 {
		fmt.Fprintln(os.Stderr, "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment.")
		os.Exit(1)
	}

	if absPathErr != nil {
		fmt.Fprintf(os.Stderr, "Can't convert data directory's path to absolute, %v\n", dataDir)
		os.Exit(1)
	}

	if *genesisFile == "" {
		*genesisFile = filepath.Join(dataDir, config.GenesisJSONFile)
	}

	// Load genesis
	genesisText, err := ioutil.ReadFile(*genesisFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read genesis file %s: %v\n", *genesisFile, err)
		os.Exit(1)
	}

	var genesis bookkeeping.Genesis
	err = protocol.DecodeJSON(genesisText, &genesis)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse genesis file %s: %v\n", *genesisFile, err)
		os.Exit(1)
	}

	if *genesisPrint {
		fmt.Println(genesis.ID())
		return
	}

	// If data directory doesn't exist, we can't run. Don't bother trying.
	if _, err := os.Stat(absolutePath); err != nil {
		fmt.Fprintf(os.Stderr, "Data directory %s does not appear to be valid\n", dataDir)
		os.Exit(1)
	}

	log := logging.Base()
	// before doing anything further, attempt to acquire the algod lock
	// to ensure this is the only node running against this data directory
	lockPath := filepath.Join(absolutePath, "algod.lock")
	fileLock := flock.New(lockPath)
	locked, err := fileLock.TryLock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unexpected failure in establishing algod.lock: %s \n", err.Error())
		os.Exit(1)
	}
	if !locked {
		fmt.Fprintln(os.Stderr, "failed to lock algod.lock; is an instance of algod already running in this data directory?")
		os.Exit(1)
	}
	defer fileLock.Unlock()

	// Enable telemetry hook in daemon to send logs to cloud
	// If ALGOTEST env variable is set, telemetry is disabled - allows disabling telemetry for tests
	isTest := os.Getenv("ALGOTEST") != ""
	if !isTest {
		telemetryConfig, err := logging.EnsureTelemetryConfig(&dataDir, genesis.ID())
		if err != nil {
			fmt.Fprintln(os.Stdout, "error loading telemetry config", err)
		}

		// Apply telemetry override.
		telemetryConfig.Enable = logging.TelemetryOverride(*telemetryOverride)

		if telemetryConfig.Enable {
			// If session GUID specified, use it.
			if *sessionGUID != "" {
				if len(*sessionGUID) == 36 {
					telemetryConfig.SessionGUID = *sessionGUID
				}
			}
			err = log.EnableTelemetry(telemetryConfig)
			if err != nil {
				fmt.Fprintln(os.Stdout, "error creating telemetry hook", err)
			}

			if log.GetTelemetryEnabled() {
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
				ticker := time.NewTicker(10 * time.Minute)
				go func() {
					values := make(map[string]string)
					for {
						metrics.DefaultRegistry().AddMetrics(values)

						heartbeatDetails := telemetryspec.HeartbeatEventDetails{
							Metrics: values,
						}

						log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.HeartbeatEvent, heartbeatDetails)
						<-ticker.C
					}
				}()
			}
		}
	}

	s := algod.Server{
		RootPath: absolutePath,
		Genesis:  genesis,
	}

	cfg, err := config.LoadConfigFromDisk(s.RootPath)
	if err != nil && !os.IsNotExist(err) {
		// log is not setup yet, this will log to stderr
		log.Fatalf("Cannot load config: %v", err)
	}

	// Generate a REST API token if one was not provided
	apiToken, wroteNewToken, err := tokens.ValidateOrGenerateAPIToken(s.RootPath, tokens.AlgodTokenFilename)

	if err != nil {
		log.Fatalf("API token error: %v", err)
	}

	if wroteNewToken {
		fmt.Printf("No REST API Token found. Generated token: %s\n", apiToken)
	}

	// Allow overriding default listening address
	if *listenIP != "" {
		cfg.EndpointAddress = *listenIP
	}

	// If overriding peers, disable SRV lookup
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

	err = s.Initialize(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		log.Error(err)
		return
	}

	if *initAndExit {
		return
	}

	if peerOverrideArray != nil {
		s.OverridePhonebook(peerOverrideArray...)
	}

	deadlockState := "enabled"
	if deadlock.Opts.Disable {
		deadlockState = "disabled"
	}
	fmt.Fprintf(os.Stdout, "Deadlock detection is set to: %s (Default state is '%s')\n", deadlockState, config.DefaultDeadlock)

	s.Start()
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
