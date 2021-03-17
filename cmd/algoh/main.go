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
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/shared/algoh"
	"github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/util"
)

var dataDirectory = flag.String("d", "", "Root Algorand daemon data path")
var versionCheck = flag.Bool("v", false, "Display and write current build version and exit")
var telemetryOverride = flag.String("t", "", `Override telemetry setting if supported (Use "true", "false", "0" or "1")`)

// the following flags aren't being used by the algoh, but are needed so that the flag package won't complain that
// these flags were provided but were not defined. We grab all the input flags and pass these downstream to the algod executable
// as an input arguments.
var peerOverride = flag.String("p", "", "Override phonebook with peer ip:port (or semicolon separated list: ip:port;ip:port;ip:port...)")
var listenIP = flag.String("l", "", "Override config.EndpointAddress (REST listening address) with ip:port")
var seed = flag.String("seed", "", "input to math/rand.Seed()")
var genesisFile = flag.String("g", "", "Genesis configuration file")

const algodFileName = "algod"
const goalFileName = "goal"

var exeDir string

func init() {
}

type stdCollector struct {
	output string
}

func (c *stdCollector) Write(p []byte) (n int, err error) {
	s := string(p)
	c.output += s
	return len(p), nil
}

func main() {
	blockWatcherInitialized := false
	flag.Parse()
	nc := getNodeController()

	genesis, err := nc.GetGenesis()
	if err != nil {
		fmt.Fprintln(os.Stdout, "error loading telemetry config", err)
		return
	}

	dataDir := ensureDataDir()
	absolutePath, absPathErr := filepath.Abs(dataDir)
	config.UpdateVersionDataDir(absolutePath)

	if *versionCheck {
		fmt.Println(config.FormatVersionAndLicense())
		return
	}

	// If data directory doesn't exist, we can't run. Don't bother trying.
	if len(dataDir) == 0 {
		fmt.Fprintln(os.Stderr, "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment.")
		os.Exit(1)
	}

	if absPathErr != nil {
		reportErrorf("Can't convert data directory's path to absolute, %v\n", dataDir)
	}

	algodConfig, err := config.LoadConfigFromDisk(absolutePath)

	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Cannot load config: %v", err)
	}

	if _, err := os.Stat(absolutePath); err != nil {
		reportErrorf("Data directory %s does not appear to be valid\n", dataDir)
	}

	algohConfig, err := algoh.LoadConfigFromFile(filepath.Join(dataDir, algoh.ConfigFilename))
	if err != nil && !os.IsNotExist(err) {
		reportErrorf("Error loading configuration, %v\n", err)
	}
	validateConfig(algohConfig)

	done := make(chan struct{})
	log := logging.Base()
	configureLogging(genesis, log, absolutePath, done, algodConfig)
	defer log.CloseTelemetry()

	exeDir, err = util.ExeDir()
	if err != nil {
		reportErrorf("Error getting ExeDir: %v\n", err)
	}

	var errorOutput stdCollector
	var output stdCollector
	go func() {
		args := make([]string, len(os.Args)-1)
		copy(args, os.Args[1:]) // Copy our arguments (skip the executable)
		if log.GetTelemetryEnabled() {
			args = append(args, "-s", log.GetTelemetrySession())
		}
		algodPath := filepath.Join(exeDir, algodFileName)
		cmd := exec.Command(algodPath, args...)
		cmd.Stderr = &errorOutput
		cmd.Stdout = &output

		err = cmd.Start()
		if err != nil {
			reportErrorf("error starting algod: %v", err)
		}
		err = cmd.Wait()
		if err != nil {
			captureErrorLogs(algohConfig, errorOutput, output, absolutePath, true)
			reportErrorf("error waiting for algod: %v", err)
		}
		close(done)

		// capture logs if algod terminated prior to blockWatcher starting
		if !blockWatcherInitialized {
			captureErrorLogs(algohConfig, errorOutput, output, absolutePath, true)
		}

		log.Infoln("++++++++++++++++++++++++++++++++++++++++")
		log.Infoln("algod exited.  Exiting...")
		log.Infoln("++++++++++++++++++++++++++++++++++++++++")
	}()

	// Set up error capturing
	defer func() {
		captureErrorLogs(algohConfig, errorOutput, output, absolutePath, false)
	}()

	// Handle signals cleanly
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)
	go func() {
		sig := <-c
		fmt.Printf("Exiting algoh on %v\n", sig)
		os.Exit(0)
	}()

	algodClient, err := waitForClient(nc, done)
	if err != nil {
		reportErrorf("error creating Rest Client: %v\n", err)
	}

	var wg sync.WaitGroup

	deadMan := makeDeadManWatcher(algohConfig.DeadManTimeSec, algodClient, algohConfig.UploadOnError, done, &wg, algodConfig)
	wg.Add(1)

	listeners := []blockListener{deadMan}
	if algohConfig.SendBlockStats {
		// Note: Resume can be implemented here. Store blockListener state and set curBlock based on latestBlock/lastBlock.
		listeners = append(listeners, &blockstats{log: logging.Base()})
	}

	delayBetweenStatusChecks := time.Duration(algohConfig.StatusDelayMS) * time.Millisecond
	stallDetectionDelay := time.Duration(algohConfig.StallDelayMS) * time.Millisecond

	runBlockWatcher(listeners, algodClient, done, &wg, delayBetweenStatusChecks, stallDetectionDelay)
	wg.Add(1)

	blockWatcherInitialized = true

	wg.Wait()
	fmt.Println("Exiting algoh normally...")
}

func waitForClient(nc nodecontrol.NodeController, abort chan struct{}) (client client.RestClient, err error) {
	for {
		client, err = getRestClient(nc)
		if err == nil {
			return client, nil
		}

		select {
		case <-abort:
			err = fmt.Errorf("aborted waiting for client")
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func getRestClient(nc nodecontrol.NodeController) (rc client.RestClient, err error) {
	// Fetch the algod client
	algodClient, err := nc.AlgodClient()
	if err != nil {
		return
	}

	// Make sure the node is running
	_, err = algodClient.Status()
	if err != nil {
		return
	}

	return algodClient, nil
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

func ensureDataDir() string {
	// Get the target data directory to work against,
	// then handle the scenario where no data directory is provided.
	dir := resolveDataDir()
	if dir == "" {
		reportErrorf("Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment. Exiting.\n")
	}
	return dir
}

func getNodeController() nodecontrol.NodeController {
	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}
	nc := nodecontrol.MakeNodeController(binDir, ensureDataDir())
	return nc
}

func configureLogging(genesis bookkeeping.Genesis, log logging.Logger, rootPath string, abort chan struct{}, algodConfig config.Local) {
	log = logging.Base()

	liveLog := fmt.Sprintf("%s/host.log", rootPath)
	fmt.Println("Logging to: ", liveLog)
	writer, err := os.OpenFile(liveLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("configureLogging: cannot open log file %v", err))
	}
	log.SetOutput(writer)
	log.SetJSONFormatter()
	log.SetLevel(logging.Debug)

	initTelemetry(genesis, log, rootPath, abort, algodConfig)

	// if we have the telemetry enabled, we want to use it's sessionid as part of the
	// collected metrics decorations.
	fmt.Fprintln(writer, "++++++++++++++++++++++++++++++++++++++++")
	fmt.Fprintln(writer, "Logging Starting")
	fmt.Fprintln(writer, "++++++++++++++++++++++++++++++++++++++++")
}

func initTelemetry(genesis bookkeeping.Genesis, log logging.Logger, dataDirectory string, abort chan struct{}, algodConfig config.Local) {
	// Enable telemetry hook in daemon to send logs to cloud
	// If ALGOTEST env variable is set, telemetry is disabled - allows disabling telemetry for tests
	isTest := os.Getenv("ALGOTEST") != ""
	if !isTest {
		telemetryConfig, err := logging.EnsureTelemetryConfig(&dataDirectory, genesis.ID())
		if err != nil {
			fmt.Fprintln(os.Stdout, "error loading telemetry config", err)
			return
		}
		fmt.Fprintf(os.Stdout, "algoh telemetry configured from '%s'\n", telemetryConfig.FilePath)

		// Apply telemetry override.
		telemetryConfig.Enable = logging.TelemetryOverride(*telemetryOverride, &telemetryConfig)

		if telemetryConfig.Enable {
			err = log.EnableTelemetry(telemetryConfig)
			if err != nil {
				fmt.Fprintln(os.Stdout, "error creating telemetry hook", err)
				return
			}

			if log.GetTelemetryEnabled() {

				// If the telemetry URI is not set, periodically check SRV records for new telemetry URI
				if log.GetTelemetryURI() == "" {
					network.StartTelemetryURIUpdateService(time.Minute, algodConfig, genesis.Network, log, abort)
				}

				// For privacy concerns, we don't want to provide the full data directory to telemetry.
				// But to be useful where multiple nodes are installed for convenience, we should be
				// able to discriminate between instances with the last letter of the path.
				if dataDirectory != "" {
					dataDirectory = dataDirectory[len(dataDirectory)-1:]
				}

				currentVersion := config.GetCurrentVersion()
				startupDetails := telemetryspec.StartupEventDetails{
					Version:      currentVersion.String(),
					CommitHash:   currentVersion.CommitHash,
					Branch:       currentVersion.Branch,
					Channel:      currentVersion.Channel,
					InstanceHash: crypto.Hash([]byte(dataDirectory)).String(),
				}

				log.EventWithDetails(telemetryspec.HostApplicationState, telemetryspec.StartupEvent, startupDetails)
			}
		}
	}
}

// capture algod error output and optionally upload logs
func captureErrorLogs(algohConfig algoh.HostConfig, errorOutput stdCollector, output stdCollector, absolutePath string, errorCondition bool) {
	if errorOutput.output != "" {
		fmt.Fprintf(os.Stdout, "errorOutput.output: `%s`\n", errorOutput.output)
		errorCondition = true
		fmt.Fprintf(os.Stderr, errorOutput.output)
		details := telemetryspec.ErrorOutputEventDetails{
			Error:  errorOutput.output,
			Output: output.output,
		}
		log.EventWithDetails(telemetryspec.HostApplicationState, telemetryspec.ErrorOutputEvent, details)

		// Write stdout & stderr streams to disk
		_ = ioutil.WriteFile(filepath.Join(absolutePath, nodecontrol.StdOutFilename), []byte(output.output), os.ModePerm)
		_ = ioutil.WriteFile(filepath.Join(absolutePath, nodecontrol.StdErrFilename), []byte(errorOutput.output), os.ModePerm)
	}
	if errorCondition && algohConfig.UploadOnError {
		fmt.Fprintf(os.Stdout, "Uploading logs...\n")
		sendLogs()
	}
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	logging.Base().Fatalf(format, args...)
}

func sendLogs() {
	var args []string
	args = append(args, "-d", ensureDataDir())
	args = append(args, "logging", "send")

	goalPath := filepath.Join(exeDir, goalFileName)
	cmd := exec.Command(goalPath, args...)

	err := cmd.Run()
	if err != nil {
		reportErrorf("Error sending logs: %v\n", err)
	}
}

func validateConfig(config algoh.HostConfig) {
	// Enforce a reasonable deadman timeout
	if config.DeadManTimeSec > 0 && config.DeadManTimeSec < 30 {
		reportErrorf("Config.DeadManTimeSec should be >= 30 seconds (set to %v)\n", config.DeadManTimeSec)
	}
}
