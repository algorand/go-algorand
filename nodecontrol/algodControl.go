// Copyright (C) 2019-2020 Algorand, Inc.
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

package nodecontrol

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/tokens"
)

// StdErrFilename is the name of the file in <datadir> where stderr will be captured if not redirected to host
const StdErrFilename = "algod-err.log"

// StdOutFilename is the name of the file in <datadir> where stdout will be captured if not redirected to host
const StdOutFilename = "algod-out.log"

// AlgodClient attempts to build a client.RestClient for communication with
// the algod REST API, but fails if we can't find the net file
func (nc NodeController) AlgodClient() (algodClient client.RestClient, err error) {
	algodAPIToken, err := tokens.GetAndValidateAPIToken(nc.algodDataDir, tokens.AlgodAdminTokenFilename)
	if err != nil {
		algodAPIToken, err = tokens.GetAndValidateAPIToken(nc.algodDataDir, tokens.AlgodTokenFilename)
		if err != nil {
			return
		}
	}

	// Fetch the server URL from the net file, if it exists
	algodURL, err := nc.ServerURL()
	if err != nil {
		return
	}

	// Build the client from the URL and API token
	algodClient = client.MakeRestClient(algodURL, algodAPIToken)
	return
}

// ServerURL returns the appropriate URL for the node under control
func (nc NodeController) ServerURL() (url.URL, error) {
	addr, err := nc.GetHostAddress()
	if err != nil {
		return url.URL{}, err
	}
	return url.URL{Scheme: "http", Host: addr}, nil
}

// GetHostAddress retrieves the REST address for the node from its algod.net file.
func (nc NodeController) GetHostAddress() (string, error) {
	// For now, we want the old behavior to 'just work';
	// so if data directory is not specified, we assume the default address of 127.0.0.1:8080
	if len(nc.algodDataDir) == 0 {
		return "127.0.0.1:8080", nil
	}
	return util.GetFirstLineFromFile(nc.algodNetFile)
}

// buildAlgodCommand
func (nc NodeController) buildAlgodCommand(args AlgodStartArgs) *exec.Cmd {
	startArgs := make([]string, 0)
	startArgs = append(startArgs, "-d")
	startArgs = append(startArgs, nc.algodDataDir)
	if len(args.TelemetryOverride) > 0 {
		startArgs = append(startArgs, "-t")
		startArgs = append(startArgs, args.TelemetryOverride)
	}

	// Parse peerDial and listenIP cmdline flags
	peerDial := args.PeerAddress
	if len(peerDial) > 0 {
		startArgs = append(startArgs, "-p")
		startArgs = append(startArgs, peerDial)
	}
	listenIP := args.ListenIP
	if len(listenIP) > 0 {
		startArgs = append(startArgs, "-l")
		startArgs = append(startArgs, listenIP)
	}

	// Check if we should be using algoh
	var cmd string
	if args.RunUnderHost {
		cmd = nc.algoh
	} else {
		cmd = nc.algod
	}

	return exec.Command(cmd, startArgs...)
}

// algodRunning returns a boolean indicating if algod is running
func (nc NodeController) algodRunning() (isRunning bool) {
	_, err := nc.GetAlgodPID()
	if err == nil {
		// no error means file already exists, and we just loaded its content.
		// check if we can communicate with it.
		algodClient, err := nc.AlgodClient()
		if err == nil {
			err = algodClient.HealthCheck()
			if err == nil {
				// yes, we can communicate with it.
				return true
			}
		}
	}
	return false
}

// StopAlgod reads the net file and kills the algod process
func (nc *NodeController) StopAlgod() (alreadyStopped bool, err error) {
	// Find algod PID
	algodPID, err := nc.GetAlgodPID()
	if err == nil {
		// Kill algod by PID
		err = killPID(int(algodPID))
		if err != nil {
			return
		}
	} else {
		err = nil
		alreadyStopped = true
	}
	return
}

// StartAlgod spins up an algod process and waits for it to begin
func (nc *NodeController) StartAlgod(args AlgodStartArgs) (alreadyRunning bool, err error) {
	// If algod is already running, we can't start again
	alreadyRunning = nc.algodRunning()
	if alreadyRunning {
		return alreadyRunning, nil
	}

	algodCmd := nc.buildAlgodCommand(args)

	var errLogger, outLogger *LaggedStdIo
	if args.RedirectOutput {
		errLogger = NewLaggedStdIo(os.Stderr, "algod")
		outLogger = NewLaggedStdIo(os.Stdout, "algod")
		algodCmd.Stderr = errLogger
		algodCmd.Stdout = outLogger
	} else if !args.RunUnderHost {
		// If not redirecting output to the host, we want to capture stderr and stdout to files
		files := nc.setAlgodCmdLogFiles(algodCmd)
		// Descriptors will get dup'd after exec, so OK to close when we return
		for _, file := range files {
			defer file.Close()
		}
	}

	err = algodCmd.Start()
	if err != nil {
		return
	}

	if args.RedirectOutput {
		// update the logger output prefix with the process id.
		linePrefix := fmt.Sprintf("algod(%d)", algodCmd.Process.Pid)
		errLogger.SetLinePrefix(linePrefix)
		outLogger.SetLinePrefix(linePrefix)
	}
	// Wait on the algod process and check if exits
	algodExitChan := make(chan error, 1)
	startAlgodCompletedChan := make(chan struct{})
	defer close(startAlgodCompletedChan)
	go func() {
		// this Wait call is important even beyond the scope of this function; it allows the system to
		// move the process from a "zombie" state into "done" state, and is required for the Signal(0) test.
		err := algodCmd.Wait()
		select {
		case <-startAlgodCompletedChan:
			// we've already exited this function, so we want to report to the error to the callback.
			if args.ExitErrorCallback != nil {
				args.ExitErrorCallback(nc, err)
			}
		default:
		}
		algodExitChan <- err
	}()
	success := false
	for !success {
		select {
		case err := <-algodExitChan:
			err = &errAlgodExitedEarly{err}
			return false, err
		case <-time.After(time.Millisecond * 100):
			// If we can't talk to the API yet, spin
			algodClient, err := nc.AlgodClient()
			if err != nil {
				continue
			}

			// See if the server is up
			err = algodClient.HealthCheck()
			if err == nil {
				success = true
				continue
			}

			// Perhaps we're running an old version with no HealthCheck endpoint?
			_, err = algodClient.Status()
			if err == nil {
				success = true
			}
		}
	}
	return
}

// GetListeningAddress retrieves the listening address from the algod-listen.net file for the node
func (nc NodeController) GetListeningAddress() (string, error) {
	return util.GetFirstLineFromFile(nc.algodNetListenFile)
}

// GetAlgodPID returns the PID from the algod.pid file in the node's data directory, or an error
func (nc NodeController) GetAlgodPID() (pid int64, err error) {
	// Pull out the PID, ignoring newlines
	pidStr, err := util.GetFirstLineFromFile(nc.algodPidFile)
	if err != nil {
		return -1, err
	}
	// Parse as an integer
	pid, err = strconv.ParseInt(pidStr, 10, 32)
	return
}

// GetDataDir provides read-only access to the controller's data directory
func (nc NodeController) GetDataDir() string {
	return nc.algodDataDir
}

// GetAlgodPath provides read-only access to the controller's algod instance
func (nc NodeController) GetAlgodPath() string {
	return nc.algod
}

// Clone creates a new DataDir based on the controller's DataDir; if copyLedger is true, we'll clone the ledger.sqlite file
func (nc NodeController) Clone(targetDir string, copyLedger bool) (err error) {
	os.RemoveAll(targetDir)
	err = os.Mkdir(targetDir, 0700)
	if err != nil && !os.IsExist(err) {
		return
	}

	// Copy Core Files, silently failing to copy any that don't exist
	files := []string{config.GenesisJSONFile, config.ConfigFilename, config.PhonebookFilename}
	for _, file := range files {
		src := filepath.Join(nc.algodDataDir, file)
		if util.FileExists(src) {
			dest := filepath.Join(targetDir, file)
			_, err = util.CopyFile(src, dest)
			if err != nil {
				switch err.(type) {
				case *os.PathError:
					continue
				default:
					return
				}
			}
		}
	}

	// Copy Ledger Files if requested
	if copyLedger {
		var genesis bookkeeping.Genesis
		genesis, err = nc.readGenesisJSON(filepath.Join(nc.algodDataDir, config.GenesisJSONFile))
		if err != nil {
			return
		}

		genesisFolder := filepath.Join(nc.algodDataDir, genesis.ID())
		targetGenesisFolder := filepath.Join(targetDir, genesis.ID())
		err = os.Mkdir(targetGenesisFolder, 0770)
		if err != nil {
			return
		}

		files := []string{"ledger.sqlite"}
		for _, file := range files {
			src := filepath.Join(genesisFolder, file)
			dest := filepath.Join(targetGenesisFolder, file)
			_, err = util.CopyFile(src, dest)
			if err != nil {
				return
			}
		}
	}

	return
}

// GetGenesis returns the current genesis for our instance
func (nc NodeController) GetGenesis() (bookkeeping.Genesis, error) {
	var genesis bookkeeping.Genesis

	genesisFile := filepath.Join(nc.GetDataDir(), config.GenesisJSONFile)
	genesisText, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		return genesis, err
	}

	err = protocol.DecodeJSON(genesisText, &genesis)
	if err != nil {
		return genesis, err
	}

	return genesis, nil
}

// GetGenesisDir returns the current genesis directory for our instance
func (nc NodeController) GetGenesisDir() (string, error) {
	genesis, err := nc.GetGenesis()
	if err != nil {
		return "", err
	}
	genesisDir := filepath.Join(nc.GetDataDir(), genesis.ID())
	return genesisDir, nil
}

func (nc NodeController) setAlgodCmdLogFiles(cmd *exec.Cmd) (files []*os.File) {
	{ // Scoped to ensure err and out variables aren't mixed up
		errFileName := filepath.Join(nc.algodDataDir, StdErrFilename)
		errFile, err := os.OpenFile(errFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			cmd.Stderr = errFile
			files = append(files, errFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stderr: %v\n", err)
		}
	}
	{
		outFileName := filepath.Join(nc.algodDataDir, StdOutFilename)
		outFile, err := os.OpenFile(outFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			cmd.Stdout = outFile
			files = append(files, outFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stdout: %v\n", err)
		}
	}
	return
}

func (nc NodeController) readGenesisJSON(genesisFile string) (genesisLedger bookkeeping.Genesis, err error) {
	// Load genesis
	genesisText, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		return
	}

	err = protocol.DecodeJSON(genesisText, &genesisLedger)
	return
}

// SetConsensus applies a new consensus settings which would get deployed before
// any of the nodes starts
func (nc NodeController) SetConsensus(consensus config.ConsensusProtocols) error {
	return config.SaveConfigurableConsensus(nc.algodDataDir, consensus)
}

// GetConsensus rebuild the consensus version from the data directroy
func (nc NodeController) GetConsensus() (config.ConsensusProtocols, error) {
	return config.PreloadConfigurableConsensusProtocols(nc.algodDataDir)
}

// Shutdown requests the node to shut itself down
func (nc NodeController) Shutdown() error {
	algodClient, err := nc.AlgodClient()
	if err == nil {
		err = algodClient.Shutdown()
	}
	return err
}
