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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/algorand/go-algorand/cmd/kmd/codes"
	"github.com/algorand/go-algorand/daemon/kmd/client"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/daemon/kmd/server"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/tokens"
)

const (
	// DefaultKMDDataDir is exported so tests can initialize it with config info
	DefaultKMDDataDir = "kmd-v0.5"
	// DefaultKMDDataDirPerms is exported so tests can initialize the default kmd data dir
	DefaultKMDDataDirPerms = 0700

	// kmdStdErrFilename is the name of the file in <kmddatadir> where stderr will be captured
	kmdStdErrFilename = "kmd-err.log"
	// kmdStdOutFilename is the name of the file in <kmddatadir> where stdout will be captured
	kmdStdOutFilename = "kmd-out.log"
)

// KMDController wraps directories and processes involved in running kmd
type KMDController struct {
	kmd        string // path to binary
	kmdDataDir string
	kmdPIDPath string
}

// MakeKMDController initializes a KMDController
func MakeKMDController(kmdDataDir, binDir string) *KMDController {
	kc := &KMDController{}
	kc.SetKMDBinDir(binDir)
	kc.SetKMDDataDir(kmdDataDir)
	return kc
}

// SetKMDBinDir updates the KMDController for a binDir that contains `kmd`
func (kc *KMDController) SetKMDBinDir(binDir string) {
	kc.kmd = filepath.Join(binDir, "kmd")
}

// SetKMDDataDir updates the KMDController for a kmd data directory.
func (kc *KMDController) SetKMDDataDir(kmdDataDir string) {
	kc.kmdDataDir = kmdDataDir
	kc.kmdPIDPath = filepath.Join(kmdDataDir, server.PIDFilename)
}

// KMDClient reads an APIToken and netFile from the kmd dataDir, and then
// builds a KMDClient for the running kmd process
func (kc KMDController) KMDClient() (kmdClient client.KMDClient, err error) {
	// Grab the KMD API token
	apiToken, err := tokens.GetAndValidateAPIToken(kc.kmdDataDir, tokens.KmdTokenFilename)
	if err != nil {
		return
	}

	// Grab the socket file location
	netFile := filepath.Join(kc.kmdDataDir, server.NetFilename)
	sockPath, err := util.GetFirstLineFromFile(netFile)
	if err != nil {
		return
	}

	// Build the client
	kmdClient, err = client.MakeKMDClient(sockPath, apiToken)
	return
}

func (kc KMDController) buildKMDCommand(args KMDStartArgs) *exec.Cmd {
	var startArgs []string
	startArgs = append(startArgs, "-d")
	startArgs = append(startArgs, kc.kmdDataDir)
	startArgs = append(startArgs, "-t")
	startArgs = append(startArgs, fmt.Sprintf("%d", args.TimeoutSecs))
	return exec.Command(kc.kmd, startArgs...)
}

// GetKMDPID returns the PID from the kmd.pid file in the kmd data directory, or an error
func (kc KMDController) GetKMDPID() (pid int64, err error) {
	// Pull out the PID, ignoring newlines
	pidStr, err := util.GetFirstLineFromFile(kc.kmdPIDPath)
	if err != nil {
		return -1, err
	}
	// Parse as an integer
	pid, err = strconv.ParseInt(pidStr, 10, 32)
	return
}

// StopKMD reads the net file and kills the kmd process
func (kc *KMDController) StopKMD() (alreadyStopped bool, err error) {
	// Find kmd PID
	kmdPID, err := kc.GetKMDPID()
	if err == nil {
		// Kill kmd by PID
		err = killPID(int(kmdPID))
		if err != nil {
			return
		}
	} else {
		err = nil
		alreadyStopped = true
	}
	return
}

// cleanUpZombieKMD removes files that a kmd node that's not actually running
// might have left behind
func (kc KMDController) cleanUpZombieKMD() {
	if kc.kmdPIDPath != "" {
		os.Remove(kc.kmdPIDPath)
	}
}

func (kc *KMDController) setKmdCmdLogFiles(cmd *exec.Cmd) (files []*os.File) {
	{ // Scoped to ensure err and out variables aren't mixed up
		errFileName := filepath.Join(kc.kmdDataDir, kmdStdErrFilename)
		errFile, err := os.OpenFile(errFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err == nil {
			cmd.Stderr = errFile
			files = append(files, errFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stderr: %v\n", err)
		}
	}
	{
		outFileName := filepath.Join(kc.kmdDataDir, kmdStdOutFilename)
		outFile, err := os.OpenFile(outFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err == nil {
			cmd.Stdout = outFile
			files = append(files, outFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stdout: %v\n", err)
		}
	}
	return
}

// StartKMD spins up a kmd process and waits for it to begin
func (kc *KMDController) StartKMD(args KMDStartArgs) (alreadyRunning bool, err error) {
	// Optimistically check if kmd is already running
	pid, err := kc.GetKMDPID()
	if err == nil {
		// Got a PID. Is there actually a process running there?
		// "If sig is 0, then no signal is sent, but existence and permission
		// checks are still performed"
		err = util.KillProcess(int(pid), syscall.Signal(0))
		if err == nil {
			// Yup, return alreadyRunning = true
			return true, nil
		}
		// Nope, clean up the files the zombie may have left behind
		kc.cleanUpZombieKMD()
	}

	if !filepath.IsAbs(kc.kmdDataDir) {
		logging.Base().Errorf("%s: kmd data dir is not an absolute path, which is unsafe", kc.kmdDataDir)
		return false, errKMDDataDirNotAbs
	}
	dataDirStat, err := os.Stat(kc.kmdDataDir)
	if err == nil {
		if !dataDirStat.IsDir() {
			logging.Base().Errorf("%s: kmd data dir exists but is not a directory", kc.kmdDataDir)
			return false, errors.New("bad kmd data dir")
		}
		if (dataDirStat.Mode() & 0077) != 0 {
			logging.Base().Errorf("%s: kmd data dir exists but is too permissive (%o)", kc.kmdDataDir, dataDirStat.Mode()&0777)
			return false, errors.New("kmd data dir not secure")
		}
	} else {
		err = os.MkdirAll(kc.kmdDataDir, DefaultKMDDataDirPerms)
		if err != nil {
			logging.Base().Errorf("%s: kmd data dir err: %s", kc.kmdDataDir, err)
			return false, err
		}
	}

	// Try to start the kmd process
	kmdCmd := kc.buildKMDCommand(args)

	// Capture stderr and stdout to files
	files := kc.setKmdCmdLogFiles(kmdCmd)
	// Descriptors will get dup'd after exec, so OK to close when we return
	for _, file := range files {
		defer file.Close()
	}

	err = kmdCmd.Start()
	if err != nil {
		return
	}

	// Call kmdCmd.Wait() to clean up the process when it exits and report
	// why it exited
	c := make(chan error)
	go func() {
		c <- kmdCmd.Wait()
	}()

	// Wait for kmd to start
	success := false
	for !success {
		select {
		case err = <-c:
			// Try to extract an exit code
			exitError, ok := err.(*exec.ExitError)
			if !ok {
				return false, errKMDExitedEarly
			}
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode := ws.ExitStatus()

			// Check if we exited because kmd is already running
			if exitCode == codes.ExitCodeKMDAlreadyRunning {
				kmdClient, err := kc.KMDClient()
				if err != nil {
					// kmd told us it's running, but we couldn't construct a client.
					// we want to keep waiting until the kmd would write out the
					// file.
					continue
				}

				// See if the server is up by requesting the versions endpoint
				req := kmdapi.VersionsRequest{}
				resp := kmdapi.VersionsResponse{}
				err = kmdClient.DoV1Request(req, &resp)
				if err != nil {
					return false, err
				}
				// cool; kmd is up and running, and responding to version queries.
				return true, nil
			}

			// Fail on any other errors
			return false, errKMDExitedEarly
		case <-time.After(time.Millisecond * 100):
			// If we can't talk to the API yet, spin
			kmdClient, err := kc.KMDClient()
			if err != nil {
				continue
			}

			// See if the server is up by requesting the versions endpoint
			req := kmdapi.VersionsRequest{}
			resp := kmdapi.VersionsResponse{}
			err = kmdClient.DoV1Request(req, &resp)
			if err == nil {
				success = true
				continue
			}
		}
	}

	return
}
