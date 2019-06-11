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
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/algorand/go-algorand/cmd/kmd/codes"
	"github.com/algorand/go-algorand/daemon/kmd"
	"github.com/algorand/go-algorand/daemon/kmd/server"
	"github.com/algorand/go-algorand/logging"
)

const (
	kmdLogFileName = "kmd.log"
	kmdLogFilePerm = 0640
)

func main() {
	dataDir := flag.String("d", "", "kmd data directory")
	timeoutSecs := flag.Uint("t", 0, "number of seconds after which to kill kmd if there are no requests. 0 means no timeout.")
	flag.Parse()

	// Use logging package instead of stdin/stdout
	log := logging.NewLogger()
	log.SetLevel(logging.Info)

	// Validate flags
	if *dataDir == "" {
		log.Errorf("dataDir (-d) is a required argument")
		os.Exit(codes.ExitCodeKMDInvalidArgs)
	}

	// Parse timeout duration. 0 timeout -> nil timeout
	var timeout *time.Duration
	if *timeoutSecs != 0 {
		t := time.Duration(*timeoutSecs) * time.Second
		timeout = &t
	}

	// We have a dataDir now, so use log files
	kmdLogFilePath := filepath.Join(*dataDir, kmdLogFileName)
	kmdLogFileMode := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	logFile, err := os.OpenFile(kmdLogFilePath, kmdLogFileMode, kmdLogFilePerm)
	if err != nil {
		log.Errorf("failed to open log file: %s", err)
		os.Exit(codes.ExitCodeKMDLogError)
	}
	log.SetOutput(logFile)

	// Prevent swapping with mlockall if supported by the platform
	tryMlockall(log)

	// Create a "kill" channel to allow the server to shut down gracefully
	kill := make(chan os.Signal)

	// Timeouts can also send on the kill channel; because signal.Notify
	// will not block, this shouldn't cause an issue. From docs: "Package
	// signal will not block sending to c"
	signal.Notify(kill, os.Interrupt, unix.SIGTERM, unix.SIGINT)
	signal.Ignore(unix.SIGHUP)

	// Build a kmd StartConfig
	startConfig := kmd.StartConfig{
		DataDir: *dataDir,
		Kill:    kill,
		Log:     log,
		Timeout: timeout,
	}

	// Start the kmd server
	died, sock, err := kmd.Start(startConfig)
	if err == server.ErrAlreadyRunning {
		log.Errorf("couldn't start kmd: %s", err)
		os.Exit(codes.ExitCodeKMDAlreadyRunning)
	}
	if err != nil {
		log.Errorf("couldn't start kmd: %s", err)
		os.Exit(codes.ExitCodeKMDError)
	}

	log.Infof("started kmd on sock: %s", sock)

	// Wait until the kmd server exits
	<-died
	log.Infof("kmd server died. exiting...")
}
