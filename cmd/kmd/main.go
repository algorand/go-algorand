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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/algorand/go-algorand/cmd/kmd/codes"
	"github.com/algorand/go-algorand/daemon/kmd"
	"github.com/algorand/go-algorand/daemon/kmd/server"
	"github.com/algorand/go-algorand/logging"
)

const (
	kmdLogFileName = "kmd.log"
	kmdLogFilePerm = 0640
)

var (
	dataDir     string
	timeoutSecs uint64
)

func init() {
	kmdCmd.Flags().StringVarP(&dataDir, "data-dir", "d", "", "kmd data directory.")
	kmdCmd.Flags().Uint64VarP(&timeoutSecs, "timout-secs", "t", 0, "Number of seconds that kmd will run for before termination.")
	kmdCmd.MarkFlagRequired("data-dir")
}

var kmdCmd = &cobra.Command{
	Use:   "kmd",
	Short: "Key Management Daemon (kmd)",
	Long: `The Key Management Daemon (kmd) is a low level wallet and key management
tool. It works in conjunction with algod and goal to keep secrets safe. An
optional timeout flag will automatically terminate kmd after a number of
seconds has elapsed, allowing a simple way to ensure kmd will be shutdown in
a timely manner. This is a blocking command.`,
	Run: func(cmd *cobra.Command, args []string) {
		runKmd(dataDir, timeoutSecs)
	},
}

func runKmd(dataDir string, timeoutSecs uint64) {
	// Use logging package instead of stdin/stdout
	log := logging.NewLogger()
	log.SetLevel(logging.Info)

	// Parse timeout duration. 0 timeout -> nil timeout
	var timeout *time.Duration
	if timeoutSecs != 0 {
		t := time.Duration(timeoutSecs) * time.Second
		timeout = &t
	}

	// We have a dataDir now, so use log files
	kmdLogFilePath := filepath.Join(dataDir, kmdLogFileName)
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
	signal.Notify(kill, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)

	// Build a kmd StartConfig
	startConfig := kmd.StartConfig{
		DataDir: dataDir,
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

func main() {
	// Hidden command to generate docs in a given directory
	// kmd generate-docs [path]
	if len(os.Args) == 3 && os.Args[1] == "generate-docs" {
		err := doc.GenMarkdownTree(kmdCmd, os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := kmdCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
