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
	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/util"
)

var kmdTimeoutSecs uint64

func init() {
	kmdCmd.AddCommand(startKMDCmd)
	startKMDCmd.Flags().Uint64VarP(&kmdTimeoutSecs, "timeout", "t", 0, "Number of seconds after which to shut down kmd if there are no requests; 0 means no timeout")
	kmdCmd.AddCommand(stopKMDCmd)
}

var kmdCmd = &cobra.Command{
	Use:   "kmd",
	Short: "Interact with kmd, the key management daemon",
	Long:  `Interact with kmd, the key management daemon. The key management daemon is a separate process from algod that is solely responsible for key management.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

func startKMDForDataDir(binDir, algodDataDir, kmdDataDir string) {
	nc := nodecontrol.MakeNodeController(binDir, algodDataDir)
	nc.SetKMDDataDir(kmdDataDir)
	nc.StopKMD()
	kmdArgs := nodecontrol.KMDStartArgs{
		TimeoutSecs: kmdTimeoutSecs,
	}
	kmdAlreadyRunning, err := nc.StartKMD(kmdArgs)
	if err != nil {
		reportErrorf(errorKMDFailedToStart, err)
	}
	if kmdAlreadyRunning {
		reportInfoln(infoKMDAlreadyStarted)
	} else {
		reportInfoln(infoKMDStarted)
	}
}

var startKMDCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the kmd process, or restart it with an updated timeout",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}

		onDataDirs(func(dataDir string) {
			kdd := resolveKmdDataDir(dataDir)
			startKMDForDataDir(binDir, dataDir, kdd)
		})
	},
}

var stopKMDCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the kmd process if it is running",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}

		onDataDirs(func(dataDir string) {
			nc := nodecontrol.MakeNodeController(binDir, dataDir)
			kdd := resolveKmdDataDir(dataDir)
			nc.SetKMDDataDir(kdd)

			kmdAlreadyStopped, err := nc.StopKMD()
			if err != nil {
				reportErrorf(errorKMDFailedToStop, err)
			}
			if kmdAlreadyStopped {
				reportInfoln(infoKMDAlreadyStopped)
			} else {
				reportInfoln(infoKMDStopped)
			}
		})
	},
}
