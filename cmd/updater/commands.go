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

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/logging"
)

var log = logging.Base()

var channel string

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(getToolsCmd)

	rootCmd.PersistentFlags().StringVarP(&channel, "channel", "c", "", "Channel on which to publish the update (required)")
	rootCmd.MarkPersistentFlagRequired("channel")
}

var rootCmd = &cobra.Command{
	Use:   "updater",
	Short: "updater latest|get|send",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help

		cmd.HelpFunc()(cmd, args)
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
