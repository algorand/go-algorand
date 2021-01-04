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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var log *logrus.Logger

func init() {
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(getCmd)

	log = logrus.New()

	log.Out = os.Stdout
	log.SetLevel(logrus.DebugLevel)
}

var rootCmd = &cobra.Command{
	Use:   "nodecfg",
	Short: "CLI for applying Algorand node configuration to a host",
	Long:  `CLI for retrieving and applying Algorand node configuration to the current host machine`,
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

func reportErrorf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	// log.Warnf(format, args...)
	os.Exit(1)
}

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	// log.Infof(format, args...)
}
