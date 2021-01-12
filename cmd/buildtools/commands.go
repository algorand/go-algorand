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
)

func init() {
	rootCmd.AddCommand(genesisCmd)
}

var rootCmd = &cobra.Command{
	Use:   "buildtools",
	Short: "buildtools",
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

func reportInfoln(args ...interface{}) {
	fmt.Println(args...)
	// log.Infoln(args...)
}

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	// log.Infof(format, args...)
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	os.Exit(1)
}
