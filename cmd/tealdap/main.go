// Copyright (C) 2019-2023 Algorand, Inc.
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

var networkInterface string
var debuggerPort uint64

func init() {
	rootCmd.PersistentFlags().StringVar(&networkInterface, "listen", "127.0.0.1", "Network interface to listen to")
	rootCmd.PersistentFlags().Uint64Var(&debuggerPort, "port", 22015, "Debugger port to listen to")
}

var rootCmd = &cobra.Command{
	Use:   "tealdap",
	Short: "Algorand TEAL Debugger (supporting Debug Adapter Protocol)",
	Long:  `Debug a ...`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

func main() {
	fmt.Println("start debugging")
	os.Exit(0)
}
