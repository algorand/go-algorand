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

package main

import (
	// "fmt"

	"github.com/spf13/cobra"

	// "github.com/algorand/go-algorand/libgoal"
)

var (
	appID uint64
	appCreator string
)

func init() {
	appCmd.AddCommand(createAppCmd)
	appCmd.AddCommand(deleteAppCmd)
	appCmd.AddCommand(callAppCmd)

	appCmd.Flags().Uint64Var(&appID, "app-id", 0, "Asset ID")
	appCmd.Flags().StringVar(&appCreator, "creator", "", "Account to create the asset")
}

var appCmd = &cobra.Command{
	Use: "app",
	Short: "Manage applications",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var createAppCmd = &cobra.Command{
	Use: "create",
	Short: "Create an application",
	Long: `Issue a transaction that creates an application`,
	Args: validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		client := ensureFullClient(dataDir)

		// Construct the transaction
		tx, err := client.MakeUnsignedAppCreateTx(creator)
		if err != nil {
			reportErrorf("Cannot create application txn: %v", err)
		}
	},
}

var deleteAppCmd = &cobra.Command{}
var callAppCmd = &cobra.Command{}
