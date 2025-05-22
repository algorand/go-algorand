// Copyright (C) 2019-2025 Algorand, Inc.
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
	"bytes"
	"strings"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/spf13/cobra"
)

var (
	boxName string
	// next    uint64 // declared in account.go
	// limit   uint64 // declared in account.go
	boxPrefix string
	boxValues bool
)

func init() {
	appCmd.AddCommand(appBoxCmd)

	appBoxCmd.AddCommand(appBoxInfoCmd)
	appBoxCmd.AddCommand(appBoxListCmd)
	appBoxCmd.PersistentFlags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	appBoxCmd.MarkFlagRequired("app-id")

	appBoxInfoCmd.Flags().StringVarP(&boxName, "name", "n", "", "Application box name. Use the same form as app-arg to name the box.")
	appBoxInfoCmd.MarkFlagRequired("name")

	appBoxListCmd.Flags().StringVarP(&boxPrefix, "prefix", "p", "", "Return only boxes that begin with the supplied prefix.")
	appBoxListCmd.Flags().StringVarP(&next, "next", "n", "", "The next-token returned from a previous call, used for pagination.")
	appBoxListCmd.Flags().Uint64VarP(&limit, "limit", "l", 0, "The maximum number of boxes to list. 0 means no limit.")
	appBoxListCmd.Flags().BoolVarP(&boxValues, "values", "v", false, "Request and display box values.")
}

var appBoxCmd = &cobra.Command{
	Use:   "box",
	Short: "Read application box data",
	Args:  cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var appBoxInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Retrieve information about an application box.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		_, client := getDataDirAndClient()

		// Ensure box name is specified
		if boxName == "" {
			reportErrorf(errorMissingBoxName)
		}

		// Get box info
		box, err := client.GetApplicationBoxByName(appIdx, boxName)
		if err != nil {
			if strings.Contains(err.Error(), "box not found") {
				reportErrorf("No box found for appid %d with name %s", appIdx, boxName)
			}
			reportErrorf(errorRequestFail, err)
		}

		// Print inputted box name, but check that it matches found box name first
		// This reduces confusion of potentially receiving a different box name representation
		boxNameBytes, err := newAppCallBytes(boxName).Raw()
		if err != nil {
			reportErrorf(errorInvalidBoxName, boxName, err)
		}
		if !bytes.Equal(box.Name, boxNameBytes) {
			reportErrorf(errorBoxNameMismatch, box.Name, boxNameBytes)
		}
		reportInfof("Name:  %s", boxName)

		// Print box value
		reportInfof("Value: %s", encodeBytesAsAppCallBytes(*box.Value))
	},
}

var appBoxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List application boxes belonging to an application",
	Long: "List application boxes belonging to an application.\n" +
		"Printable names and values are formatted as 'str:hello' otherwise 'b64:A=='.",
	Args: validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := datadir.EnsureSingleDataDir()
		client := ensureAlgodClient(dataDir)

		response, err := client.ApplicationBoxes(appIdx, boxPrefix, &next, limit, boxValues)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		// Endpoint did not originally report the Round, so don't show it if it's 0
		if response.Round != 0 {
			reportInfof("Round: %d", response.Round)
		}
		// There will only be a next-token if there are more boxes to list
		if response.NextToken != nil {
			encoded := encodeBytesAsAppCallBytes([]byte(*response.NextToken))
			reportInfof("NextToken (use with --next to retrieve more boxes): %s", encoded)
		}
		reportInfoln("Boxes:")
		for _, descriptor := range response.Boxes {
			name := encodeBytesAsAppCallBytes(descriptor.Name)
			if boxValues {
				reportInfof("%s : %s", name, encodeBytesAsAppCallBytes(*descriptor.Value))
			} else {
				reportInfoln(name)
			}
		}
	},
}
