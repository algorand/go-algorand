// Copyright (C) 2019-2026 Algorand, Inc.
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

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/data/basics"
)

var boxName string
var boxLimit uint64
var boxNext string
var boxPrefix string
var boxValues bool
var boxRound uint64

func init() {
	appCmd.AddCommand(appBoxCmd)

	appBoxCmd.AddCommand(appBoxInfoCmd)
	appBoxCmd.AddCommand(appBoxListCmd)
	appBoxCmd.PersistentFlags().Uint64Var((*uint64)(&appIdx), "app-id", 0, "Application ID")
	appBoxCmd.MarkFlagRequired("app-id")

	appBoxInfoCmd.Flags().StringVarP(&boxName, "name", "n", "", "Application box name. Use the same form as app-arg to name the box.")
	appBoxInfoCmd.MarkFlagRequired("name")

	appBoxListCmd.Flags().Uint64VarP(&boxLimit, "limit", "l", 0, "Maximum number of boxes per page (default: 1000, or 100 with --values).")
	appBoxListCmd.Flags().StringVarP(&boxNext, "next", "n", "", "Pagination cursor from a previous response's next-token.")
	appBoxListCmd.Flags().StringVarP(&boxPrefix, "prefix", "p", "", "Filter by box name prefix, in the same form as app-arg.")
	appBoxListCmd.Flags().BoolVarP(&boxValues, "values", "v", false, "If set, include box values in the output.")
	appBoxListCmd.Flags().Uint64VarP(&boxRound, "round", "r", 0, "Query boxes at a specific round (auto-pinned from first page if not set).")
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
		reportInfof("Value: %s", encodeBytesAsAppCallBytes(box.Value))
	},
}

var appBoxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all application boxes belonging to an application",
	Long: `List all application boxes belonging to an application.
For printable strings, the box name is formatted as 'str:hello'
For everything else, the box name is formatted as 'b64:A=='.

Use --limit to fetch a single page of results.
When there are more results, NextToken is printed.
Use --next and --round to resume from a limited request.
Use --prefix to filter boxes by name prefix.
Use --values to include box values in the output.`,
	Args: validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		_, client := getDataDirAndClient()

		// Apply default limit when not explicitly set.
		limit := boxLimit
		if limit == 0 {
			if boxValues {
				limit = 100
			} else {
				limit = 1000
			}
		}

		next := boxNext
		round := basics.Round(boxRound)
		for {
			boxesRes, err := client.ApplicationBoxesPage(appIdx, limit, next, boxPrefix, boxValues, round)
			if err != nil {
				reportErrorf(errorRequestFail, err)
			}

			if round == 0 {
				// Auto-pin round from first page for consistent pagination.
				round = *boxesRes.Round
				if len(boxesRes.Boxes) == 0 {
					reportErrorf("No matching boxes found")
				}
			}

			for _, descriptor := range boxesRes.Boxes {
				encodedName := encodeBytesAsAppCallBytes(descriptor.Name)
				if boxValues && descriptor.Value != nil {
					encodedValue := encodeBytesAsAppCallBytes(*descriptor.Value)
					reportInfof("%s : %s", encodedName, encodedValue)
				} else {
					reportInfof("%s", encodedName)
				}
			}

			next = nilToZero(boxesRes.NextToken)
			if next == "" {
				break
			}
			if boxLimit > 0 || boxNext != "" {
				// Stop after a page if a limit or next-token was explicitly specified
				reportInfof("NextToken: %s", next)
				break
			}
		}
	},
}
