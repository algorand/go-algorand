// Copyright (C) 2019-2022 Algorand, Inc.
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
	"encoding/base64"

	"github.com/spf13/cobra"
)

var boxName string

func init() {
	appCmd.AddCommand(appBoxCmd)

	appBoxCmd.AddCommand(appBoxInfoCmd)
	appBoxCmd.AddCommand(appBoxListCmd)
	appBoxCmd.PersistentFlags().Uint64Var(&appIdx, "app-id", 0, "Application ID")
	appBoxCmd.MarkFlagRequired("app-id")

	appBoxInfoCmd.Flags().StringVarP(&boxName, "name", "n", "", "Application box name. Use the same form as app-arg to name the box.")
	appBoxInfoCmd.MarkFlagRequired("name")
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
	Long:  "Retrieve information about an application box. The returned box name and value are base64 encoded.",
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
			reportErrorf(errorRequestFail, err)
		}

		// Print box info
		encodedName := base64.StdEncoding.EncodeToString(box.Name)
		encodedValue := base64.StdEncoding.EncodeToString(box.Value)
		reportInfof("Name:  %s", encodedName)
		reportInfof("Value: %s", encodedValue)
	},
}

func encodeValueInAppCallBytesFormat(value []byte) string {
	if isPrintable, _ := unicodePrintable(string(value)); isPrintable {
		return "str:" + string(value)
	}

	return "b64:" + base64.StdEncoding.EncodeToString(value)
}

var appBoxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all application boxes belonging to an application",
	Long: "List all application boxes belonging to an application.\n" +
		"For printable strings, the box name is formatted as 'str:hello'\n" +
		"For everything else, the box name is formatted as 'b64:A=='. ",
	Args: validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		_, client := getDataDirAndClient()

		// Get app boxes
		boxesRes, err := client.ApplicationBoxes(appIdx)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}
		boxes := boxesRes.Boxes

		// Error if no boxes found
		if len(boxes) == 0 {
			reportErrorf("No application boxes found")
		}

		// Print app boxes
		for _, descriptor := range boxes {
			encodedName := encodeValueInAppCallBytesFormat(descriptor.Name)
			reportInfof("%s", encodedName)
		}
	},
}
