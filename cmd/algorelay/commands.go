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
}

var rootCmd = &cobra.Command{
	Use:   "algorelay",
	Short: "algorelay",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help

		cmd.HelpFunc()(cmd, args)
	},
}

type exitError struct {
	error

	exitCode     int
	errorMessage string
}

func makeExitError(exitCode int, errMsg string, errArgs ...interface{}) exitError {
	ee := exitError{
		exitCode:     exitCode,
		errorMessage: fmt.Sprintf(errMsg, errArgs...),
	}
	return ee
}

func (e exitError) Error() string {
	return e.errorMessage
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			switch exitErr := err.(type) {
			case exitError:
				fmt.Println(exitErr.Error())
				os.Exit(exitErr.exitCode)
			default:
				panic(err)
			}
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
