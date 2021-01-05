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
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

var log = logging.Base()

var dataDirs []string

var defaultCacheDir = "goal.cache"

var verboseVersionPrint bool

var kmdDataDirFlag string

var versionCheck bool

func init() {
	// file.go
	rootCmd.AddCommand(fileCmd)
	rootCmd.AddCommand(netCmd)
	rootCmd.AddCommand(databaseCmd)

}

var rootCmd = &cobra.Command{
	Use:   "catchpointdump",
	Short: "Catchpoint dump utility",
	Long:  "Catchpoint dump utility",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if versionCheck {
			fmt.Println(config.FormatVersionAndLicense())
			return
		}
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

// Write commands to exercise all subcommands with `-h`
// Can be used to check that there are no conflicts in arguments between inner and outer commands.
func runAllHelps(c *cobra.Command, out io.Writer) (err error) {
	if c.Runnable() {
		cmd := c.CommandPath() + " -h\n"
		_, err = out.Write([]byte(cmd))
		if err != nil {
			return
		}
	}
	for _, sub := range c.Commands() {
		err = runAllHelps(sub, out)
		if err != nil {
			return
		}
	}
	return
}

func main() {
	// Hidden command to generate docs in a given directory
	// goal generate-docs [path]
	if len(os.Args) == 3 && os.Args[1] == "generate-docs" {
		err := doc.GenMarkdownTree(rootCmd, os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	} else if len(os.Args) == 2 && os.Args[1] == "helptest" {
		// test that subcommands don't have arg conflicts:
		// goal helptest | bash -x -e
		runAllHelps(rootCmd, os.Stdout)
		os.Exit(0)
	}

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

func reportWarnln(args ...interface{}) {
	fmt.Print("Warning: ")
	fmt.Println(args...)
	// log.Warnln(args...)
}

func reportWarnf(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format+"\n", args...)
	// log.Warnf(format, args...)
}

func reportErrorln(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	// log.Warnln(args...)
	os.Exit(1)
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	// log.Warnf(format, args...)
	os.Exit(1)
}

// validateNoPosArgsFn is a reusable cobra positional argument validation function
// for generating proper error messages when commands see unexpected arguments when they expect no args.
// We don't use cobra.NoArgs directly, in case we want to customize behavior later.
var validateNoPosArgsFn = cobra.NoArgs
