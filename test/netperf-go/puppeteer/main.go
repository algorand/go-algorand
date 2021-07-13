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
	"path"

	"github.com/spf13/cobra"
)

var (
	testFilename string
	channel      string
	verbose      bool
	stageDir     string
	skipCleanup  bool
	skipReset    bool
	deployFor    string
)

func init() {
	rootCmd.Flags().StringVarP(&testFilename, "run", "r", "", "Specify a network test json or a directory containing test jsons")
	rootCmd.MarkFlagRequired("run")
	rootCmd.Flags().StringVarP(&channel, "channel", "c", "", "Specify a channel name")
	rootCmd.MarkFlagRequired("channel")
	rootCmd.Flags().StringVarP(&deployFor, "for", "f", "", "Specify instance `for` tag")
	rootCmd.MarkFlagRequired("for")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbosed output")
	rootCmd.Flags().StringVarP(&stageDir, "stageDir", "s", "", "staging directory for deployed networks (defaults to a temporary directory)")
	rootCmd.Flags().BoolVarP(&skipCleanup, "skipCleanup", "", false, "Skip clean up of the staging directory on exit")
	rootCmd.Flags().BoolVarP(&skipReset, "skipReset", "", false, "Skip resetting of the staging directory during initialization")

	rootCmd.SilenceErrors = true
}

var rootCmd = &cobra.Command{
	Use: "puppeteer",
	RunE: func(cmd *cobra.Command, args []string) error {
		fstat, err := os.Stat(testFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if fstat.IsDir() {
			// it's a directory.
			dir, err := os.OpenFile(testFilename, os.O_RDONLY, 0755)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			for err == nil {
				fstat, err := dir.Readdir(1)
				if err == io.EOF {
					return nil
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "%v\n", err)
					os.Exit(1)
				}
				fqn := path.Join(testFilename, fstat[0].Name())
				fmt.Printf("Processing %v...\n", fqn)
				err = puppeteer(channel, fqn)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%v\n", err)
					os.Exit(1)
				}
			}

		} else {
			// it's a file.
			fmt.Printf("Processing %v...\n", testFilename)
			err := puppeteer(channel, testFilename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		}
		return nil
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
