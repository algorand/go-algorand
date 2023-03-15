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

// carpenter builds meaningful patterns out of raw Algorand logs
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

const (
	red    = color.FgRed
	green  = color.FgGreen
	yellow = color.FgYellow
)

var help = flag.Bool("help", false, "Show help")
var helpShort = flag.Bool("h", false, "Show help")

func usage() {
	fmt.Fprintln(os.Stderr, `Utility to extract and compare balance root messages from algod log files (node.log)
Usage: ./chopper file1 file2`)
}

type logEntry struct {
	Details telemetryspec.CatchpointRootUpdateEventDetails
}

func extractEntries(filename string) map[basics.Round]*telemetryspec.CatchpointRootUpdateEventDetails {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening %s: %s\n", filename, err.Error())
		os.Exit(1)
	}
	s := bufio.NewScanner(f)

	result := make(map[basics.Round]*telemetryspec.CatchpointRootUpdateEventDetails)
	for s.Scan() {
		line := s.Text()
		if line[0] == '{' && strings.Contains(line[:20], "Root") {
			var entry logEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading catchpoint root entry %s: %s", filename, err.Error())
			} else {
				result[basics.Round(entry.Details.NewBase)] = &entry.Details
			}
		}
	}

	if err := s.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading lines from %s: %s\n", filename, err.Error())
		os.Exit(1)
	}

	return result
}

func main() {
	flag.Parse()

	if *help || *helpShort || len(flag.Args()) < 2 {
		usage()
		os.Exit(1)
	}

	file1 := flag.Args()[0]
	file2 := flag.Args()[1]

	fmt.Printf("%s %s\n", file1, file2)

	forest1 := extractEntries(file1)
	forest2 := extractEntries(file2)

	matched := 0
	var mismatched [][2]*telemetryspec.CatchpointRootUpdateEventDetails
	for rnd, tree1 := range forest1 {
		if tree2, ok := forest2[rnd]; ok {
			if tree1.Root == tree2.Root {
				matched++
			} else {
				mismatched = append(mismatched, [2]*telemetryspec.CatchpointRootUpdateEventDetails{tree1, tree2})
			}
		}
	}
	fmt.Printf("Roots in first: %d, second: %d\n", len(forest1), len(forest2))

	const matchedStr = "Matched roots: %d"
	c := yellow
	if matched > 0 {
		c = green
	}
	fmt.Println(color.New(c).Sprintf(matchedStr, matched))

	const mismatchedStr = "Mismatched roots: %d"
	c = green
	if len(mismatched) > 0 {
		c = red
	}
	fmt.Println(color.New(c).Sprintf(mismatchedStr, len(mismatched)))
	if len(mismatched) > 0 {
		for _, entry := range mismatched {
			fmt.Printf("NewBase: %d, first: (%d, %s), second (%d,%s)\n", entry[0].NewBase, entry[0].OldBase, entry[0].Root, entry[1].OldBase, entry[1].Root)
		}
	}
	fmt.Printf("Other roots in first: %d, second: %d\n", len(forest1)-matched-len(mismatched), len(forest2)-matched-len(mismatched))
}
