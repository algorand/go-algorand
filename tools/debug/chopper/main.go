// Copyright (C) 2019-2024 Algorand, Inc.
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

// chopper compares raw Algorand logs for matching catchpoint (balance trie) roots and labels
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

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
var labels = flag.Bool("labels", false, "Compare catchpoint labels in addition to roots")
var labelsShort = flag.Bool("l", false, "Compare catchpoint labels in addition to roots")

func usage() {
	fmt.Fprintln(os.Stderr, `Utility to extract and compare balance root and catchpoint labels messages from algod log files (node.log)
Usage: ./chopper [--labels] file1 file2`)
}

// logEntry is json representing catchpoint root message telemetry
type logEntry struct {
	Details telemetryspec.CatchpointRootUpdateEventDetails
}

// rootLabelInfo is parsed roots/labels from a log file
type rootLabelInfo struct {
	roots  map[basics.Round]*telemetryspec.CatchpointRootUpdateEventDetails
	labels map[basics.Round]string
}

// extractEntries reads the log file line by line and collects root and labels entries
func extractEntries(filename string, checkLabels bool) rootLabelInfo {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening %s: %s\n", filename, err.Error())
		os.Exit(1)
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	var re *regexp.Regexp
	if checkLabels {
		re = regexp.MustCompile(`Creating a catchpoint label (\d+#[A-Z0-9]+)\s+for round=(\d+).*`)
	}

	result := rootLabelInfo{
		roots: make(map[basics.Round]*telemetryspec.CatchpointRootUpdateEventDetails),
	}
	if checkLabels {
		result.labels = make(map[basics.Round]string)
	}

	for s.Scan() {
		line := s.Text()
		if line[0] == '{' && strings.Contains(line[:20], "Root") {
			var entry logEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading catchpoint root entry %s: %s\n", filename, err.Error())
				continue
			}
			result.roots[basics.Round(entry.Details.NewBase)] = &entry.Details
		} else if checkLabels && strings.HasPrefix(line, `{"file":"catchpointlabel.go"`) {
			entry := map[string]interface{}{}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading catchpoint label entry %s: %s\n", filename, err.Error())
				continue
			}
			matches := re.FindStringSubmatch(entry["msg"].(string))
			if len(matches) != 3 {
				fmt.Fprintf(os.Stderr, "No catchpoint label match %s: %s %s\n", filename, matches, entry["msg"])
				continue
			}
			uintRound, err := strconv.ParseUint(matches[2], 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot parse round %s: %s\n", filename, matches[1])
				continue
			}
			result.labels[basics.Round(uintRound)] = matches[1]
		}
	}

	if err := s.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading lines from %s: %s\n", filename, err.Error())
		os.Exit(1)
	}

	return result
}

type reportData struct {
	what        string
	size1       int
	size2       int
	matched     int
	mismatched  []interface{}
	errReporter func(interface{})
}

// report prints out stats about matched and mismatched roots or labels
func report(rd reportData) {
	fmt.Printf("%s in first: %d, second: %d\n", cases.Title(language.English).String(rd.what), rd.size1, rd.size2)

	const matchedStr = "Matched %s: %d"
	c := yellow
	if rd.matched > 0 {
		c = green
	}
	fmt.Println(color.New(c).Sprintf(matchedStr, rd.what, rd.matched))

	const mismatchedStr = "Mismatched %s: %d"
	c = green
	if len(rd.mismatched) > 0 {
		c = red
	}
	fmt.Println(color.New(c).Sprintf(mismatchedStr, rd.what, len(rd.mismatched)))
	if len(rd.mismatched) > 0 {
		for _, entry := range rd.mismatched {
			rd.errReporter(entry)
		}
	}
	fmt.Printf("Other %s in first: %d, second: %d\n", rd.what, rd.size1-rd.matched-len(rd.mismatched), rd.size2-rd.matched-len(rd.mismatched))
}

func main() {
	flag.Parse()

	if *help || *helpShort || len(flag.Args()) < 2 {
		usage()
		os.Exit(1)
	}

	checkLabels := *labels || *labelsShort

	file1 := flag.Args()[0]
	file2 := flag.Args()[1]

	// load data
	info1 := extractEntries(file1, checkLabels)
	info2 := extractEntries(file2, checkLabels)

	// match roots
	matchedRoots := 0
	var mismatchedRoots []interface{}
	for rnd, tree1 := range info1.roots {
		if tree2, ok := info2.roots[rnd]; ok {
			if tree1.Root == tree2.Root {
				matchedRoots++
			} else {
				mismatchedRoots = append(mismatchedRoots, [2]*telemetryspec.CatchpointRootUpdateEventDetails{tree1, tree2})
			}
		}
	}

	// match labels
	matchedLabels := 0
	var mismatchedLabels []interface{}
	if checkLabels {
		for rnd, label1 := range info1.labels {
			if label2, ok := info2.labels[rnd]; ok {
				if label1 == label2 {
					matchedLabels++
				} else {
					mismatchedLabels = append(mismatchedLabels, [2]string{label1, label2})
				}
			}
		}

	}

	report(reportData{
		what:       "roots",
		size1:      len(info1.roots),
		size2:      len(info2.roots),
		matched:    matchedRoots,
		mismatched: mismatchedRoots,
		errReporter: func(e interface{}) {
			entry := e.([2]*telemetryspec.CatchpointRootUpdateEventDetails)
			fmt.Printf("NewBase: %d, first: (%d, %s), second (%d,%s)\n", entry[0].NewBase, entry[0].OldBase, entry[0].Root, entry[1].OldBase, entry[1].Root)
		},
	})

	if checkLabels {
		report(reportData{
			what:       "labels",
			size1:      len(info1.labels),
			size2:      len(info2.labels),
			matched:    matchedLabels,
			mismatched: mismatchedLabels,
			errReporter: func(e interface{}) {
				entry := e.([2]string)
				fmt.Printf("first: %s != %s second\n", entry[0], entry[1])
			},
		})
	}
}
