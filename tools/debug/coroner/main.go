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

// coroner performs post-mortem autospies on Algorand nodes
package main

import (
	"flag"
	"log"
	"os"
	"regexp"
	"strconv"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

var numRegex = regexp.MustCompile(`^\d+$`)

var filename = flag.String("file", "", "Name of the input cadaver file (otherwise, use stdin)")
var versionCheck = flag.Bool("version", false, "Display current coroner build version and exit")
var printmsgpack = flag.Bool("msgpack", false, "If provided, emit msgpack instead of a string")

var skipHead = flag.String("skip-head", "", "The first round to trim before")
var skipTail = flag.String("skip-tail", "", "The last round to trim after")

func mustParse(data []byte) uint64 {
	x, err := strconv.ParseUint(string(data), 10, 64)
	if err != nil {
		log.Fatalf(`failed to parse round bound in "%s": %s`, string(data), err)
	}
	return x
}

func parseRoundBound(s string) uint64 {
	if !numRegex.Match([]byte(s)) {
		log.Fatalf(`failed to parse round bound in "%s": string does not match regex "^\d+$"`, s)
	}
	return mustParse(numRegex.Find([]byte(s)))
}

func done(n int, err error) {
	if n == 0 {
		log.Println("coroner: no cadavers autopsied")
	}

	if err != nil {
		log.Println("coroner: failed to extract full autopsy trace:", err)
	}
}

func nextBounds(i int, bounds agreement.AutopsyBounds) {
	log.Printf("cadaver seq: %d\tstart(r,p): (%d,%d)\tend(r,p): (%d,%d)\n", i, bounds.StartRound, bounds.StartPeriod, bounds.EndRound, bounds.EndPeriod)
}

func main() {
	flag.Parse()
	var autopsy *agreement.Autopsy
	var err error
	version := config.GetCurrentVersion()

	if *versionCheck {
		log.Printf("uint64 version: %d\n%s.%s [%s] (commit #%s)\n", version.AsUInt64(), version.String(),
			version.Channel, version.Branch, version.GetCommitHash())
		return
	}

	if *filename == "" {
		log.Println("coroner: no filename provided; reading from stdin...")
		autopsy, err = agreement.PrepareAutopsyFromStream(os.Stdin, nextBounds, done)
	} else {
		autopsy, err = agreement.PrepareAutopsy(*filename, nextBounds, done)
	}
	if err != nil {
		log.Fatalln("coroner: failed to prepare autopsy:", err)
	}
	defer autopsy.Close()

	var filter agreement.AutopsyFilter
	if *skipHead != "" {
		filter.Enabled = true
		filter.First = basics.Round(parseRoundBound(*skipHead))
	}
	if *skipTail != "" {
		filter.Enabled = true
		filter.Last = basics.Round(parseRoundBound(*skipTail))
	}

	var commitHash string
	if *printmsgpack {
		commitHash = autopsy.DumpMessagePack(filter, os.Stdout)
	} else {
		commitHash = autopsy.DumpString(filter, os.Stdout)
	}
	if commitHash != version.GetCommitHash() {
		log.Printf("coroner: cadaver version mismatches coroner version:\n(%s (cadaver) != %s (coroner))\n", commitHash, version.GetCommitHash())
	}

	return
}
