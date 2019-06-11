// Copyright (C) 2019 Algorand, Inc.
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
)

var numRegex = regexp.MustCompile(`^\d+$`)
var posOffRegex = regexp.MustCompile(`^\+\d+$`)
var negOffRegex = regexp.MustCompile(`^\-\d+$`)

var filename = flag.String("file", "", "Name of the input cadaver file")
var versionCheck = flag.Bool("version", false, "Display current coroner build version and exit")

var printmsgpack = flag.Bool("msgpack", false, "If provided, emit msgpack instead of a string")

// note: these also take relative offsets given by "+" or "-" symbols
// e.g., the command
//   coroner --skip-head -10
// will give the last 10 rounds of the coroner.
// If relative is set, the removal is done relative to the minimum round in the
// trace if the given round is nonnegative. Otherwise, the removal is relative
// to the maximum round in the trace.
var skipHead = flag.String("skip-head", "", "The first round to trim before")
var skipTail = flag.String("skip-tail", "", "The last round to trim after")

func mustParse(data []byte) int64 {
	x, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.Fatalf(`failed to parse round bound in "%s": %s`, string(data), err)
	}
	return x
}

func parseRoundBound(s string) (bound int64, relative bool) {
	data := []byte(s)
	signfact := int64(1)

	switch {
	case s == "":
	case numRegex.Match(data):
		bound = mustParse(numRegex.Find(data))
	case negOffRegex.Match(data):
		signfact = -1
		fallthrough
	case posOffRegex.Match(data):
		relative = true
		bound = mustParse(numRegex.Find(data[1:])) * signfact
	default:
		log.Fatalf(`failed to parse round bound in "%s": string does not match regex "^(+|-)\d+$"`, s)
	}
	return
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
		autopsy, err = agreement.PrepareAutopsyFromInputStream()
	} else {
		autopsy, err = agreement.PrepareAutopsy(*filename)
	}
	if err != nil {
		log.Fatalln("coroner: failed to prepare autopsy:", err)
	}
	defer autopsy.Close()

	headRound, headRelative := parseRoundBound(*skipHead)
	tailRound, tailRelative := parseRoundBound(*skipTail)

	autopsiedCdvs, err := autopsy.ExtractCdvs()
	if err != nil {
		log.Println("coroner: failed to extract full autopsy trace:", err)
		log.Println("coroner: continuing after error...")
	}

	if len(autopsiedCdvs) < 1 {
		log.Println("coroner: no cadavers autopsied")
		return
	}

	firstMeta := autopsiedCdvs[0].M
	log.Printf("coroner: Cadaver file generated with commit hash:\n%s\n", firstMeta.VersionCommitHash)
	if firstMeta.VersionCommitHash != version.GetCommitHash() {
		log.Printf("coroner: Cadaver version mismatches coroner version:\n(%s (cadaver) != %s (coroner))\n", firstMeta.VersionCommitHash, version.GetCommitHash())
	}

	cachedStartRound := autopsiedCdvs[0].StartRound
	if *skipHead != "" {
		numCdvs := len(autopsiedCdvs)
		first := headRound
		if headRelative {
			if headRound >= 0 {
				first = cachedStartRound + headRound
			} else {
				first = autopsiedCdvs[numCdvs-1].EndRound + headRound
			}
		}
		for i := range autopsiedCdvs {
			if autopsiedCdvs[i].EndRound < first {
				autopsiedCdvs = autopsiedCdvs[i+1:]
				break
			}
		}
		autopsiedCdvs[0].T, autopsiedCdvs[0].StartRound = autopsiedCdvs[0].T.FilterBefore(first)
	}
	if *skipTail != "" {
		numCdvs := len(autopsiedCdvs)
		last := tailRound
		if tailRelative {
			if tailRound >= 0 {
				last = cachedStartRound + tailRound
			} else {
				last = autopsiedCdvs[numCdvs-1].EndRound + tailRound
			}
		}
		for i := range autopsiedCdvs {
			if autopsiedCdvs[i].StartRound > last {
				autopsiedCdvs = autopsiedCdvs[:i]
				break
			}
		}
		end := len(autopsiedCdvs)
		autopsiedCdvs[end].T, autopsiedCdvs[end].EndRound = autopsiedCdvs[end].T.FilterAfter(last)
	}

	for i := range autopsiedCdvs {
		log.Printf("Cadaver Seq: %d\tstart: %d\tend: %d\n", i, autopsiedCdvs[i].StartRound, autopsiedCdvs[i].EndRound)
	}
	if *printmsgpack {
		agreement.DumpMessagePack(autopsiedCdvs, os.Stdout)
	} else {
		agreement.DumpString(autopsiedCdvs, os.Stdout)
	}
}
