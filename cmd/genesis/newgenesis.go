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
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/util"
)

var outDir = flag.String("d", "", "The directory containing the generated ledger and wallet files.")
var netName = flag.String("n", "", "The name of the network for this ledger (will override config file).")
var configFile = flag.String("c", "", "The config file containing the genesis ledger and wallets")
var quiet = flag.Bool("q", false, "Skip verbose informational messages")
var firstPartKeyRound = flag.Uint64("f", 0, "The first round in which the participation keys are valid")
var lastPartKeyRound = flag.Uint64("l", 0, "The last round in which the participation keys are valid")

func init() {
	flag.Parse()
}

func main() {
	if !*quiet {
		fmt.Println("Network Name: " + *netName)
	}

	cfgFile := *configFile
	if !util.FileExists(cfgFile) {
		reportErrorf("missing configuration file '%s'\n", cfgFile)
	}

	genesisData, err := gen.LoadGenesisData(cfgFile)
	if err != nil {
		reportErrorf("error loading configuration file: %v\n", err)
	}

	if *firstPartKeyRound != 0 {
		genesisData.FirstPartKeyRound = *firstPartKeyRound
	}

	if *lastPartKeyRound != 0 {
		genesisData.LastPartKeyRound = *lastPartKeyRound
	}

	if *netName != "" {
		genesisData.NetworkName = *netName
	}

	var verboseOut io.Writer = nil
	if !*quiet {
		verboseOut = os.Stdout
	}
	err = gen.GenerateGenesisFiles(genesisData, config.Consensus, *outDir, verboseOut)
	if err != nil {
		reportErrorf("Cannot write genesis files: %s", err)
	}
}

func reportErrorf(format string, args ...interface{}) {
	log.Fatalf(format, args...)
}
