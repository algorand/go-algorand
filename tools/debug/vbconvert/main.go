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
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/config"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type arguments struct {
	inputFile  string
	outputFile string
	format     string
}

type algodVB struct {
	Blk   bookkeeping.Block
	Delta ledgercore.StateDelta
}

type conduitVB struct {
	Blk   bookkeeping.Block
	Delta model.LedgerStateDelta
}

func run(args arguments) {
	var algodType algodVB

	// Read
	data, err := os.ReadFile(args.inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read input file '%s': %s\n", args.inputFile, err)
		os.Exit(1)
	}

	err = protocol.DecodeReflect(data, &algodType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to decode input file '%s': %s\n", args.inputFile, err)
		os.Exit(1)
	}

	// Convert
	consensusParams := config.Consensus[algodType.Delta.Hdr.CurrentProtocol]
	modelDelta, err := v2.StateDeltaToLedgerDelta(algodType.Delta, consensusParams)

	// Write
	outputFile, err := os.Create(args.outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open output file '%s': %s\n", args.outputFile, err)
		os.Exit(1)
	}

	var enc *codec.Encoder
	switch strings.ToLower(args.format) {
	case "json":
		enc = protocol.NewJSONEncoder(outputFile)
	case "msgp":
		enc = protocol.NewEncoder(outputFile)
	default:
		fmt.Fprintf(os.Stderr, "Unknown encoder type '%s', valid encoders: json, msgp.\n", args.format)
		os.Exit(1)
	}

	conduitType := conduitVB{
		Blk:   algodType.Blk,
		Delta: modelDelta,
	}
	err = enc.Encode(conduitType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to decode input file '%s': %s\n", args.outputFile, err)
		os.Exit(1)
	}
}

func main() {
	var args arguments

	command := &cobra.Command{
		Use:  "vbconvert",
		Long: "Convert a ledgercore.ValidatedBlock into the conduit version of a ValidatedBlock.",
		Run: func(_ *cobra.Command, _ []string) {
			run(args)
		},
	}

	command.Flags().StringVarP(&args.inputFile, "input", "i", "", "Input filename.")
	command.Flags().StringVarP(&args.outputFile, "output", "o", "", "Optional output filename. If not present a default <filename>.convert is created.")
	command.Flags().StringVarP(&args.format, "format", "f", "json", "Optional output format. Valid formats are 'json' and 'msgp'.")
	command.MarkFlagRequired("input")
	command.MarkFlagRequired("output")

	command.Execute()
}
