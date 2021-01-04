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
	"encoding/base64"
	"fmt"
	"math"
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

var partKeyfile string
var partFirstRound uint64
var partLastRound uint64
var partKeyDilution uint64
var partParent string

var partCmd = &cobra.Command{
	Use:   "part",
	Short: "Manage participation keys",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var partGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate participation key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		if partLastRound < partFirstRound {
			fmt.Fprintf(os.Stderr, "Last round %d < first round %d\n", partLastRound, partFirstRound)
			os.Exit(1)
		}

		if partKeyDilution == 0 {
			partKeyDilution = 1 + uint64(math.Sqrt(float64(partLastRound-partFirstRound)))
		}

		var err error
		var parent basics.Address
		if partParent != "" {
			parent, err = basics.UnmarshalChecksumAddress(partParent)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot parse parent address %s: %v\n", partParent, err)
				os.Exit(1)
			}
		}

		partdb, err := db.MakeErasableAccessor(partKeyfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		partkey, err := account.FillDBWithParticipationKeys(partdb, parent, basics.Round(partFirstRound), basics.Round(partLastRound), partKeyDilution)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot generate partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		printPartkey(partkey)
	},
}

var partInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print participation key information",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		partdb, err := db.MakeErasableAccessor(partKeyfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		partkey, err := account.RestoreParticipation(partdb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		printPartkey(partkey)
	},
}

var partReparentCmd = &cobra.Command{
	Use:   "reparent",
	Short: "Change parent address of participation key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		parent, err := basics.UnmarshalChecksumAddress(partParent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot parse parent address %s: %v\n", partParent, err)
			os.Exit(1)
		}

		partdb, err := db.MakeErasableAccessor(partKeyfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		partkey, err := account.RestoreParticipation(partdb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		partkey.Parent = parent
		err = partkey.PersistNewParent()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot persist partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		printPartkey(partkey)
	},
}

func printPartkey(partkey account.Participation) {
	fmt.Printf("Parent address:    %s\n", partkey.Parent.String())
	fmt.Printf("VRF public key:    %s\n", base64.StdEncoding.EncodeToString(partkey.VRF.PK[:]))
	fmt.Printf("Voting public key: %s\n", base64.StdEncoding.EncodeToString(partkey.Voting.OneTimeSignatureVerifier[:]))
	fmt.Printf("First round:       %d\n", partkey.FirstValid)
	fmt.Printf("Last round:        %d\n", partkey.LastValid)
	fmt.Printf("Key dilution:      %d\n", partkey.KeyDilution)
	fmt.Printf("First batch:       %d\n", partkey.Voting.FirstBatch)
	fmt.Printf("First offset:      %d\n", partkey.Voting.FirstOffset)
}

func init() {
	partCmd.AddCommand(partGenerateCmd)
	partCmd.AddCommand(partInfoCmd)
	partCmd.AddCommand(partReparentCmd)

	partGenerateCmd.Flags().StringVar(&partKeyfile, "keyfile", "", "Participation key filename")
	partGenerateCmd.Flags().Uint64Var(&partFirstRound, "first", 0, "First round for participation key")
	partGenerateCmd.Flags().Uint64Var(&partLastRound, "last", 0, "Last round for participation key")
	partGenerateCmd.Flags().Uint64Var(&partKeyDilution, "dilution", 0, "Key dilution (default to sqrt of validity window)")
	partGenerateCmd.Flags().StringVar(&partParent, "parent", "", "Address of parent account")
	partGenerateCmd.MarkFlagRequired("first")
	partGenerateCmd.MarkFlagRequired("last")
	partGenerateCmd.MarkFlagRequired("keyfile")

	partInfoCmd.Flags().StringVar(&partKeyfile, "keyfile", "", "Participation key filename")
	partInfoCmd.MarkFlagRequired("keyfile")

	partReparentCmd.Flags().StringVar(&partKeyfile, "keyfile", "", "Participation key filename")
	partReparentCmd.Flags().StringVar(&partParent, "parent", "", "Address of parent account")
	partReparentCmd.MarkFlagRequired("keyfile")
	partReparentCmd.MarkFlagRequired("parent")
}
