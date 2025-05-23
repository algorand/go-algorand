// Copyright (C) 2019-2025 Algorand, Inc.
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
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/db"
)

var partKeyfile string
var partFirstRound basics.Round
var partLastRound basics.Round
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
			partKeyDilution = account.DefaultKeyDilution(partFirstRound, partLastRound)
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
		defer partdb.Close()

		fmt.Println("Please stand by while generating keys. This might take a few minutes...")

		var partkey account.PersistedParticipation
		participationGen := func() {
			partkey, err = account.FillDBWithParticipationKeys(partdb, parent, partFirstRound, partLastRound, partKeyDilution)
		}

		util.RunFuncWithSpinningCursor(participationGen)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot generate partkey database %s: %v\n", partKeyfile, err)
			err = os.Remove(partKeyfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to cleanup the database file %s: %v\n", partKeyfile, err)
			}
			os.Exit(1)
		}

		fmt.Println("Participation key generation successful")

		printPartkey(partkey.Participation)

		version := config.GetCurrentVersion()
		fmt.Println("\nGenerated with algokey v" + version.String())
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
		partdb.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}
		partkey.Close()

		printPartkey(partkey.Participation)
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
		defer partdb.Close()

		partkey, err := account.RestoreParticipation(partdb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}
		defer partkey.Close()

		partkey.Parent = parent
		err = partkey.PersistNewParent()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot persist partkey database %s: %v\n", partKeyfile, err)
			os.Exit(1)
		}

		printPartkey(partkey.Participation)
	},
}

func printPartkey(partkey account.Participation) {
	fmt.Printf("Parent address:    %s\n", partkey.Parent.String())
	fmt.Printf("VRF public key:    %s\n", base64.StdEncoding.EncodeToString(partkey.VRF.PK[:]))
	fmt.Printf("Voting public key: %s\n", base64.StdEncoding.EncodeToString(partkey.Voting.OneTimeSignatureVerifier[:]))
	if partkey.StateProofSecrets != nil && !partkey.StateProofSecrets.GetVerifier().MsgIsZero() {
		fmt.Printf("State proof key:   %s\n", base64.StdEncoding.EncodeToString(partkey.StateProofSecrets.GetVerifier().Commitment[:]))
		fmt.Printf("State proof key lifetime:   %d\n", partkey.StateProofSecrets.GetVerifier().KeyLifetime)
	}
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
	partCmd.AddCommand(keyregCmd)

	partGenerateCmd.Flags().StringVar(&partKeyfile, "keyfile", "", "Participation key filename")
	partGenerateCmd.Flags().Uint64Var((*uint64)(&partFirstRound), "first", 0, "First round for participation key")
	partGenerateCmd.Flags().Uint64Var((*uint64)(&partLastRound), "last", 0, "Last round for participation key")
	partGenerateCmd.Flags().Uint64Var(&partKeyDilution, "dilution", 0, "Key dilution for two-level participation keys (defaults to sqrt of validity window)")
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
