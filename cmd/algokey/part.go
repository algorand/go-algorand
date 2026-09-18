// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/db"
)

var partKeyfile string
var partFirstRound basics.Round
var partLastRound basics.Round
var partKeyDilution uint64
var partParent string
var partNoValidation bool

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

		// read-only: do not migrate the file as a side effect of printing info
		partkey, err := account.RestoreParticipationUnmigrated(partdb)
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

var partMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate a participation key file to the latest schema version",
	Long: `Migrate a copy of a participation key file to the latest schema version.

The original file is not modified: the migrated database is written to <keyfile>.new.
Prints out migration time in order to estimate algod's auto-migration time at startup.
Unless --no-validation is given, the keys reconstructed from the migrated copy are validated
against the ones in the original file.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		partkey, migrated, err := runPartMigrate(partKeyfile, partNoValidation, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if migrated {
			fmt.Println()
			printPartkey(partkey)
		}
	},
}

// runPartMigrate migrates a copy of keyfile to <keyfile>.new and optionally
// validates the copy against the original.  It returns the migrated key
// (valid only when migrated is true).
func runPartMigrate(keyfile string, noValidation bool, out io.Writer) (partkey account.Participation, migrated bool, err error) {
	origdb, err := db.MakeErasableAccessor(keyfile)
	if err != nil {
		return partkey, false, fmt.Errorf("cannot open partkey database %s: %v", keyfile, err)
	}
	defer origdb.Close()

	version, err := account.PartkeySchemaVersion(origdb)
	if err != nil {
		return partkey, false, fmt.Errorf("cannot read schema version of %s: %v", keyfile, err)
	}
	fmt.Fprintf(out, "Current schema version of %s: %d\n", keyfile, version)
	if version == account.PartTableSchemaVersion {
		fmt.Fprintf(out, "Already at the latest schema version; nothing to do.\n")
		return partkey, false, nil
	}
	if version != account.PartTableSchemaVersionVotingSplit-1 {
		return partkey, false, fmt.Errorf("unsupported schema version %d: only version %d files can be migrated", version, account.PartTableSchemaVersionVotingSplit-1)
	}

	newFile := keyfile + ".new"
	if _, statErr := os.Stat(newFile); statErr == nil {
		return partkey, false, fmt.Errorf("%s already exists; remove it before migrating", newFile)
	}
	// drop stale sidecars a previous failed run may have left, so SQLite
	// cannot replay them into the fresh snapshot
	for _, ext := range []string{"-wal", "-shm"} {
		if err = os.Remove(newFile + ext); err != nil && !os.IsNotExist(err) {
			return partkey, false, fmt.Errorf("cannot remove stale %s: %v", newFile+ext, err)
		}
	}
	// pre-create the snapshot target as an empty file with the original's
	// restrictive permissions (VACUUM INTO accepts an empty file, and SQLite
	// creates the -wal/-shm sidecars with the database file's mode), so the
	// secret material is never readable more broadly than the original —
	// not even between the snapshot and a later chmod
	srcInfo, err := os.Stat(keyfile)
	if err != nil {
		return partkey, false, fmt.Errorf("cannot stat %s: %v", keyfile, err)
	}
	f, err := os.OpenFile(newFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, srcInfo.Mode().Perm())
	if err != nil {
		return partkey, false, fmt.Errorf("cannot create %s: %v", newFile, err)
	}
	f.Close()
	// the umask may have stripped bits during creation; force the exact mode
	if err = os.Chmod(newFile, srcInfo.Mode().Perm()); err != nil {
		return partkey, false, fmt.Errorf("cannot set permissions on %s: %v", newFile, err)
	}
	// VACUUM INTO takes one transactionally consistent snapshot through
	// SQLite itself, so a concurrently writing algod (which updates the file
	// every round) cannot produce a torn copy the way independent file
	// copies of the database and its WAL could.
	if _, err = origdb.Handle.Exec("VACUUM INTO ?", newFile); err != nil {
		// remove the empty target so a retry is not refused by the
		// already-exists guard
		os.Remove(newFile)
		return partkey, false, fmt.Errorf("cannot snapshot %s to %s: %v", keyfile, newFile, err)
	}
	// a copy whose migration or validation failed is useless and would block
	// a retry through the already-exists guard; keep it only on success
	migrateOK := false
	defer func() {
		if !migrateOK {
			os.Remove(newFile)
			os.Remove(newFile + "-wal")
			os.Remove(newFile + "-shm")
		}
	}()

	newdb, err := db.MakeErasableAccessor(newFile)
	if err != nil {
		return partkey, false, fmt.Errorf("cannot open copied partkey database %s: %v", newFile, err)
	}
	defer newdb.Close()

	start := time.Now()
	err = account.Migrate(newdb)
	migrationTime := time.Since(start)
	if err != nil {
		return partkey, false, fmt.Errorf("migration of %s failed: %v", newFile, err)
	}
	fmt.Fprintf(out, "Migrated %s to schema version %d, spent %v\n", newFile, account.PartTableSchemaVersion, migrationTime)

	// load the state proof secret keys too, so validation covers them
	restored, err := account.RestoreParticipationWithSecrets(newdb)
	if err != nil {
		return partkey, false, fmt.Errorf("cannot load migrated partkey database %s: %v", newFile, err)
	}
	partkey = restored.Participation

	if noValidation {
		migrateOK = true
		return partkey, true, nil
	}

	original, err := account.RestoreParticipationUnmigrated(origdb)
	if err != nil {
		return partkey, false, fmt.Errorf("cannot load original partkey database %s for validation: %v", keyfile, err)
	}
	if original.StateProofSecrets != nil {
		if err = original.StateProofSecrets.RestoreAllSecrets(origdb); err != nil {
			return partkey, false, fmt.Errorf("cannot load state proof keys from %s for validation: %v", keyfile, err)
		}
	}
	if err = comparePartkeys(original.Participation, partkey); err != nil {
		return partkey, false, fmt.Errorf("validation FAILED: migrated keys differ from the original: %v", err)
	}
	fmt.Fprintf(out, "Validation PASSED: keys reconstructed from %s match the original\n", newFile)
	migrateOK = true
	return partkey, true, nil
}

// comparePartkeys verifies two participation keys carry identical key
// material and metadata.
func comparePartkeys(expected, actual account.Participation) error {
	if expected.Parent != actual.Parent {
		return fmt.Errorf("parent address mismatch")
	}
	if expected.FirstValid != actual.FirstValid || expected.LastValid != actual.LastValid || expected.KeyDilution != actual.KeyDilution {
		return fmt.Errorf("validity metadata mismatch")
	}
	if !bytes.Equal(protocol.Encode(expected.VRF), protocol.Encode(actual.VRF)) {
		return fmt.Errorf("VRF secrets mismatch")
	}
	expectedVoting := expected.Voting.Snapshot()
	actualVoting := actual.Voting.Snapshot()
	if !bytes.Equal(protocol.Encode(&expectedVoting), protocol.Encode(&actualVoting)) {
		return fmt.Errorf("voting secrets mismatch")
	}
	// v1/v2 files (and v3 files upgraded from them) have no state proof secrets
	if (expected.StateProofSecrets == nil) != (actual.StateProofSecrets == nil) {
		return fmt.Errorf("state proof secrets presence mismatch")
	}
	if expected.StateProofSecrets != nil {
		// the encoding covers the SignerContext only
		if !bytes.Equal(protocol.Encode(expected.StateProofSecrets), protocol.Encode(actual.StateProofSecrets)) {
			return fmt.Errorf("state proof secrets mismatch")
		}
		// the secret keys live in their own table and must be compared
		// explicitly (callers load them with RestoreAllSecrets)
		expectedKeys := expected.StateProofSecrets.GetAllKeys()
		actualKeys := actual.StateProofSecrets.GetAllKeys()
		if len(expectedKeys) != len(actualKeys) {
			return fmt.Errorf("state proof key count mismatch (%d != %d)", len(expectedKeys), len(actualKeys))
		}
		for i := range expectedKeys {
			if !bytes.Equal(protocol.Encode(&expectedKeys[i]), protocol.Encode(&actualKeys[i])) {
				return fmt.Errorf("state proof key %d mismatch", i)
			}
		}
	}
	return nil
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
	partCmd.AddCommand(partMigrateCmd)
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

	partMigrateCmd.Flags().StringVar(&partKeyfile, "keyfile", "", "Participation key filename")
	partMigrateCmd.Flags().BoolVar(&partNoValidation, "no-validation", false, "Skip validating the migrated keys against the original file")
	partMigrateCmd.MarkFlagRequired("keyfile")
}
