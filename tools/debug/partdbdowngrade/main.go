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

// partdbdowngrade converts a node's participation registry
// (partregistry.sqlite) from schema version 2 back to version 1, so the node
// can run algod 5.0 or earlier again after a later algod opened the registry.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
)

var dataDir = flag.String("d", "", "algod data directory (required); algod must not be running in it")
var registryFile = flag.String("f", "", "participation registry to convert (default: the "+config.ParticipationRegistryFilename+" in the data directory's genesis directory)")
var dryRun = flag.Bool("dry-run", false, "convert and verify, then roll back, leaving the registry unchanged")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage: %s -d <data directory> [-f <registry file>] [-dry-run]

Converts the participation registry of a stopped node from schema version 2
(algod 5.1 and later) to version 1, which algod 5.0 and earlier require. The
voting subkeys each key still has move back into one record per key.
Starting a later algod on the data directory upgrades the registry again.

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *dataDir == "" || flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*dataDir, *registryFile, *dryRun, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "partdbdowngrade: %v\n", err)
		os.Exit(1)
	}
}

func run(dataDir, registryFile string, dryRun bool, out io.Writer) error {
	if _, err := os.Stat(filepath.Join(dataDir, config.GenesisJSONFile)); err != nil {
		return fmt.Errorf("%s is not an algod data directory: %w", dataDir, err)
	}
	// algod holds this lock while it runs; holding it here also keeps algod
	// from starting during the conversion
	lock := flock.New(filepath.Join(dataDir, "algod.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return fmt.Errorf("cannot take algod.lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("algod is running in %s; stop it first", dataDir)
	}
	defer func() { _ = lock.Unlock() }()

	if registryFile == "" {
		if registryFile, err = findRegistry(dataDir); err != nil {
			return err
		}
	}

	records, err := account.DowngradeRegistry(registryFile, dryRun)
	if errors.Is(err, account.ErrRegistryAlreadyVersion1) {
		fmt.Fprintf(out, "%s already has schema version 1; nothing to do\n", registryFile)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", registryFile, err)
	}

	if dryRun {
		fmt.Fprintf(out, "%s: dry run, schema version 2 converts to 1; nothing was changed\n", registryFile)
	} else {
		fmt.Fprintf(out, "%s: schema version 2 converted to 1\n", registryFile)
	}
	for _, r := range records {
		fmt.Fprintf(out, "  %s  account %s  valid %d to %d  %s\n", r.ParticipationID, r.Account, r.FirstValid, r.LastValid, describeVoting(r))
	}
	return nil
}

// findRegistry returns the registry in the genesis directory of dataDir. A
// data directory that has held more than one network has a registry in each
// genesis directory, and a node whose config sets HotDataDir keeps it there,
// so anything but exactly one match is left to -f.
func findRegistry(dataDir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dataDir, "*", config.ParticipationRegistryFilename))
	if err != nil {
		return "", err
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no %s in a subdirectory of %s; name it with -f", config.ParticipationRegistryFilename, dataDir)
	default:
		return "", fmt.Errorf("several registries in %s (%v); name one with -f", dataDir, matches)
	}
}

func describeVoting(r account.DowngradedRecord) string {
	switch {
	case r.Voting == nil:
		return "no voting secrets"
	case r.Voting.Exhausted():
		return "no voting subkeys left"
	default:
		return fmt.Sprintf("voting subkeys: %d batches from batch %d, %d offsets from offset %d",
			r.Voting.BatchCount, r.Voting.FirstBatch, r.Voting.OffsetCount, r.Voting.FirstOffset)
	}
}
