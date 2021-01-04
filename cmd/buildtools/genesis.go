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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

var (
	timestampSecs int64
	timestampFile string
	forceUpdate   bool

	genesisFile string

	networkName   string
	sourceFile    string
	targetFile    string
	releaseDir    string
	createRelease bool
	forceCreate   bool
)

func init() {
	timestampCmd.Flags().Int64VarP(&timestampSecs, "timestamp", "t", time.Now().Unix(), "Specify the timestamp value to use (in unix time)")
	timestampCmd.MarkFlagRequired("timestamp")
	timestampCmd.Flags().StringVarP(&timestampFile, "file", "f", "", "Specify the genesis file to update")
	timestampCmd.MarkFlagRequired("file")
	timestampCmd.Flags().BoolVar(&forceUpdate, "force", false, "Force updating timestamp even if already set")
	genesisCmd.AddCommand(timestampCmd)

	dumpGenesisIDCmd.Flags().StringVarP(&genesisFile, "file", "f", "", "Specify the genesis file to check")
	dumpGenesisIDCmd.MarkFlagRequired("file")
	genesisCmd.AddCommand(dumpGenesisIDCmd)

	dumpGenesisHashCmd.Flags().StringVarP(&genesisFile, "file", "f", "", "Specify the genesis file to hash")
	dumpGenesisHashCmd.MarkFlagRequired("file")
	genesisCmd.AddCommand(dumpGenesisHashCmd)

	ensureCmd.Flags().StringVarP(&networkName, "network", "n", "", "The network name for the genesis file")
	ensureCmd.MarkFlagRequired("network")
	ensureCmd.Flags().StringVar(&sourceFile, "source", "", "Specify the source genesis file")
	ensureCmd.MarkFlagRequired("source")
	ensureCmd.Flags().StringVar(&releaseDir, "releasedir", "", "Specify the location of release genesis.json files")
	ensureCmd.MarkFlagRequired("releasedir")
	ensureCmd.Flags().StringVar(&targetFile, "target", "", "Specify the target genesis file (if any)")
	ensureCmd.Flags().BoolVar(&createRelease, "release", false, "Create timestamped release version of genesis.json if missing")
	ensureCmd.Flags().BoolVar(&forceCreate, "force", false, "Force creating a new timestamped release version of genesis.json, even if present")
	genesisCmd.AddCommand(ensureCmd)
}

var genesisCmd = &cobra.Command{
	Use:   "genesis",
	Short: "Build-time genesis modifications",
	Run: func(cmd *cobra.Command, args []string) {
		// Fall back
		cmd.HelpFunc()(cmd, args)
	},
}

var timestampCmd = &cobra.Command{
	Use:   "timestamp",
	Short: "Initialize the timestamp",
	Run: func(cmd *cobra.Command, args []string) {
		genesis, err := bookkeeping.LoadGenesisFromFile(timestampFile)
		if err != nil {
			reportErrorf("Error loading genesis file '%s': %v\n", timestampFile, err)
		}

		if genesis.Timestamp == 0 || forceUpdate {
			if genesis.Timestamp == 0 {
				reportInfof("Overwriting previously initialized Genesis timestamp\n")
			}

			genesis.Timestamp = timestampSecs

			// Write out the genesis file in the same way we do to generate originally
			// (see gen/generate.go)
			jsonData := protocol.EncodeJSON(genesis)
			err = ioutil.WriteFile(timestampFile, append(jsonData, '\n'), 0666)
			if err != nil {
				reportErrorf("Error saving genesis file '%s': %v\n", timestampFile, err)
			}
		} else {
			reportInfof("Genesis timestamp already initialized - not updating\n")
		}
	},
}

var dumpGenesisIDCmd = &cobra.Command{
	Use:   "id",
	Short: "Dump the genesis ID for the specified genesis file",
	Run: func(cmd *cobra.Command, args []string) {
		// Load genesis
		genesisText, err := ioutil.ReadFile(genesisFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read genesis file %s: %v\n", genesisFile, err)
			os.Exit(1)
		}

		var genesis bookkeeping.Genesis
		err = protocol.DecodeJSON(genesisText, &genesis)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot parse genesis file %s: %v\n", genesisFile, err)
			os.Exit(1)
		}

		fmt.Print(genesis.ID())
	},
}

var dumpGenesisHashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Dump the genesis Hash for the specified genesis file",
	Run: func(cmd *cobra.Command, args []string) {
		// Load genesis
		genesisText, err := ioutil.ReadFile(genesisFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read genesis file %s: %v\n", genesisFile, err)
			os.Exit(1)
		}

		var genesis bookkeeping.Genesis
		err = protocol.DecodeJSON(genesisText, &genesis)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot parse genesis file %s: %v\n", genesisFile, err)
			os.Exit(1)
		}

		hash := crypto.HashObj(genesis)
		fmt.Print(hash.String())
	},
}

var ensureCmd = &cobra.Command{
	Use:   "ensure",
	Short: "Ensures a valid timestamped genesis file exists",
	Run: func(cmd *cobra.Command, args []string) {
		// Validate arguments
		if createRelease {
			if targetFile != "" {
				reportErrorf("target parameter specified but not needed\n")
			}
		}

		sourceGenesis, err := bookkeeping.LoadGenesisFromFile(sourceFile)
		if err != nil {
			reportErrorf("Error loading source genesis file '%s': %v\n", sourceFile, err)
		}

		// Seed timestamp in case we don't have a release to copy
		sourceGenesis.Timestamp = time.Now().Unix()

		releaseNetworkDir := filepath.Join(releaseDir, networkName)
		releaseFile := filepath.Join(releaseNetworkDir, sourceGenesis.ID()) + ".json"

		if createRelease {
			// In case we're creating first one for network, ensure output directory exists
			err := os.MkdirAll(releaseNetworkDir, os.ModeDir|os.FileMode(0777))
			if err != nil {
				reportErrorf("Error creating release genesis output directory '%s': %v\n", releaseNetworkDir, err)
			}

			// Make sure release genesis file exists and if it does, the hash matches its computed hash
			err = ensureReleaseGenesis(sourceGenesis, releaseFile)
			if err != nil {
				reportErrorf("Error ensuring release genesis file '%s': %v\n", releaseFile, err)
			}
		} else {
			// If the target network is custom (not well-known), don't bother with release genesis file
			if util.IsDir(releaseNetworkDir) {
				sourceGenesis, err = verifyReleaseGenesis(sourceGenesis, releaseFile)
				if err != nil {
					reportErrorf("Error verifying release genesis file '%s': %v\n", releaseFile, err)
				}
			}

			// If targetFile not specified, we are just verifying consistency.
			// If we're here, our files/hashes are consistent.
			if targetFile == "" {
				reportInfoln("Source and Release files and hashes appear consistent.")
			} else {
				// Write source genesis (now updated with release timestamp, if applicable)
				jsonData := protocol.EncodeJSON(sourceGenesis)
				err = ioutil.WriteFile(targetFile, jsonData, 0666)
				if err != nil {
					reportErrorf("Error writing target genesis file '%s': %v\n", targetFile, err)
				}
			}
		}
	},
}

func ensureReleaseGenesis(src bookkeeping.Genesis, releaseFile string) (err error) {
	releaseFileHash := releaseFile + ".hash"
	releaseGenesis, err := bookkeeping.LoadGenesisFromFile(releaseFile)
	if err != nil {
		// Doesn't exist or error loading.  If NotExist, we'll create it
		if !os.IsNotExist(err) {
			return fmt.Errorf("error loading file: %v", err)
		}
	} else if !forceCreate {
		// No error loading existing release genesis and we aren't asked to recreate
		// Just verify and return
		return verifyGenesisHashes(src, releaseGenesis, releaseFileHash)
	}

	releaseGenesis = src
	jsonData := protocol.EncodeJSON(releaseGenesis)
	err = ioutil.WriteFile(releaseFile, jsonData, 0666)
	if err != nil {
		return fmt.Errorf("error saving file: %v", err)
	}

	hash := crypto.HashObj(releaseGenesis)
	err = ioutil.WriteFile(releaseFileHash, []byte(hash.String()), 0666)
	if err != nil {
		return fmt.Errorf("error saving hash file '%s': %v", releaseFileHash, err)
	}
	return
}

func verifyReleaseGenesis(src bookkeeping.Genesis, releaseFile string) (updateGenesis bookkeeping.Genesis, err error) {
	releaseGenesis, err := bookkeeping.LoadGenesisFromFile(releaseFile)
	if err != nil {
		return
	}

	updateGenesis = src
	updateGenesis.Timestamp = releaseGenesis.Timestamp
	releaseFileHash := releaseFile + ".hash"
	err = verifyGenesisHashes(updateGenesis, releaseGenesis, releaseFileHash)
	return
}

func verifyGenesisHashes(src, release bookkeeping.Genesis, hashFile string) (err error) {
	src.Timestamp = release.Timestamp

	srcHash := crypto.HashObj(src)
	releaseHash := crypto.HashObj(release)
	if srcHash != releaseHash {
		return fmt.Errorf("source and release hashes differ - genesis.json may have diverge from released version")
	}

	relHashBytes, err := ioutil.ReadFile(hashFile)
	if err != nil {
		return fmt.Errorf("error loading release hash file '%s'", hashFile)
	}
	if string(relHashBytes) != releaseHash.String() {
		return fmt.Errorf("release hash appears to have changed since it was released")
	}
	return
}
