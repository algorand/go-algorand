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

package libgoal

import (
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// chooseParticipation chooses which participation keys to use for going online
// based on the address, round number, and available participation databases
func (c *Client) chooseParticipation(address basics.Address, round basics.Round) (part account.Participation, err error) {
	genID, err := c.GenesisID()
	if err != nil {
		return
	}

	// Get a list of files in the participation keys directory
	keyDir := filepath.Join(c.DataDir(), genID)
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return
	}
	// This lambda will be used for finding the desired file.
	checkIfFileIsDesiredKey := func(file os.FileInfo, expiresAfter basics.Round) (part account.Participation, err error) {
		var handle db.Accessor
		var partCandidate account.Participation

		// If it can't be a participation key database, skip it
		if !config.IsPartKeyFilename(file.Name()) {
			return
		}

		filename := file.Name()

		// Fetch a handle to this database
		handle, err = db.MakeErasableAccessor(filepath.Join(keyDir, filename))
		if err != nil {
			// Couldn't open it, skip it
			return
		}
		defer handle.Close()

		// Fetch an account.Participation from the database
		partCandidate, err = account.RestoreParticipation(handle)
		if err != nil {
			// Couldn't read it, skip it
			return
		}

		// Return the Participation valid for this round that relates to the passed address
		// that expires farthest in the future.
		// Note that algod will sign votes with all possible Participations. so any should work
		// in the short-term.
		// In the future we should allow the user to specify exactly which partkeys to register.
		if partCandidate.FirstValid <= round && round <= partCandidate.LastValid && partCandidate.Parent == address && partCandidate.LastValid > expiresAfter {
			part = partCandidate
		}
		return
	}

	// Loop through each of the files; pick the one that expires farthest in the future.
	var expiry basics.Round
	for _, info := range files {
		// Use above lambda so the deferred handle closure happens each loop
		partCandidate, err := checkIfFileIsDesiredKey(info, expiry)
		if err == nil && (!partCandidate.Parent.IsZero()) {
			part = partCandidate
			expiry = part.LastValid
		}
	}
	if part.Parent.IsZero() {
		// Couldn't find one
		err = fmt.Errorf("Couldn't find a participation key database for address %v valid at round %v in directory %v", address.GetUserAddress(), round, keyDir)
		return
	}
	return
}

func participationKeysPath(dataDir string, address basics.Address, firstValid, lastValid basics.Round) (string, error) {
	// Build /<dataDir>/<genesisID>/<address>.<first_round>.<last_round>.partkey
	first := uint64(firstValid)
	last := uint64(lastValid)
	fileName := config.PartKeyFilename(address.String(), first, last)
	return filepath.Join(dataDir, fileName), nil
}

// GenParticipationKeys creates a .partkey database for a given address, fills
// it with keys, and installs it in the right place
func (c *Client) GenParticipationKeys(address string, firstValid, lastValid, keyDilution uint64) (part account.Participation, filePath string, err error) {
	return c.GenParticipationKeysTo(address, firstValid, lastValid, keyDilution, "")
}

// GenParticipationKeysTo creates a .partkey database for a given address, fills
// it with keys, and saves it in the specified output directory.
func (c *Client) GenParticipationKeysTo(address string, firstValid, lastValid, keyDilution uint64, outDir string) (part account.Participation, filePath string, err error) {
	// Parse the address
	parsedAddr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return
	}

	firstRound, lastRound := basics.Round(firstValid), basics.Round(lastValid)

	// Get the current protocol for ephemeral key parameters
	stat, err := c.Status()
	if err != nil {
		return
	}

	proto, ok := c.consensus[protocol.ConsensusVersion(stat.LastVersion)]
	if !ok {
		err = fmt.Errorf("consensus protocol %s not supported", stat.LastVersion)
		return
	}

	// If output directory wasn't specified, store it in the current ledger directory.
	if outDir == "" {
		// Get the GenesisID for use in the participation key path
		var genID string
		genID, err = c.GenesisID()
		if err != nil {
			return
		}

		outDir = filepath.Join(c.DataDir(), genID)
	}
	// Connect to the database
	partKeyPath, err := participationKeysPath(outDir, parsedAddr, firstRound, lastRound)
	if err != nil {
		return
	}
	partdb, err := db.MakeErasableAccessor(partKeyPath)
	if err != nil {
		return
	}

	if keyDilution == 0 {
		keyDilution = proto.DefaultKeyDilution
	}

	// Fill the database with new participation keys
	newPart, err := account.FillDBWithParticipationKeys(partdb, parsedAddr, firstRound, lastRound, keyDilution)
	return newPart, partKeyPath, err
}

// InstallParticipationKeys creates a .partkey database for a given address,
// based on an existing database from inputfile.  On successful install, it
// deletes the input file.
func (c *Client) InstallParticipationKeys(inputfile string) (part account.Participation, filePath string, err error) {
	// Get the GenesisID for use in the participation key path
	var genID string
	genID, err = c.GenesisID()
	if err != nil {
		return
	}

	outDir := filepath.Join(c.DataDir(), genID)

	inputdb, err := db.MakeErasableAccessor(inputfile)
	if err != nil {
		return
	}
	defer inputdb.Close()

	partkey, err := account.RestoreParticipation(inputdb)
	if err != nil {
		return
	}

	if partkey.Parent == (basics.Address{}) {
		err = fmt.Errorf("Cannot install partkey with missing (zero) parent address")
		return
	}

	newdbpath, err := participationKeysPath(outDir, partkey.Parent, partkey.FirstValid, partkey.LastValid)
	if err != nil {
		return
	}

	newdb, err := db.MakeErasableAccessor(newdbpath)
	if err != nil {
		return
	}

	newpartkey := partkey
	newpartkey.Store = newdb
	err = newpartkey.Persist()
	if err != nil {
		return
	}

	proto, ok := c.consensus[protocol.ConsensusCurrentVersion]
	if !ok {
		err = fmt.Errorf("Unknown consensus protocol %s", protocol.ConsensusCurrentVersion)
		return
	}

	// After successful install, remove the input copy of the
	// partkey so that old keys cannot be recovered after they
	// are used by algod.  We try to delete the data inside
	// sqlite first, so the key material is zeroed out from
	// disk blocks, but regardless of whether that works, we
	// delete the input file.  The consensus protocol version
	// is irrelevant for the maxuint64 round number we pass in.
	errCh := partkey.DeleteOldKeys(basics.Round(math.MaxUint64), proto)
	err = <-errCh
	if err != nil {
		return
	}
	os.Remove(inputfile)

	return newpartkey, newdbpath, nil
}

// ListParticipationKeys returns the available participation keys,
// as a map from database filename to Participation key object.
func (c *Client) ListParticipationKeys() (partKeyFiles map[string]account.Participation, err error) {
	genID, err := c.GenesisID()
	if err != nil {
		return
	}

	// Get a list of files in the participation keys directory
	keyDir := filepath.Join(c.DataDir(), genID)
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return
	}

	partKeyFiles = make(map[string]account.Participation)
	for _, file := range files {
		// If it can't be a participation key database, skip it
		if !config.IsPartKeyFilename(file.Name()) {
			continue
		}

		filename := file.Name()

		// Fetch a handle to this database
		handle, err := db.MakeErasableAccessor(filepath.Join(keyDir, filename))
		if err != nil {
			// Couldn't open it, skip it
			continue
		}

		// Fetch an account.Participation from the database
		part, err := account.RestoreParticipation(handle)
		handle.Close()
		if err != nil {
			// Couldn't read it, skip it
			continue
		}

		partKeyFiles[filename] = part
	}

	return
}
