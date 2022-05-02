// Copyright (C) 2019-2022 Algorand, Inc.
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
	"math"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

// chooseParticipation chooses which participation keys to use for going online
// based on the address, round number, and available participation databases
func (c *Client) chooseParticipation(address basics.Address, round basics.Round) (part generated.ParticipationKey, err error) {
	parts, err := c.ListParticipationKeys()
	if err != nil {
		return
	}

	// Loop through each of the participation keys; pick the one that expires farthest in the future.
	var expiry uint64 = 0
	for _, info := range parts {
		// Choose the Participation valid for this round that relates to the passed address
		// that expires farthest in the future.
		// Note that algod will sign votes with all possible Participations. so any should work
		// in the short-term.
		// In the future we should allow the user to specify exactly which partkeys to register.
		if info.Key.VoteFirstValid <= uint64(round) && uint64(round) <= info.Key.VoteLastValid && info.Address == address.String() && info.Key.VoteLastValid > expiry {
			part = info
			expiry = part.Key.VoteLastValid
		}

	}
	if part.Address == "" {
		// Couldn't find one
		err = fmt.Errorf("couldn't find a participation key database for address %v valid at round %v in participation registry", address.GetUserAddress(), round)
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
// it with keys, and saves it in the specified output directory. If the output
// directory is empty, the key will be installed.
func (c *Client) GenParticipationKeysTo(address string, firstValid, lastValid, keyDilution uint64, outDir string) (part account.Participation, filePath string, err error) {

	install := outDir == ""

	// Parse the address
	parsedAddr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return
	}

	firstRound, lastRound := basics.Round(firstValid), basics.Round(lastValid)

	// If we are installing, generate in the temp dir
	if install {
		outDir = os.TempDir()
	}
	// Connect to the database
	partKeyPath, err := participationKeysPath(outDir, parsedAddr, firstRound, lastRound)
	if err != nil {
		return
	}
	_, err = os.Stat(partKeyPath)
	if err == nil {
		err = fmt.Errorf("ParticipationKeys exist for the range %d to %d", firstRound, lastRound)
		return
	} else if !os.IsNotExist(err) {
		err = fmt.Errorf("participation key file '%s' cannot be accessed : %w", partKeyPath, err)
		return
	}

	// If the key is being installed, remove it afterwards.
	if install {
		// Explicitly ignore any errors
		defer func(name string) {
			_ = os.Remove(name)
		}(partKeyPath)
	}

	partdb, err := db.MakeErasableAccessor(partKeyPath)
	if err != nil {
		return
	}

	if keyDilution == 0 {
		keyDilution = 1 + uint64(math.Sqrt(float64(lastRound-firstRound)))
	}

	// Fill the database with new participation keys
	newPart, err := account.FillDBWithParticipationKeys(partdb, parsedAddr, firstRound, lastRound, keyDilution)
	part = newPart.Participation
	partdb.Close()

	if err != nil {
		return
	}

	if install {
		_, err = c.AddParticipationKey(partKeyPath)
	}
	return part, partKeyPath, err
}

// ListParticipationKeys returns the available participation keys,
// as a response object.
func (c *Client) ListParticipationKeys() (partKeyFiles generated.ParticipationKeysResponse, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		partKeyFiles, err = algod.GetParticipationKeys()
	}
	return
}
