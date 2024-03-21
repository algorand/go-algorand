// Copyright (C) 2019-2024 Algorand, Inc.
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

package participation

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

func participationKeysPath(dataDir string, address basics.Address, firstValid, lastValid basics.Round) (string, error) {
	// Build /<dataDir>/<genesisID>/<address>.<first_round>.<last_round>.partkey
	first := uint64(firstValid)
	last := uint64(lastValid)
	fileName := config.PartKeyFilename(address.String(), first, last)
	return filepath.Join(dataDir, fileName), nil
}

// GenParticipationKeysTo creates a .partkey database for a given address, fills
// it with keys, and saves it in the specified output directory. If the output
// directory is empty, the key will be installed.
func GenParticipationKeysTo(address string, firstValid, lastValid, keyDilution uint64, outDir string, installFunc func(keyPath string) error) (part account.Participation, filePath string, err error) {

	install := outDir == ""
	if install && installFunc == nil {
		return account.Participation{}, "", fmt.Errorf("must provide an install function when installing keys")
	}

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
		keyDilution = account.DefaultKeyDilution(firstRound, lastRound)
	}

	// Fill the database with new participation keys
	newPart, err := account.FillDBWithParticipationKeys(partdb, parsedAddr, firstRound, lastRound, keyDilution)
	part = newPart.Participation
	partdb.Close()

	if err != nil {
		return
	}

	if install {
		err = installFunc(partKeyPath)
	}
	return part, partKeyPath, err
}
