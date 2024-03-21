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

package libgoal

import (
	"fmt"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal/participation"
)

// chooseParticipation chooses which participation keys to use for going online
// based on the address, round number, and available participation databases
func (c *Client) chooseParticipation(address basics.Address, round basics.Round) (part model.ParticipationKey, err error) {
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

// GenParticipationKeys creates a .partkey database for a given address, fills
// it with keys, and installs it in the right place
func (c *Client) GenParticipationKeys(address string, firstValid, lastValid, keyDilution uint64) (part account.Participation, filePath string, err error) {
	installFunc := func(keyPath string) error {
		_, err := c.AddParticipationKey(keyPath)
		return err
	}
	return participation.GenParticipationKeysTo(address, firstValid, lastValid, keyDilution, "", installFunc)
}

// ListParticipationKeys returns the available participation keys,
// as a response object.
func (c *Client) ListParticipationKeys() (partKeyFiles model.ParticipationKeysResponse, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		partKeyFiles, err = algod.GetParticipationKeys()
	}
	return
}
