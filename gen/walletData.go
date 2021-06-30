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

package gen

import (
	"encoding/json"
	"os"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// DefaultGenesis should be used as the default initial state for any GenesisData
// instance (because we have no ctors...)
var DefaultGenesis = GenesisData{
	FirstPartKeyRound: 0,
	LastPartKeyRound:  3000000,
}

// WalletData represents a wallet's name, percent stake, and initial online status for a genesis.json file
type WalletData struct {
	Name   string
	Stake  float64
	Online bool
}

// GenesisData represents the genesis data for creating a genesis.json and wallets
type GenesisData struct {
	NetworkName       string
	VersionModifier   string
	ConsensusProtocol protocol.ConsensusVersion
	FirstPartKeyRound uint64
	LastPartKeyRound  uint64
	PartKeyDilution   uint64
	Wallets           []WalletData
	FeeSink           basics.Address
	RewardsPool       basics.Address
	DevMode           bool
	Comment           string
}

// LoadGenesisData loads a GenesisData structure from a json file
func LoadGenesisData(file string) (gen GenesisData, err error) {
	gen = DefaultGenesis
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(&gen)
	return gen, err
}
