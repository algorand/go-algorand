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

package bookkeeping

import (
	"io/ioutil"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const (
	// MaxInitialGenesisAllocationSize is the maximum number of accounts that are supported when
	// bootstrapping a new network. The number of account *can* grow further after the bootstrapping.
	// This value is used exclusively for the messagepack decoder, and has no affect on the network
	// capabilities/capacity in any way.
	MaxInitialGenesisAllocationSize = 100000000
)

// A Genesis object defines an Algorand "universe" -- a set of nodes that can
// talk to each other, agree on the ledger contents, etc.  This is defined
// by the initial account states (GenesisAllocation), the initial
// consensus protocol (GenesisProto), and the schema of the ledger.
type Genesis struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// The SchemaID allows nodes to store data specific to a particular
	// universe (in case of upgrades at development or testing time),
	// and as an optimization to quickly check if two nodes are in
	// the same universe.
	SchemaID string `codec:"id"`

	// Network identifies the unique algorand network for which the ledger
	// is valid.
	// Note the Network name should not include a '-', as we generate the
	// GenesisID from "<Network>-<SchemaID>"; the '-' makes it easy
	// to distinguish between the network and schema.
	Network protocol.NetworkID `codec:"network"`

	// Proto is the consensus protocol in use at the genesis block.
	Proto protocol.ConsensusVersion `codec:"proto"`

	// Allocation determines the initial accounts and their state.
	Allocation []GenesisAllocation `codec:"alloc,allocbound=MaxInitialGenesisAllocationSize"`

	// RewardsPool is the address of the rewards pool.
	RewardsPool string `codec:"rwd"`

	// FeeSink is the address of the fee sink.
	FeeSink string `codec:"fees"`

	// Timestamp for the genesis block
	Timestamp int64 `codec:"timestamp"`

	// Arbitrary genesis comment string - will be excluded from file if empty
	Comment string `codec:"comment"`

	// DevMode defines whether this network operates in a developer mode or not. Developer mode networks
	// are a single node network, that operates without the agreement service being active. In liue of the
	// agreement service, a new block is generated each time a node receives a transaction group. The
	// default value for this field is "false", which makes this field empty from it's encoding, and
	// therefore backward compatible.
	DevMode bool `codec:"devmode"`
}

// LoadGenesisFromFile attempts to load a Genesis structure from a (presumably) genesis.json file.
func LoadGenesisFromFile(genesisFile string) (genesis Genesis, err error) {
	// Load genesis.json
	genesisText, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		return
	}

	err = protocol.DecodeJSON(genesisText, &genesis)
	return
}

// ID is the effective Genesis identifier - the combination
// of the network and the ledger schema version
func (genesis Genesis) ID() string {
	return string(genesis.Network) + "-" + genesis.SchemaID
}

// A GenesisAllocation object represents an allocation of algos to
// an address in the genesis block.  Address is the checksummed
// short address.  Comment is a note about what this address is
// representing, and is purely informational.  State is the initial
// account state.
type GenesisAllocation struct {
	// Unfortunately we forgot to specify omitempty, and now
	// this struct must be encoded without omitempty for the
	// Address, Comment, and State fields..
	_struct struct{} `codec:""`

	Address string             `codec:"addr"`
	Comment string             `codec:"comment"`
	State   basics.AccountData `codec:"state"`
}

// ToBeHashed impements the crypto.Hashable interface.
func (genesis Genesis) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Genesis, protocol.Encode(&genesis)
}
