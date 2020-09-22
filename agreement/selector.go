// Copyright (C) 2019-2020 Algorand, Inc.
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

package agreement

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
)

// A Selector is the input used to define proposers and members of voting
// committees.
type selector struct {
	_struct struct{} `codec:""` // not omitempty

	Seed   committee.Seed `codec:"seed"`
	Round  basics.Round   `codec:"rnd"`
	Period period         `codec:"per"`
	Step   step           `codec:"step"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (sel selector) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AgreementSelector, protocol.Encode(&sel)
}

// CommitteeSize returns the size of the committee, which is determined by
// Selector.Step.
func (sel selector) CommitteeSize(proto config.ConsensusParams) uint64 {
	return sel.Step.committeeSize(proto)
}

func balanceRound(r basics.Round, cparams config.ConsensusParams) basics.Round {
	return r.SubSaturate(basics.Round(2 * cparams.SeedRefreshInterval * cparams.SeedLookback))
}

func seedRound(r basics.Round, cparams config.ConsensusParams) basics.Round {
	return r.SubSaturate(basics.Round(cparams.SeedLookback))
}

// a helper function for obtaining memberhship verification parameters.
func membership(l LedgerReader, addr basics.Address, r basics.Round, p period, s step) (m committee.Membership, err error) {
	cparams, err := l.ConsensusParams(ParamsRound(r))
	if err != nil {
		return
	}
	balanceRound := balanceRound(r, cparams)
	seedRound := seedRound(r, cparams)

	record, err := l.Lookup(balanceRound, addr)
	if err != nil {
		err = fmt.Errorf("Service.initializeVote (r=%d): Failed to obtain balance record for address %v in round %d: %w", r, addr, balanceRound, err)
		return
	}

	total, err := l.Circulation(balanceRound)
	if err != nil {
		err = fmt.Errorf("Service.initializeVote (r=%d): Failed to obtain total circulation in round %d: %v", r, balanceRound, err)
		return
	}

	seed, err := l.Seed(seedRound)
	if err != nil {
		err = fmt.Errorf("Service.initializeVote (r=%d): Failed to obtain seed in round %d: %v", r, seedRound, err)
		return
	}

	m.Record = committee.BalanceRecord{AccountData: record, Addr: addr}
	m.Selector = selector{Seed: seed, Round: r, Period: p, Step: s}
	m.TotalMoney = total
	return m, nil
}
