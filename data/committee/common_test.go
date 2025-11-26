// Copyright (C) 2019-2025 Algorand, Inc.
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

package committee

import (
	"io"
	"math/rand"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/protocol"
)

type selectionParameterFn func(addr basics.Address) (bool, BalanceRecord, Seed, basics.MicroAlgos)
type selectionParameterListFn func(addr []basics.Address) (bool, []BalanceRecord, Seed, basics.MicroAlgos)

var proto = config.Consensus[protocol.ConsensusCurrentVersion]

func newAccount(t testing.TB, gen io.Reader) (basics.Address, *crypto.SignatureSecrets, *crypto.VrfPrivkey) {
	var seed crypto.Seed
	gen.Read(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	_, v := crypto.VrfKeygenFromSeed(seed)
	addr := basics.Address(s.SignatureVerifier)
	return addr, s, &v
}

// testingenv creates a random set of participating accounts and the associated
// selection parameters for use testing committee membership and credential
// validation.  seedGen is provided as an external source of randomness for the
// selection seed; if the caller persists seedGen between calls to testingenv,
// each iteration that calls testingenv will exercise a new selection seed.
// formerly, testingenv, generated transactions and one-time secrets as well,
// but they were not used by the tests.
func testingenv(t testing.TB, numAccounts, numTxs int, seedGen io.Reader) (selectionParameterFn, selectionParameterListFn, basics.Round, []basics.Address, []*crypto.SignatureSecrets, []*crypto.VrfPrivkey) {
	return testingenvMoreKeys(t, numAccounts, numTxs, seedGen)
}

func testingenvMoreKeys(t testing.TB, numAccounts, numTxs int, seedGen io.Reader) (selectionParameterFn, selectionParameterListFn, basics.Round, []basics.Address, []*crypto.SignatureSecrets, []*crypto.VrfPrivkey) {
	if seedGen == nil {
		seedGen = rand.New(rand.NewSource(1)) // same source as setting GODEBUG=randautoseed=0, same as pre-Go 1.20 default seed
	}
	P := numAccounts          // n accounts
	maxMoneyAtStart := 100000 // max money start
	minMoneyAtStart := 10000  // max money start

	// generate accounts
	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	addrs := make([]basics.Address, P)
	secrets := make([]*crypto.SignatureSecrets, P)
	vrfSecrets := make([]*crypto.VrfPrivkey, P)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	lookback := basics.Round(2*proto.SeedRefreshInterval + proto.SeedLookback + 1)
	var total basics.MicroAlgos
	for i := 0; i < P; i++ {
		addr, sigSec, vrfSec := newAccount(t, gen)
		addrs[i] = addr
		secrets[i] = sigSec
		vrfSecrets[i] = vrfSec

		startamt := uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))
		short := addr
		genesis[short] = basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  basics.MicroAlgos{Raw: startamt},
			SelectionID: vrfSec.Pubkey(),
		}
		total.Raw += startamt
	}

	var seed Seed
	seedGen.Read(seed[:])

	for i := 0; i < numTxs; i++ {
		seedGen.Read(make([]byte, 4)) // to match output from previous versions, which shared global RNG for seed & note
	}

	selParams := func(addr basics.Address) (bool, BalanceRecord, Seed, basics.MicroAlgos) {
		data, ok := genesis[addr]
		if !ok {
			return false, BalanceRecord{}, Seed{}, basics.MicroAlgos{Raw: 0}
		}
		return true, BalanceRecord{Addr: addr, OnlineAccountData: basics_testing.OnlineAccountData(data)}, seed, total
	}

	selParamsList := func(addrs []basics.Address) (ok bool, records []BalanceRecord, seed Seed, total basics.MicroAlgos) {
		records = make([]BalanceRecord, len(addrs))
		for i, addr := range addrs {
			var record BalanceRecord
			ok, record, seed, total = selParams(addr)
			if !ok {
				return false, nil, Seed{}, basics.MicroAlgos{Raw: 0}
			}
			records[i] = record
		}
		ok = true
		return
	}

	return selParams, selParamsList, lookback, addrs, secrets, vrfSecrets
}

/* TODO deprecate these types after they have been removed successfully */

type (
	// Step is a sequence number denoting distinct stages in Algorand
	Step uint64

	// Period is used to track progress with a given round in the protocol
	Period uint64

	// RoundPeriod represents a specific Period in a specific Round of the protocol
	RoundPeriod struct {
		basics.Round
		Period
	}
)

// An AgreementSelector is the input used to define
// proposers and members of voting committees.
type AgreementSelector struct {
	Seed   Seed         `codec:"seed"`
	Round  basics.Round `codec:"rnd"`
	Period Period       `codec:"per"`
	Step   Step         `codec:"step"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (sel AgreementSelector) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AgreementSelector, protocol.EncodeReflect(&sel)
}

// CommitteeSize returns the size of the committee,
// which is determined by AgreementSelector.Step.
func (sel AgreementSelector) CommitteeSize(proto config.ConsensusParams) uint64 {
	return sel.Step.CommitteeSize(proto)
}

// Algorand 2.0 steps
const (
	Propose Step = iota
	Soft
	Cert
	Next
)

// CommitteeSize returns the size of the committee required for the Step
func (s Step) CommitteeSize(proto config.ConsensusParams) uint64 {
	switch s {
	case Propose:
		return proto.NumProposers
	case Soft:
		return proto.SoftCommitteeSize
	case Cert:
		return proto.CertCommitteeSize
	default:
		return proto.NextCommitteeSize
	}
}
