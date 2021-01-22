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

package committee

import (
	"io"
	"math/rand"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type selectionParameterFn func(addr basics.Address) (bool, BalanceRecord, Seed, basics.MicroAlgos)
type selectionParameterListFn func(addr []basics.Address) (bool, []BalanceRecord, Seed, basics.MicroAlgos)

var proto = config.Consensus[protocol.ConsensusCurrentVersion]

func newAccount(t testing.TB, gen io.Reader, latest basics.Round, keyBatchesForward uint) (basics.Address, *crypto.SignatureSecrets, *crypto.VrfPrivkey, *crypto.OneTimeSignatureSecrets) {
	var seed crypto.Seed
	gen.Read(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	_, v := crypto.VrfKeygenFromSeed(seed)
	o := crypto.GenerateOneTimeSignatureSecrets(basics.OneTimeIDForRound(latest, proto.DefaultKeyDilution).Batch, uint64(keyBatchesForward))
	addr := basics.Address(s.SignatureVerifier)
	return addr, s, &v, o
}

func signTx(s *crypto.SignatureSecrets, t transactions.Transaction) transactions.SignedTxn {
	return t.Sign(s)
}

func testingenv(t testing.TB, numAccounts, numTxs int) (selectionParameterFn, selectionParameterListFn, basics.Round, []basics.Address, []*crypto.SignatureSecrets, []*crypto.VrfPrivkey, []*crypto.OneTimeSignatureSecrets, []transactions.SignedTxn) {
	return testingenvMoreKeys(t, numAccounts, numTxs, uint(5))
}

func testingenvMoreKeys(t testing.TB, numAccounts, numTxs int, keyBatchesForward uint) (selectionParameterFn, selectionParameterListFn, basics.Round, []basics.Address, []*crypto.SignatureSecrets, []*crypto.VrfPrivkey, []*crypto.OneTimeSignatureSecrets, []transactions.SignedTxn) {
	P := numAccounts          // n accounts
	TXs := numTxs             // n txns
	maxMoneyAtStart := 100000 // max money start
	minMoneyAtStart := 10000  // max money start
	transferredMoney := 100   // max money/txn
	maxFee := 10              // max maxFee/txn
	E := basics.Round(50)     // max round

	// generate accounts
	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	addrs := make([]basics.Address, P)
	secrets := make([]*crypto.SignatureSecrets, P)
	vrfSecrets := make([]*crypto.VrfPrivkey, P)
	otSecrets := make([]*crypto.OneTimeSignatureSecrets, P)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	lookback := basics.Round(2*proto.SeedRefreshInterval + proto.SeedLookback + 1)
	var total basics.MicroAlgos
	for i := 0; i < P; i++ {
		addr, sigSec, vrfSec, otSec := newAccount(t, gen, lookback, keyBatchesForward)
		addrs[i] = addr
		secrets[i] = sigSec
		vrfSecrets[i] = vrfSec
		otSecrets[i] = otSec

		startamt := uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))
		short := addr
		genesis[short] = basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  basics.MicroAlgos{Raw: startamt},
			SelectionID: vrfSec.Pubkey(),
			VoteID:      otSec.OneTimeSignatureVerifier,
		}
		total.Raw += startamt
	}

	var seed Seed
	rand.Read(seed[:])

	tx := make([]transactions.SignedTxn, TXs)
	for i := 0; i < TXs; i++ {
		send := gen.Int() % P
		recv := gen.Int() % P

		saddr := addrs[send]
		raddr := addrs[recv]
		amt := basics.MicroAlgos{Raw: uint64(gen.Int() % transferredMoney)}
		fee := basics.MicroAlgos{Raw: uint64(gen.Int() % maxFee)}

		t := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:     saddr,
				Fee:        fee,
				FirstValid: 0,
				LastValid:  E,
				Note:       make([]byte, 4),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: raddr,
				Amount:   amt,
			},
		}
		rand.Read(t.Note)
		tx[i] = t.Sign(secrets[send])
	}

	selParams := func(addr basics.Address) (bool, BalanceRecord, Seed, basics.MicroAlgos) {
		data, ok := genesis[addr]
		if !ok {
			return false, BalanceRecord{}, Seed{}, basics.MicroAlgos{Raw: 0}
		}
		return true, BalanceRecord{Addr: addr, AccountData: data}, seed, total
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

	return selParams, selParamsList, lookback, addrs, secrets, vrfSecrets, otSecrets, tx
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
