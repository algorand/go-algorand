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
	"math/rand" // used for replicability of sortition benchmark
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
)

// test SelfCheckSelected (should always be true, with current testingenv parameters)
// and then set balance to 0 and test not SelfCheckSelected
func TestAccountSelected(t *testing.T) {
	N := 1
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(t, 100, 2000)
		period := Period(0)

		leaders := uint64(0)
		for i := range addresses {
			ok, record, selectionSeed, totalMoney := selParams(addresses[i])
			if !ok {
				t.Errorf("can't read selection params")
			}
			sel := AgreementSelector{
				Seed:   selectionSeed,
				Round:  round,
				Period: period,
				Step:   Propose,
			}
			m := Membership{
				Record:     record,
				Selector:   sel,
				TotalMoney: totalMoney,
			}
			u := MakeCredential(vrfSecrets[i], sel)
			credential, _ := u.Verify(proto, m)
			leaders += credential.Weight
		}

		if (leaders < proto.NumProposers/2) || (leaders > 2*proto.NumProposers) {
			t.Errorf("bad number of leaders %v expected %v", leaders, proto.NumProposers)
		}

		committee := uint64(0)
		step := Soft
		for i, addr := range addresses {
			_, record, selectionSeed, totalMoney := selParams(addr)
			sel := AgreementSelector{
				Seed:   selectionSeed,
				Round:  round,
				Period: period,
				Step:   step,
			}
			m := Membership{
				Record:     record,
				Selector:   sel,
				TotalMoney: totalMoney,
			}
			u := MakeCredential(vrfSecrets[i], sel)
			credential, _ := u.Verify(proto, m)
			committee += credential.Weight
		}

		if (committee < uint64(0.8*float64(step.CommitteeSize(proto)))) || (committee > uint64(1.2*float64(step.CommitteeSize(proto)))) {
			t.Errorf("bad number of committee members %v expected %v", committee, step.CommitteeSize(proto))
		}
	}
}

func TestRichAccountSelected(t *testing.T) {
	selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(t, 10, 2000)

	period := Period(0)
	ok, record, selectionSeed, _ := selParams(addresses[0])
	if !ok {
		t.Errorf("can't read selection params")
	}

	TotalMoney := basics.MicroAlgos{Raw: 1 << 50}
	record.MicroAlgos.Raw = TotalMoney.Raw / 2
	sel := AgreementSelector{
		Seed:   selectionSeed,
		Round:  round,
		Period: period,
		Step:   Propose,
	}
	m := Membership{
		Record:     record,
		Selector:   sel,
		TotalMoney: TotalMoney,
	}

	lu := MakeCredential(vrfSecrets[0], sel)
	lcred, _ := lu.Verify(proto, m)

	if lcred.Weight == 0 {
		t.Errorf("bad number of leaders %v expected %v", lcred.Weight, proto.NumProposers)
	}

	step := Cert
	sel = AgreementSelector{
		Seed:   selectionSeed,
		Round:  round,
		Period: period,
		Step:   step,
	}
	m = Membership{
		Record:     record,
		Selector:   sel,
		TotalMoney: TotalMoney,
	}

	cu := MakeCredential(vrfSecrets[0], sel)
	ccred, _ := cu.Verify(proto, m)

	if (ccred.Weight < uint64(0.4*float64(step.CommitteeSize(proto)))) || (ccred.Weight > uint64(.6*float64(step.CommitteeSize(proto)))) {
		t.Errorf("bad number of committee members %v expected %v", ccred.Weight, step.CommitteeSize(proto))
	}
}

func TestPoorAccountSelectedLeaders(t *testing.T) {
	N := 2
	failsLeaders := 0
	leaders := make([]uint64, N)
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(t, 100, 2000)
		period := Period(0)
		for j := range addresses {
			ok, record, selectionSeed, _ := selParams(addresses[j])
			if !ok {
				t.Errorf("can't read selection params")
			}

			sel := AgreementSelector{
				Seed:   selectionSeed,
				Round:  round,
				Period: period,
				Step:   Propose,
			}

			record.MicroAlgos.Raw = uint64(1000 / len(addresses))
			m := Membership{
				Record:     record,
				Selector:   sel,
				TotalMoney: basics.MicroAlgos{Raw: 1000},
			}

			u := MakeCredential(vrfSecrets[j], sel)
			credential, _ := u.Verify(proto, m)
			leaders[i] += credential.Weight

		}

		if leaders[i] < uint64(0.5*float64(proto.NumProposers)) || (leaders[i] > 2*proto.NumProposers) {
			failsLeaders++
		}
	}

	if failsLeaders == 2 {
		t.Errorf("bad number of leaders %v expected %v", leaders, proto.NumProposers)
	}
}

func TestPoorAccountSelectedCommittee(t *testing.T) {
	N := 1
	committee := uint64(0)
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(t, 100, 2000)
		period := Period(0)

		step := Cert
		for j := range addresses {
			ok, record, selectionSeed, _ := selParams(addresses[j])
			if !ok {
				t.Errorf("can't read selection params")
			}

			sel := AgreementSelector{
				Seed:   selectionSeed,
				Round:  round,
				Period: period,
				Step:   step,
			}

			record.MicroAlgos.Raw = uint64(2000 / len(addresses))
			m := Membership{
				Record:     record,
				Selector:   sel,
				TotalMoney: basics.MicroAlgos{Raw: 2000},
			}
			u := MakeCredential(vrfSecrets[j], sel)
			credential, _ := u.Verify(proto, m)
			committee += credential.Weight
		}

		if (committee < uint64(0.8*float64(step.CommitteeSize(proto)))) || (committee > uint64(1.2*float64(step.CommitteeSize(proto)))) {
			t.Errorf("bad number of committee members %v expected %v", committee, step.CommitteeSize(proto))
		}
	}
}

func TestNoMoneyAccountNotSelected(t *testing.T) {
	N := 1
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, _, _, _ := testingenv(t, 10, 2000)
		lookback := basics.Round(2*proto.SeedRefreshInterval + proto.SeedLookback + 1)
		gen := rand.New(rand.NewSource(2))
		_, _, zeroVRFSecret, _ := newAccount(t, gen, lookback, 5)
		period := Period(0)
		ok, record, selectionSeed, _ := selParams(addresses[i])
		if !ok {
			t.Errorf("can't read selection params")
		}
		sel := AgreementSelector{
			Seed:   selectionSeed,
			Round:  round,
			Period: period,
			Step:   Propose,
		}

		record.MicroAlgos.Raw = 0
		m := Membership{
			Record:     record,
			Selector:   sel,
			TotalMoney: basics.MicroAlgos{Raw: 1000},
		}
		u := MakeCredential(zeroVRFSecret, sel)
		_, err := u.Verify(proto, m)
		require.Error(t, err, "account should not have been selected")
	}
}

func TestLeadersSelected(t *testing.T) {
	selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(t, 100, 2000)

	period := Period(0)
	step := Propose

	ok, record, selectionSeed, _ := selParams(addresses[0])
	if !ok {
		t.Errorf("can't read selection params")
	}

	record.MicroAlgos.Raw = 50000
	totalMoney := basics.MicroAlgos{Raw: 100000}

	sel := AgreementSelector{
		Seed:   selectionSeed,
		Round:  round,
		Period: period,
		Step:   step,
	}

	m := Membership{
		Record:     record,
		Selector:   sel,
		TotalMoney: totalMoney,
	}
	_, err := MakeCredential(vrfSecrets[0], sel).Verify(proto, m)
	require.NoError(t, err, "leader should have been selected")
}

func TestCommitteeSelected(t *testing.T) {
	selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(t, 100, 2000)

	period := Period(0)
	step := Soft

	ok, record, selectionSeed, _ := selParams(addresses[0])
	if !ok {
		t.Errorf("can't read selection params")
	}

	record.MicroAlgos.Raw = 50000
	totalMoney := basics.MicroAlgos{Raw: 100000}

	sel := AgreementSelector{
		Seed:   selectionSeed,
		Round:  round,
		Period: period,
		Step:   step,
	}

	m := Membership{
		Record:     record,
		Selector:   sel,
		TotalMoney: totalMoney,
	}
	_, err := MakeCredential(vrfSecrets[0], sel).Verify(proto, m)
	require.NoError(t, err, "committee should have been selected")
}

func TestAccountNotSelected(t *testing.T) {
	selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(t, 100, 2000)
	period := Period(0)
	leaders := uint64(0)
	for i := range addresses {
		ok, record, selectionSeed, totalMoney := selParams(addresses[i])
		if !ok {
			t.Errorf("can't read selection params")
		}

		sel := AgreementSelector{
			Seed:   selectionSeed,
			Round:  round,
			Period: period,
			Step:   Propose,
		}
		record.MicroAlgos.Raw = 0
		m := Membership{
			Record:     record,
			Selector:   sel,
			TotalMoney: totalMoney,
		}
		credential, _ := MakeCredential(vrfSecrets[i], sel).Verify(proto, m)
		require.False(t, credential.Selected())
		leaders += credential.Weight
	}
	require.Zero(t, leaders)
}

// TODO update to remove VRF verification overhead
func BenchmarkSortition(b *testing.B) {
	selParams, _, round, addresses, _, vrfSecrets, _, _ := testingenv(b, 100, 2000)

	period := Period(0)
	step := Soft
	ok, record, selectionSeed, _ := selParams(addresses[0])
	if !ok {
		panic("can't read selection params")
	}

	totalMoney := 100000
	credentials := make([]Credential, b.N)
	money := make([]int, b.N)
	rng := rand.New(rand.NewSource(0))

	for i := 0; i < b.N; i++ {
		money[i] = rng.Intn(totalMoney)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sel := AgreementSelector{
			Seed:   selectionSeed,
			Round:  round,
			Period: period,
			Step:   step,
		}

		record.MicroAlgos.Raw = uint64(money[i])
		m := Membership{
			Record:     record,
			Selector:   sel,
			TotalMoney: basics.MicroAlgos{Raw: uint64(totalMoney)},
		}
		credentials[i], _ = MakeCredential(vrfSecrets[0], sel).Verify(proto, m)
	}
}
