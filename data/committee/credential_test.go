// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/sortition"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// test SelfCheckSelected (should always be true, with current testingenv parameters)
// and then set balance to 0 and test not SelfCheckSelected
func TestAccountSelected(t *testing.T) {
	partitiontest.PartitionTest(t)

	seedGen := rand.New(rand.NewSource(1))
	N := 1
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 100, 2000, seedGen)
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

		if (leaders < uint64(proto.NumProposers/2)) || (leaders > uint64(2*proto.NumProposers)) {
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
		if i == 0 {
			// pin down deterministic outputs for first iteration
			assert.EqualValues(t, 17, leaders)
			assert.EqualValues(t, 2918, committee)
		}
	}
}

func TestRichAccountSelected(t *testing.T) {
	partitiontest.PartitionTest(t)

	selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 10, 2000, nil)

	period := Period(0)
	ok, record, selectionSeed, _ := selParams(addresses[0])
	if !ok {
		t.Errorf("can't read selection params")
	}

	TotalMoney := basics.MicroAlgos{Raw: 1 << 50}
	record.MicroAlgosWithRewards.Raw = TotalMoney.Raw / 2
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
	// pin down deterministic outputs, given initial seed values
	assert.EqualValues(t, 6, lcred.Weight)
	assert.EqualValues(t, 735, ccred.Weight)
}

func TestPoorAccountSelectedLeaders(t *testing.T) {
	partitiontest.PartitionTest(t)

	seedGen := rand.New(rand.NewSource(1))
	N := 2
	failsLeaders := 0
	leaders := make([]uint64, N)
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 100, 2000, seedGen)
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

			record.MicroAlgosWithRewards.Raw = uint64(1000 / len(addresses))
			m := Membership{
				Record:     record,
				Selector:   sel,
				TotalMoney: basics.MicroAlgos{Raw: 1000},
			}

			u := MakeCredential(vrfSecrets[j], sel)
			credential, _ := u.Verify(proto, m)
			leaders[i] += credential.Weight

		}

		if leaders[i] < uint64(0.5*float64(proto.NumProposers)) || (leaders[i] > uint64(2*proto.NumProposers)) {
			failsLeaders++
		}
	}

	if failsLeaders == 2 {
		t.Errorf("bad number of leaders %v expected %v", leaders, proto.NumProposers)
	}
	// pin down deterministic outputs, given initial seed values
	assert.EqualValues(t, 18, leaders[0])
	assert.EqualValues(t, 20, leaders[1])
}

func TestPoorAccountSelectedCommittee(t *testing.T) {
	partitiontest.PartitionTest(t)

	seedGen := rand.New(rand.NewSource(1))
	N := 1
	committee := uint64(0)
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 100, 2000, seedGen)
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

			record.MicroAlgosWithRewards.Raw = uint64(2000 / len(addresses))
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
		if i == 0 { // pin down deterministic committee size, given initial seed value
			assert.EqualValues(t, 1513, committee)
		}
	}
}

func TestNoMoneyAccountNotSelected(t *testing.T) {
	partitiontest.PartitionTest(t)

	seedGen := rand.New(rand.NewSource(1))
	N := 1
	for i := 0; i < N; i++ {
		selParams, _, round, addresses, _, _ := testingenv(t, 10, 2000, seedGen)
		gen := rand.New(rand.NewSource(2))
		_, _, zeroVRFSecret := newAccount(t, gen)
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

		record.MicroAlgosWithRewards.Raw = 0
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
	partitiontest.PartitionTest(t)

	selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 100, 2000, nil)

	period := Period(0)
	step := Propose

	ok, record, selectionSeed, _ := selParams(addresses[0])
	if !ok {
		t.Errorf("can't read selection params")
	}

	record.MicroAlgosWithRewards.Raw = 50000
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
	partitiontest.PartitionTest(t)

	selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 100, 2000, nil)

	period := Period(0)
	step := Soft

	ok, record, selectionSeed, _ := selParams(addresses[0])
	if !ok {
		t.Errorf("can't read selection params")
	}

	record.MicroAlgosWithRewards.Raw = 50000
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
	partitiontest.PartitionTest(t)

	selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 100, 2000, nil)
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
		record.MicroAlgosWithRewards.Raw = 0
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
	selParams, _, round, addresses, _, vrfSecrets := testingenv(b, 100, 2000, nil)

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

		record.MicroAlgosWithRewards.Raw = uint64(money[i])
		m := Membership{
			Record:     record,
			Selector:   sel,
			TotalMoney: basics.MicroAlgos{Raw: uint64(totalMoney)},
		}
		credentials[i], _ = MakeCredential(vrfSecrets[0], sel).Verify(proto, m)
	}
}

// TestSortitionMoneyDomain verifies that every stake reachable under consensus
// stays inside the domain bound exported by the sortition package. The money
// argument of sortition.SelectF128 is a voting stake in microalgos, bounded
// above by total online money and therefore by the supply minted at genesis;
// behavior at or above sortition.SelectF128MaxMoney is undefined in the sortition
// package (it does not enforce the bound). If an economics change (for example an inflationary
// model) raises the possible supply, or a consensus version introduces a
// committee size beyond it, this test must fail before the change can
// silently misround consensus.
func TestSortitionMoneyDomain(t *testing.T) {
	partitiontest.PartitionTest(t)

	// 10 billion Algos in microalgos: the mainnet genesis supply. The ledger
	// conserves total money, so no VotingStake or TotalMoney can exceed it.
	const mainnetSupply = uint64(10_000_000_000_000_000)

	require.Less(t, mainnetSupply, sortition.SelectF128MaxMoney,
		"genesis supply reaches the sortition domain bound")
	// Insist on headroom so erosion of the margin is a deliberate decision.
	require.LessOrEqual(t, 7*mainnetSupply, sortition.SelectF128MaxMoney,
		"less than 2 bits of headroom between the supply and the sortition domain bound")

	for v, p := range config.Consensus {
		if !p.EnableSelectF128 {
			continue
		}
		committees := []uint64{
			p.NumProposers, p.SoftCommitteeSize, p.CertCommitteeSize, p.NextCommitteeSize,
			p.LateCommitteeSize, p.RedoCommitteeSize, p.DownCommitteeSize,
		}
		for _, size := range committees {
			// credential.go panics when committeeSize exceeds total money,
			// so a committee size beyond the supply could never form a valid p.
			require.LessOrEqual(t, size, mainnetSupply,
				"consensus version %v: committee size %d exceeds the supply", v, size)
		}
	}

	// The checks above prove the guard cannot fire under mainnet economics;
	// this exercises the guard itself. A stake at the domain bound must make
	// Verify fail closed with an error instead of calling SelectF128 out of
	// domain. No released consensus version enables the flag yet, so force it on
	// a copy of the current proto.
	protoF128 := proto
	protoF128.EnableSelectF128 = true

	selParams, _, round, addresses, _, vrfSecrets := testingenv(t, 100, 2000, nil)
	ok, record, selectionSeed, _ := selParams(addresses[0])
	require.True(t, ok)
	// A voting stake exactly at the bound trips the >= check; TotalMoney is set
	// no lower so the earlier total-money panic does not fire first.
	record.MicroAlgosWithRewards.Raw = sortition.SelectF128MaxMoney
	sel := AgreementSelector{Seed: selectionSeed, Round: round, Period: Period(0), Step: Propose}
	m := Membership{
		Record:     record,
		Selector:   sel,
		TotalMoney: basics.MicroAlgos{Raw: sortition.SelectF128MaxMoney},
	}
	_, err := MakeCredential(vrfSecrets[0], sel).Verify(protoF128, m)
	require.ErrorContains(t, err, "at or above SelectF128MaxMoney")
}
