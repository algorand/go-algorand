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

package eval

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type mockLedger struct {
	balanceMap map[basics.Address]basics.AccountData
}

func (ml *mockLedger) lookup(addr basics.Address) (ledgercore.AccountData, error) {
	return ledgercore.ToAccountData(ml.balanceMap[addr]), nil
}

// convertToOnline is only suitable for test code because OnlineAccountData
// should have rewards paid. Here, we ignore that for simple tests.
func convertToOnline(ad ledgercore.AccountData) basics.OnlineAccountData {
	return basics.OnlineAccountData{
		MicroAlgosWithRewards: ad.MicroAlgos,
		VotingData: basics.VotingData{
			VoteID:          ad.VoteID,
			SelectionID:     ad.SelectionID,
			StateProofID:    ad.StateProofID,
			VoteFirstValid:  ad.VoteFirstValid,
			VoteLastValid:   ad.VoteLastValid,
			VoteKeyDilution: ad.VoteKeyDilution,
		},
		IncentiveEligible: ad.IncentiveEligible,
	}
}

func (ml *mockLedger) lookupAgreement(addr basics.Address) (basics.OnlineAccountData, error) {
	ad, err := ml.lookup(addr)
	if err != nil { //  impossible, see lookup()
		return basics.OnlineAccountData{}, err
	}
	return convertToOnline(ad), nil
}

func (ml *mockLedger) onlineStake() (basics.MicroAlgos, error) {
	return basics.Algos(55_555), nil
}

func (ml *mockLedger) lookupAppParams(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppParamsDelta, bool, error) {
	params, ok := ml.balanceMap[addr].AppParams[aidx]
	return ledgercore.AppParamsDelta{Params: &params}, ok, nil // XXX make a copy?
}

func (ml *mockLedger) lookupAssetParams(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetParamsDelta, bool, error) {
	params, ok := ml.balanceMap[addr].AssetParams[aidx]
	return ledgercore.AssetParamsDelta{Params: &params}, ok, nil
}

func (ml *mockLedger) lookupAppLocalState(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppLocalStateDelta, bool, error) {
	params, ok := ml.balanceMap[addr].AppLocalStates[aidx]
	return ledgercore.AppLocalStateDelta{LocalState: &params}, ok, nil
}

func (ml *mockLedger) lookupAssetHolding(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetHoldingDelta, bool, error) {
	params, ok := ml.balanceMap[addr].Assets[aidx]
	return ledgercore.AssetHoldingDelta{Holding: &params}, ok, nil
}

func (ml *mockLedger) checkDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl ledgercore.Txlease) error {
	return nil
}

func (ml *mockLedger) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *mockLedger) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return basics.StateSchema{}, nil
}

func (ml *mockLedger) getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return basics.StateSchema{}, nil
}

func (ml *mockLedger) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	return true, nil
}

func (ml *mockLedger) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *mockLedger) kvGet(key string) ([]byte, bool, error) {
	return nil, false, nil
}

func (ml *mockLedger) Counter() uint64 {
	return 0
}

func (ml *mockLedger) GetStateProofNextRound() basics.Round {
	return 0
}

func (ml *mockLedger) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, errors.New("requested blockheader not found")
}

func (ml *mockLedger) GenesisHash() crypto.Digest {
	panic("GenesisHash unused by tests")
}

func (ml *mockLedger) GetStateProofVerificationContext(rnd basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	return nil, errors.New("requested state proof verification data not found")
}

func checkCowByUpdate(t *testing.T, cow *roundCowState, delta ledgercore.AccountDeltas) {
	for i := 0; i < delta.Len(); i++ {
		addr, data := delta.GetByIdx(i)
		d, err := cow.lookup(addr)
		require.NoError(t, err)
		require.Equal(t, d, data)
	}

	d, err := cow.lookup(ledgertesting.RandomAddress())
	require.NoError(t, err)
	require.Equal(t, d, ledgercore.AccountData{})
}

func checkCow(t *testing.T, cow *roundCowState, accts map[basics.Address]basics.AccountData) {
	for addr, data := range accts {
		d, err := cow.lookup(addr)
		require.NoError(t, err)
		require.Equal(t, d, ledgercore.ToAccountData(data))
	}

	d, err := cow.lookup(ledgertesting.RandomAddress())
	require.NoError(t, err)
	require.Equal(t, d, ledgercore.AccountData{})
}

func applyUpdates(cow *roundCowState, updates ledgercore.AccountDeltas) {
	for i := 0; i < updates.Len(); i++ {
		addr, delta := updates.GetByIdx(i)
		cow.putAccount(addr, delta)
	}
}

func TestCowBalance(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts0 := ledgertesting.RandomAccounts(20, true)
	ml := mockLedger{balanceMap: accts0}

	c0 := makeRoundCowState(
		&ml, bookkeeping.BlockHeader{}, config.Consensus[protocol.ConsensusCurrentVersion],
		0, ledgercore.AccountTotals{}, 0)
	checkCow(t, c0, accts0)

	c1 := c0.child(0)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts0)

	updates1, _, _ := ledgertesting.RandomDeltas(10, accts0, 0)
	applyUpdates(c1, updates1)
	checkCow(t, c0, accts0)
	checkCowByUpdate(t, c1, updates1)

	c2 := c1.child(0)
	checkCow(t, c0, accts0)
	checkCowByUpdate(t, c1, updates1)
	checkCowByUpdate(t, c2, updates1)

	accts1 := make(map[basics.Address]basics.AccountData, updates1.Len())
	for i := 0; i < updates1.Len(); i++ {
		addr, _ := updates1.GetByIdx(i)
		var ok bool
		accts1[addr], ok = updates1.GetBasicsAccountData(addr)
		require.True(t, ok)
	}

	checkCow(t, c1, accts1)
	checkCow(t, c2, accts1)

	updates2, _, _ := ledgertesting.RandomDeltas(10, accts1, 0)
	applyUpdates(c2, updates2)
	checkCowByUpdate(t, c1, updates1)
	checkCowByUpdate(t, c2, updates2)

	c2.commitToParent()
	checkCow(t, c0, accts0)
	checkCowByUpdate(t, c1, updates2)

	c1.commitToParent()
	checkCowByUpdate(t, c0, updates2)
}

// TestCowDeltasAfterCommit tests that deltas are still valid after committing to parent.
func TestCowDeltasAfterCommit(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	accts0 := ledgertesting.RandomAccounts(20, true)
	ml := mockLedger{balanceMap: accts0}

	c0 := makeRoundCowState(
		&ml, bookkeeping.BlockHeader{}, config.Consensus[protocol.ConsensusCurrentVersion],
		0, ledgercore.AccountTotals{}, 0)
	checkCow(t, c0, accts0)

	c1 := c0.child(0)

	acctUpdates, _, _ := ledgertesting.RandomDeltas(10, accts0, 0)
	applyUpdates(c1, acctUpdates)
	acctUpdates.Dehydrate() // Prep for comparison

	c1.kvPut("key", []byte("value"))
	expectedKvMods := map[string]ledgercore.KvValueDelta{
		"key": {
			Data: []byte("value"),
		},
	}

	actualDeltas := c1.deltas()
	actualDeltas.Dehydrate() // Prep for comparison
	require.Equal(t, acctUpdates, actualDeltas.Accts)
	require.Equal(t, expectedKvMods, actualDeltas.KvMods)

	// Parent should now have deltas
	c1.commitToParent()
	actualDeltas = c0.deltas()
	actualDeltas.Dehydrate() // Prep for comparison
	require.Equal(t, acctUpdates, actualDeltas.Accts)
	require.Equal(t, expectedKvMods, actualDeltas.KvMods)

	// Deltas remain valid in child after commit
	actualDeltas = c0.deltas()
	actualDeltas.Dehydrate() // Prep for comparison
	require.Equal(t, acctUpdates, actualDeltas.Accts)
	require.Equal(t, expectedKvMods, actualDeltas.KvMods)
}

func BenchmarkCowChild(b *testing.B) {
	b.ReportAllocs()
	cow := makeRoundCowState(nil, bookkeeping.BlockHeader{}, config.ConsensusParams{}, 10000, ledgercore.AccountTotals{}, 16)
	for i := 0; i < b.N; i++ {
		cow.child(16)
		cow.recycle()
	}
}

// Ideally we'd be able to randomize the roundCowState but can't do it via reflection
// since it' can't set unexported fields. This test just makes sure that all of the existing
// fields are correctly reset but won't be able to catch any new fields added.
func TestCowChildReset(t *testing.T) {
	partitiontest.PartitionTest(t)
	cow := makeRoundCowState(nil, bookkeeping.BlockHeader{}, config.ConsensusParams{}, 10000, ledgercore.AccountTotals{}, 16)
	calf := cow.child(16)
	require.NotEmpty(t, calf)
	calf.compatibilityMode = true
	calf.reset()
	// simple fields
	require.Zero(t, calf.commitParent)
	require.Zero(t, calf.proto)
	require.Zero(t, calf.txnCount)
	require.Zero(t, calf.compatibilityMode)
	require.Zero(t, calf.prevTotals)

	// alloced map
	require.NotZero(t, calf.sdeltas)
	require.Empty(t, calf.sdeltas)
}

func TestCowChildReflect(t *testing.T) {
	partitiontest.PartitionTest(t)

	cowFieldNames := map[string]struct{}{
		"lookupParent":             {},
		"commitParent":             {},
		"proto":                    {},
		"mods":                     {},
		"txnCount":                 {},
		"sdeltas":                  {},
		"compatibilityMode":        {},
		"compatibilityGetKeyCache": {},
		"prevTotals":               {},
		"feesCollected":            {},
	}

	cow := roundCowState{}
	v := reflect.ValueOf(cow)
	st := v.Type()
	for i := 0; i < v.NumField(); i++ {
		reflectedCowName := st.Field(i).Name
		require.Containsf(t, cowFieldNames, reflectedCowName, "new field:\"%v\" added to roundCowState, please update roundCowState.reset() to handle it before fixing this test", reflectedCowName)
	}
}

func TestCowStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	version := config.Consensus[protocol.ConsensusCurrentVersion]
	firstStateproof := basics.Round(version.StateProofInterval * 2)
	accts0 := ledgertesting.RandomAccounts(20, true)
	ml := mockLedger{balanceMap: accts0}
	c0 := makeRoundCowState(
		&ml, bookkeeping.BlockHeader{}, version,
		0, ledgercore.AccountTotals{}, 0)

	c0.SetStateProofNextRound(firstStateproof)
	stateproofTxn := transactions.StateProofTxnFields{
		StateProofType: protocol.StateProofBasic,
		Message:        stateproofmsg.Message{LastAttestedRound: firstStateproof + basics.Round(version.StateProofInterval)},
	}

	// can not apply state proof for 3*version.StateProofInterval when we expect 2*version.StateProofInterval
	err := apply.StateProof(stateproofTxn, firstStateproof+1, c0, false)
	a.ErrorIs(err, apply.ErrExpectedDifferentStateProofRound)

	stateproofTxn.Message.LastAttestedRound = firstStateproof
	err = apply.StateProof(stateproofTxn, firstStateproof+1, c0, false)
	a.NoError(err)
	a.Equal(3*basics.Round(version.StateProofInterval), c0.GetStateProofNextRound())

	// try to apply the next stateproof 3*version.StateProofInterval
	stateproofTxn.Message.LastAttestedRound = 3 * basics.Round(version.StateProofInterval)
	err = apply.StateProof(stateproofTxn, firstStateproof+1, c0, false)
	a.NoError(err)
	a.Equal(4*basics.Round(version.StateProofInterval), c0.GetStateProofNextRound())
}
