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

package simulation

import (
	"math"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// requireOverrideCovers ensures that override has a field for every field of params, other than
// those excluded, so that new fields are not forgotten.
func requireOverrideCovers(t *testing.T, override reflect.Type, params reflect.Type, excluded ...string) {
	t.Helper()
	for i := 0; i < params.NumField(); i++ {
		field := params.Field(i)
		if field.Name == "_struct" || slices.Contains(excluded, field.Name) {
			continue
		}
		if field.Anonymous {
			requireOverrideCovers(t, override, field.Type, excluded...)
			continue
		}
		_, ok := override.FieldByName(field.Name)
		require.True(t, ok, "%s has no field for %s.%s", override.Name(), params.Name(), field.Name)
	}
}

func TestOverridesCoverAllFields(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	requireOverrideCovers(t, reflect.TypeFor[AppOverride](), reflect.TypeFor[basics.AppParams]())
	requireOverrideCovers(t, reflect.TypeFor[AssetOverride](), reflect.TypeFor[basics.AssetParams]())
	requireOverrideCovers(t, reflect.TypeFor[AssetHoldingOverride](), reflect.TypeFor[basics.AssetHolding]())
	requireOverrideCovers(t, reflect.TypeFor[AppLocalStateOverride](), reflect.TypeFor[basics.AppLocalState]())
	requireOverrideCovers(t, reflect.TypeFor[AccountOverride](), reflect.TypeFor[ledgercore.AccountData](),
		// The balance is overridden by Balance, and pending rewards are not overridable
		"MicroAlgos", "RewardsBase", "RewardedMicroAlgos",
		// These are derived from the account's resources, so are maintained by their overrides
		"TotalAppSchema", "TotalExtraAppPages", "TotalAppParams", "TotalAppLocalStates",
		"TotalAssetParams", "TotalAssets", "TotalBoxes", "TotalBoxBytes")
}

func newOverlayLedger(t *testing.T, env *simulationtesting.Environment, overrides StateOverrides) simulatorLedger {
	t.Helper()
	l := simulatorLedger{Ledger: env.Ledger, start: env.Ledger.Latest()}
	hdr, err := l.BlockHdr(l.start)
	require.NoError(t, err)
	l.overlay, err = l.buildStateOverlay(overrides, hdr)
	require.NoError(t, err)
	return l
}

func TestAccountOverridesDoNotOverflowIntermediateTotals(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	rnd := env.Ledger.Latest()
	totals, err := env.Ledger.Totals(rnd)
	require.NoError(t, err)
	a := env.Accounts[0].Addr
	aData, _, err := env.Ledger.LookupWithoutRewards(rnd, a)
	require.NoError(t, err)
	var b basics.Address
	var bData ledgercore.AccountData
	for _, account := range env.Accounts[1:] {
		data, _, lookupErr := env.Ledger.LookupWithoutRewards(rnd, account.Addr)
		require.NoError(t, lookupErr)
		if data.Status == aData.Status {
			b, bData = account.Addr, data
			break
		}
	}
	require.NotEqual(t, basics.Address{}, b)

	// The final status total fits exactly, but adding b before removing a would overflow.
	proto := env.TxnInfo.CurrentProtocolParams()
	aMoney, _ := aData.Money(proto.RewardUnit, totals.RewardsLevel)
	bMoney, _ := bData.Money(proto.RewardUnit, totals.RewardsLevel)
	var statusTotal uint64
	switch aData.Status {
	case basics.Online:
		statusTotal = totals.Online.Money.Raw
	case basics.Offline:
		statusTotal = totals.Offline.Money.Raw
	case basics.NotParticipating:
		statusTotal = totals.NotParticipating.Money.Raw
	}
	zero := basics.MicroAlgos{}
	large := basics.MicroAlgos{Raw: math.MaxUint64 - statusTotal + aMoney.Raw + bMoney.Raw}
	overrides := StateOverrides{Accounts: map[basics.Address]AccountOverride{
		a: {Balance: &zero},
		b: {Balance: &large},
	}}
	for range 20 {
		l := newOverlayLedger(t, &env, overrides)
		switch aData.Status {
		case basics.Online:
			require.Equal(t, uint64(math.MaxUint64), l.overlay.totals.Online.Money.Raw)
		case basics.Offline:
			require.Equal(t, uint64(math.MaxUint64), l.overlay.totals.Offline.Money.Raw)
		case basics.NotParticipating:
			require.Equal(t, uint64(math.MaxUint64), l.overlay.totals.NotParticipating.Money.Raw)
		}
	}
}

func TestAppOverrideAllParams(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	creator := env.Accounts[0].Addr
	sponsor := env.Accounts[1].Addr
	aidx := env.CreateApp(creator, simulationtesting.AppParams{
		ApprovalProgram:   "#pragma version 8\nint 1",
		ClearStateProgram: "#pragma version 8\nint 1",
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
	})

	approval := []byte{0x08, 0x81, 0x01}
	clear := []byte{0x08, 0x81, 0x00}
	globalSchema := basics.StateSchema{NumUint: 2, NumByteSlice: 3}
	localSchema := basics.StateSchema{NumUint: 4, NumByteSlice: 5}
	extraPages := uint32(1)
	version := uint64(9)
	yes := true

	l := newOverlayLedger(t, &env, StateOverrides{Apps: map[basics.AppIndex]AppOverride{
		aidx: {
			ApprovalProgram:   approval,
			ClearStateProgram: clear,
			GlobalStateSchema: &globalSchema,
			LocalStateSchema:  &localSchema,
			ExtraProgramPages: &extraPages,
			Version:           &version,
			SizeSponsor:       &sponsor,
			ForeignBoxReads:   &yes,
			FamilyBoxAccess:   &yes,
			GlobalState:       basics.TealKeyValue{"k": {Type: basics.TealUintType, Uint: 1}},
		},
	}})

	res, err := l.LookupApplication(l.start, creator, aidx)
	require.NoError(t, err)
	require.NotNil(t, res.AppParams)
	require.Equal(t, basics.AppParams{
		ApprovalProgram:   approval,
		ClearStateProgram: clear,
		GlobalState:       basics.TealKeyValue{"k": {Type: basics.TealUintType, Uint: 1}},
		StateSchemas:      basics.StateSchemas{LocalStateSchema: localSchema, GlobalStateSchema: globalSchema},
		ExtraProgramPages: extraPages,
		Version:           version,
		SizeSponsor:       sponsor,
		ForeignBoxReads:   true,
		FamilyBoxAccess:   true,
	}, *res.AppParams)

	// The global schema and extra pages charge moves from the creator to the new sponsor
	realCreator, _, err := env.Ledger.LookupWithoutRewards(l.start, creator)
	require.NoError(t, err)
	realSponsor, _, err := env.Ledger.LookupWithoutRewards(l.start, sponsor)
	require.NoError(t, err)

	creatorData, _, err := l.LookupWithoutRewards(l.start, creator)
	require.NoError(t, err)
	require.Equal(t, realCreator.TotalAppParams, creatorData.TotalAppParams)
	require.Equal(t, realCreator.TotalAppSchema.SubSchema(basics.StateSchema{NumUint: 1}), creatorData.TotalAppSchema)
	require.Equal(t, realCreator.TotalExtraAppPages, creatorData.TotalExtraAppPages)

	sponsorData, _, err := l.LookupWithoutRewards(l.start, sponsor)
	require.NoError(t, err)
	require.Equal(t, realSponsor.TotalAppSchema.AddSchema(globalSchema), sponsorData.TotalAppSchema)
	require.Equal(t, realSponsor.TotalExtraAppPages+extraPages, sponsorData.TotalExtraAppPages)

	// Clearing the sponsor moves the charge back to the creator
	var zero basics.Address
	l = newOverlayLedger(t, &env, StateOverrides{Apps: map[basics.AppIndex]AppOverride{
		aidx: {SizeSponsor: &zero, GlobalStateSchema: &globalSchema},
	}})
	creatorData, _, err = l.LookupWithoutRewards(l.start, creator)
	require.NoError(t, err)
	require.Equal(t, realCreator.TotalAppSchema.SubSchema(basics.StateSchema{NumUint: 1}).AddSchema(globalSchema), creatorData.TotalAppSchema)
	_, touched := l.overlay.accounts[sponsor]
	require.False(t, touched)
}

func TestAssetOverrideHoldings(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	creator := env.Accounts[0].Addr
	holder := env.Accounts[1].Addr
	aidx := env.CreateAsset(creator, basics.AssetParams{Total: 100})
	env.TransferAlgos(creator, holder, 1)
	newAidx := basics.AssetIndex(env.TxnInfo.LatestHeader.TxnCounter)

	rnd := env.Ledger.Latest()
	realCreator, _, err := env.Ledger.LookupWithoutRewards(rnd, creator)
	require.NoError(t, err)
	realHolder, _, err := env.Ledger.LookupWithoutRewards(rnd, holder)
	require.NoError(t, err)

	yes := true
	total := uint64(55)
	amount := uint64(5)
	l := newOverlayLedger(t, &env, StateOverrides{
		Accounts: map[basics.Address]AccountOverride{
			// The creator's own holding of a new asset can be overridden
			creator: {Assets: map[basics.AssetIndex]AssetHoldingOverride{newAidx: {Amount: &amount}}},
			holder: {Assets: map[basics.AssetIndex]AssetHoldingOverride{
				aidx:    {},
				newAidx: {},
			}},
		},
		Assets: map[basics.AssetIndex]AssetOverride{
			// An existing asset's DefaultFrozen applies to accounts opted in by override
			aidx:    {DefaultFrozen: &yes},
			newAidx: {Creator: creator, Total: &total},
		},
	})

	res, err := l.LookupAsset(l.start, holder, aidx)
	require.NoError(t, err)
	require.Equal(t, &basics.AssetHolding{Frozen: true}, res.AssetHolding)
	require.Nil(t, res.AssetParams)

	res, err = l.LookupAsset(l.start, holder, newAidx)
	require.NoError(t, err)
	require.Equal(t, &basics.AssetHolding{}, res.AssetHolding)

	res, err = l.LookupAsset(l.start, creator, newAidx)
	require.NoError(t, err)
	require.Equal(t, &basics.AssetParams{Total: total}, res.AssetParams)
	require.Equal(t, &basics.AssetHolding{Amount: amount}, res.AssetHolding)

	// The existing creator's holding is untouched
	res, err = l.LookupAsset(l.start, creator, aidx)
	require.NoError(t, err)
	require.Equal(t, &basics.AssetHolding{Amount: 100}, res.AssetHolding)
	require.True(t, res.AssetParams.DefaultFrozen)

	creatorAddr, ok, err := l.GetCreatorForRound(l.start, basics.CreatableIndex(newAidx), basics.AssetCreatable)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, creator, creatorAddr)
	_, ok, err = l.GetCreatorForRound(l.start, basics.CreatableIndex(newAidx), basics.AppCreatable)
	require.NoError(t, err)
	require.False(t, ok)

	creatorData, _, err := l.LookupWithoutRewards(l.start, creator)
	require.NoError(t, err)
	require.Equal(t, realCreator.TotalAssetParams+1, creatorData.TotalAssetParams)
	require.Equal(t, realCreator.TotalAssets+1, creatorData.TotalAssets)

	holderData, _, err := l.LookupWithoutRewards(l.start, holder)
	require.NoError(t, err)
	require.Equal(t, realHolder.TotalAssets+2, holderData.TotalAssets)
	require.Equal(t, realHolder.TotalAssetParams, holderData.TotalAssetParams)
}

func TestLocalStateOverrides(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	creator := env.Accounts[0].Addr
	optedIn := env.Accounts[1].Addr
	newOptIn := env.Accounts[2].Addr
	optOut := env.Accounts[3].Addr
	localSchema := basics.StateSchema{NumUint: 1}
	aidx := env.CreateApp(creator, simulationtesting.AppParams{
		ApprovalProgram:   "#pragma version 8\nint 1",
		ClearStateProgram: "#pragma version 8\nint 1",
		LocalStateSchema:  localSchema,
	})
	env.OptIntoApp(optedIn, aidx)
	env.OptIntoApp(optOut, aidx)

	rnd := env.Ledger.Latest()
	real := make(map[basics.Address]ledgercore.AccountData)
	for _, addr := range []basics.Address{optedIn, newOptIn, optOut} {
		acct, _, err := env.Ledger.LookupWithoutRewards(rnd, addr)
		require.NoError(t, err)
		real[addr] = acct
	}

	bigSchema := basics.StateSchema{NumUint: 2, NumByteSlice: 1}
	appLocalSchema := basics.StateSchema{NumByteSlice: 3}
	kv := basics.TealKeyValue{
		"u": {Type: basics.TealUintType, Uint: 1},
		"b": {Type: basics.TealBytesType, Bytes: "v"},
	}
	l := newOverlayLedger(t, &env, StateOverrides{
		Accounts: map[basics.Address]AccountOverride{
			optedIn:  {Apps: map[basics.AppIndex]AppLocalStateOverride{aidx: {Schema: &bigSchema, KeyValue: kv}}},
			newOptIn: {Apps: map[basics.AppIndex]AppLocalStateOverride{aidx: {}}},
			optOut:   {Apps: map[basics.AppIndex]AppLocalStateOverride{aidx: {OptOut: true}}},
		},
		// A new opt-in takes the app's overridden local schema
		Apps: map[basics.AppIndex]AppOverride{aidx: {LocalStateSchema: &appLocalSchema}},
	})

	// An existing opt-in's schema and state are replaced
	res, err := l.LookupApplication(l.start, optedIn, aidx)
	require.NoError(t, err)
	require.Equal(t, &basics.AppLocalState{Schema: bigSchema, KeyValue: kv}, res.AppLocalState)
	acct, _, err := l.LookupWithoutRewards(l.start, optedIn)
	require.NoError(t, err)
	require.Equal(t, real[optedIn].TotalAppLocalStates, acct.TotalAppLocalStates)
	require.Equal(t, real[optedIn].TotalAppSchema.SubSchema(localSchema).AddSchema(bigSchema), acct.TotalAppSchema)

	res, err = l.LookupApplication(l.start, newOptIn, aidx)
	require.NoError(t, err)
	require.Equal(t, &basics.AppLocalState{Schema: appLocalSchema}, res.AppLocalState)
	acct, _, err = l.LookupWithoutRewards(l.start, newOptIn)
	require.NoError(t, err)
	require.Equal(t, real[newOptIn].TotalAppLocalStates+1, acct.TotalAppLocalStates)
	require.Equal(t, real[newOptIn].TotalAppSchema.AddSchema(appLocalSchema), acct.TotalAppSchema)

	res, err = l.LookupApplication(l.start, optOut, aidx)
	require.NoError(t, err)
	require.Nil(t, res.AppLocalState)
	acct, _, err = l.LookupWithoutRewards(l.start, optOut)
	require.NoError(t, err)
	require.Equal(t, real[optOut].TotalAppLocalStates-1, acct.TotalAppLocalStates)
	require.Equal(t, real[optOut].TotalAppSchema.SubSchema(localSchema), acct.TotalAppSchema)

	// Callers cannot modify the overlay through the returned state
	res, err = l.LookupApplication(l.start, optedIn, aidx)
	require.NoError(t, err)
	res.AppLocalState.KeyValue["u"] = basics.TealValue{Type: basics.TealUintType, Uint: 99}
	res, err = l.LookupApplication(l.start, optedIn, aidx)
	require.NoError(t, err)
	require.Equal(t, kv, res.AppLocalState.KeyValue)

	// The real ledger is unaffected
	res, err = env.Ledger.LookupApplication(rnd, optOut, aidx)
	require.NoError(t, err)
	require.NotNil(t, res.AppLocalState)
	res, err = env.Ledger.LookupApplication(rnd, newOptIn, aidx)
	require.NoError(t, err)
	require.Nil(t, res.AppLocalState)
}

func TestAccountOverrideFields(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	rnd := env.Ledger.Latest()
	totals, err := env.Ledger.Totals(rnd)
	require.NoError(t, err)
	proto := env.TxnInfo.CurrentProtocolParams()

	// Find an online account to take offline
	var addr basics.Address
	var real ledgercore.AccountData
	for _, account := range env.Accounts {
		data, _, lookupErr := env.Ledger.LookupWithoutRewards(rnd, account.Addr)
		require.NoError(t, lookupErr)
		if data.Status == basics.Online {
			addr, real = account.Addr, data
			break
		}
	}
	require.False(t, addr.IsZero(), "no online account")
	money, _ := real.Money(proto.RewardUnit, totals.RewardsLevel)

	offline := basics.Offline
	authAddr := env.Accounts[0].Addr
	voteID := crypto.OneTimeSignatureVerifier{1}
	selectionID := crypto.VRFVerifier{2}
	stateProofID := merklesignature.Commitment{3}
	first, last := basics.Round(4), basics.Round(5)
	dilution := uint64(6)
	yes := true
	lastProposed, lastHeartbeat := basics.Round(7), basics.Round(8)
	l := newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
		addr: {
			AuthAddr:          &authAddr,
			Status:            &offline,
			VoteID:            &voteID,
			SelectionID:       &selectionID,
			StateProofID:      &stateProofID,
			VoteFirstValid:    &first,
			VoteLastValid:     &last,
			VoteKeyDilution:   &dilution,
			IncentiveEligible: &yes,
			LastProposed:      &lastProposed,
			LastHeartbeat:     &lastHeartbeat,
		},
	}})

	expected := real
	expected.AuthAddr = authAddr
	expected.Status = basics.Offline
	expected.VotingData = basics.VotingData{
		VoteID:          voteID,
		SelectionID:     selectionID,
		StateProofID:    stateProofID,
		VoteFirstValid:  first,
		VoteLastValid:   last,
		VoteKeyDilution: dilution,
	}
	expected.IncentiveEligible = true
	expected.LastProposed = lastProposed
	expected.LastHeartbeat = lastHeartbeat
	acct, _, err := l.LookupWithoutRewards(l.start, addr)
	require.NoError(t, err)
	require.Equal(t, expected, acct)

	// The account's stake moves from the online to the offline totals
	require.Equal(t, totals.Online.Money.Raw-money.Raw, l.overlay.totals.Online.Money.Raw)
	require.Equal(t, totals.Offline.Money.Raw+money.Raw, l.overlay.totals.Offline.Money.Raw)
}
