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
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
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

	// BlockOverride is not checked: only a subset of block header fields can be overridden
	// GlobalState is overridden by AppOverride.GlobalDelta
	requireOverrideCovers(t, reflect.TypeFor[AppOverride](), reflect.TypeFor[basics.AppParams](), "GlobalState")
	requireOverrideCovers(t, reflect.TypeFor[AssetOverride](), reflect.TypeFor[basics.AssetParams]())
	requireOverrideCovers(t, reflect.TypeFor[AssetHoldingOverride](), reflect.TypeFor[basics.AssetHolding]())
	// KeyValue is overridden by AppOverride.LocalDeltas
	requireOverrideCovers(t, reflect.TypeFor[AppLocalStateOverride](), reflect.TypeFor[basics.AppLocalState](), "KeyValue")
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

func TestBalanceOverrideLimit(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	rnd := env.Ledger.Latest()
	hdr, err := env.Ledger.BlockHdr(rnd)
	require.NoError(t, err)
	proto := env.TxnInfo.CurrentProtocolParams()
	limit := maxOverrideBalance(hdr, proto)
	require.Less(t, limit, uint64(math.MaxUint64))
	// The limit leaves room for the largest rate the protocol can recalculate, plus the residue
	require.GreaterOrEqual(t, math.MaxUint64-limit, math.MaxUint64/proto.RewardsRateRefreshInterval)

	var a, b basics.Address
	crypto.RandBytes(a[:])
	crypto.RandBytes(b[:])
	balances := func(balance ...uint64) StateOverrides {
		accounts := make(map[basics.Address]AccountOverride)
		for i, addr := range []basics.Address{a, b}[:len(balance)] {
			accounts[addr] = AccountOverride{Balance: &basics.MicroAlgos{Raw: balance[i]}}
		}
		return StateOverrides{Accounts: accounts}
	}
	build := func(overrides StateOverrides) error {
		l := simulatorLedger{Ledger: env.Ledger, start: rnd}
		_, err := l.buildStateOverlay(overrides, hdr)
		return err
	}

	// A balance at the limit is accepted, and one microAlgo more is not
	require.NoError(t, build(balances(limit)))
	err = build(balances(limit + 1))
	require.ErrorAs(t, err, &InvalidRequestError{})
	require.ErrorContains(t, err, "exceeds maximum")

	// Balances within the limit can still overflow the ledger totals, which is checked first
	err = build(balances(limit, limit))
	require.ErrorAs(t, err, &InvalidRequestError{})
	require.ErrorContains(t, err, "account balances overflow ledger totals")
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
			GlobalDelta:       basics.StateDelta{"k": {Action: basics.SetUintAction, Uint: 1}},
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

	// Sponsoring by the creator is stored as the zero address, as the ledger does
	l = newOverlayLedger(t, &env, StateOverrides{Apps: map[basics.AppIndex]AppOverride{
		aidx: {SizeSponsor: &creator},
	}})
	res, err = l.LookupApplication(l.start, creator, aidx)
	require.NoError(t, err)
	require.True(t, res.AppParams.SizeSponsor.IsZero())
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

func TestNewAssetOverrideCreatorHolding(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	creator := env.Accounts[0].Addr
	holder := env.Accounts[1].Addr
	total := uint64(100)
	frozen := true
	realID := env.CreateAsset(creator, basics.AssetParams{Total: total, DefaultFrozen: frozen})
	real, err := env.Ledger.LookupAsset(env.Ledger.Latest(), creator, realID)
	require.NoError(t, err)
	aidx := basics.AssetIndex(env.TxnInfo.LatestHeader.TxnCounter + reservedCreatableIDs + 1)
	overrides := StateOverrides{
		Assets: map[basics.AssetIndex]AssetOverride{
			aidx: {Creator: creator, Total: &total, DefaultFrozen: &frozen},
		},
		Accounts: map[basics.Address]AccountOverride{
			holder: {Assets: map[basics.AssetIndex]AssetHoldingOverride{aidx: {}}},
		},
	}
	l := newOverlayLedger(t, &env, overrides)
	res, err := l.LookupAsset(l.start, creator, aidx)
	require.NoError(t, err)
	require.Equal(t, real.AssetHolding, res.AssetHolding)
	require.False(t, res.AssetHolding.Frozen)
	res, err = l.LookupAsset(l.start, holder, aidx)
	require.NoError(t, err)
	require.True(t, res.AssetHolding.Frozen, "new opt-ins still use DefaultFrozen")

	// Account overrides may explicitly freeze the creator's initial holding.
	overrides.Accounts[creator] = AccountOverride{
		Assets: map[basics.AssetIndex]AssetHoldingOverride{aidx: {Frozen: &frozen}},
	}
	l = newOverlayLedger(t, &env, overrides)
	res, err = l.LookupAsset(l.start, creator, aidx)
	require.NoError(t, err)
	require.Equal(t, &basics.AssetHolding{Amount: total, Frozen: true}, res.AssetHolding)
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
			optedIn:  {Apps: map[basics.AppIndex]AppLocalStateOverride{aidx: {Schema: &bigSchema}}},
			newOptIn: {Apps: map[basics.AppIndex]AppLocalStateOverride{aidx: {}}},
			optOut:   {Apps: map[basics.AppIndex]AppLocalStateOverride{aidx: {OptOut: true}}},
		},
		// A new opt-in takes the app's overridden local schema
		Apps: map[basics.AppIndex]AppOverride{aidx: {
			LocalStateSchema: &appLocalSchema,
			LocalDeltas: map[basics.Address]basics.StateDelta{optedIn: {
				"u": {Action: basics.SetUintAction, Uint: 1},
				"b": {Action: basics.SetBytesAction, Bytes: "v"},
			}},
		}},
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
	authAddr := basics.Address{9}
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

func TestStatusOverrideSettlesRewards(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// The test ledger's rewards level never advances, so use synthetic account data
	const rewardUnit = 1_000_000
	const level = 10
	online, offline, notParticipating := basics.Online, basics.Offline, basics.NotParticipating
	balance := basics.MicroAlgos{Raw: 7_000_000}
	var addr basics.Address

	// An Online account with pending rewards has them credited before going offline
	acct := ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{
		Status: basics.Online, MicroAlgos: basics.MicroAlgos{Raw: 5_000_000}, RewardsBase: 4,
	}}
	moneyBefore, _ := acct.Money(rewardUnit, level)
	require.NoError(t, overlayAccountFields(&acct, addr, AccountOverride{Status: &offline}, rewardUnit, level))
	require.Equal(t, basics.Offline, acct.Status)
	require.Equal(t, uint64(5_000_000+5*(level-4)), acct.MicroAlgos.Raw)
	require.Equal(t, uint64(5*(level-4)), acct.RewardedMicroAlgos.Raw)
	require.Equal(t, uint64(level), acct.RewardsBase)
	moneyAfter, _ := acct.Money(rewardUnit, level)
	require.Equal(t, moneyBefore, moneyAfter)

	// A NotParticipating account's frozen RewardsBase does not earn it rewards once online
	acct = ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{
		Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 5_000_000}, RewardsBase: 4,
	}}
	require.NoError(t, overlayAccountFields(&acct, addr, AccountOverride{Status: &online}, rewardUnit, level))
	require.Equal(t, basics.Online, acct.Status)
	require.Equal(t, uint64(5_000_000), acct.MicroAlgos.Raw)
	require.Equal(t, uint64(level), acct.RewardsBase)
	moneyAfter, _ = acct.Money(rewardUnit, level)
	require.Equal(t, uint64(5_000_000), moneyAfter.Raw)

	// Going NotParticipating keeps the rewards earned while participating
	acct = ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{
		Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 5_000_000}, RewardsBase: 4,
	}}
	require.NoError(t, overlayAccountFields(&acct, addr, AccountOverride{Status: &notParticipating}, rewardUnit, level))
	require.Equal(t, uint64(5_000_000+5*(level-4)), acct.MicroAlgos.Raw)

	// A balance override replaces the balance, including any settled rewards
	acct = ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{
		Status: basics.Online, MicroAlgos: basics.MicroAlgos{Raw: 5_000_000}, RewardsBase: 4,
	}}
	require.NoError(t, overlayAccountFields(&acct, addr, AccountOverride{Status: &offline, Balance: &balance}, rewardUnit, level))
	require.Equal(t, balance, acct.MicroAlgos)
	require.Equal(t, uint64(level), acct.RewardsBase)
}

func TestAuthAddrOverrideToSelf(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	addr := basics.Address{1}
	other := basics.Address{2}

	// An account rekeyed to itself is stored with a zero AuthAddr, as apply.Rekey does
	acct := ledgercore.AccountData{}
	acct.AuthAddr = other
	require.NoError(t, overlayAccountFields(&acct, addr, AccountOverride{AuthAddr: &addr}, 1, 0))
	require.Zero(t, acct.AuthAddr)

	require.NoError(t, overlayAccountFields(&acct, addr, AccountOverride{AuthAddr: &other}, 1, 0))
	require.Equal(t, other, acct.AuthAddr)
}

func TestKnockOfflineCandidateOverrides(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	// Fund a new account and bring it online with a keyreg. It is online but, not being an online
	// genesis account, the ledger does not return it as a candidate.
	var keyregOnline basics.Address
	crypto.RandBytes(keyregOnline[:])
	env.TransferAlgos(env.Accounts[0].Addr, keyregOnline, 10_000_000)
	env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
		Type:            protocol.KeyRegistrationTx,
		Sender:          keyregOnline,
		VotePK:          crypto.OneTimeSignatureVerifier{1},
		SelectionPK:     crypto.VRFVerifier{2},
		StateProofPK:    merklesignature.Commitment{3},
		VoteFirst:       1,
		VoteLast:        100_000,
		VoteKeyDilution: 10,
	}).SignedTxn())

	var genesisOnline []basics.Address
	for _, account := range env.Accounts {
		if account.AcctData.Status == basics.Online {
			genesisOnline = append(genesisOnline, account.Addr)
		}
	}
	require.GreaterOrEqual(t, len(genesisOnline), 2)
	candidate, zeroed := genesisOnline[0], genesisOnline[1]

	proto := env.TxnInfo.CurrentProtocolParams()
	start := env.Ledger.Latest()
	realCandidates, err := env.Ledger.GetKnockOfflineCandidates(start, proto)
	require.NoError(t, err)
	require.Contains(t, realCandidates, candidate)
	require.Contains(t, realCandidates, zeroed)
	require.NotContains(t, realCandidates, keyregOnline)
	keyregData, _, err := env.Ledger.LookupWithoutRewards(start, keyregOnline)
	require.NoError(t, err)
	require.Equal(t, basics.Online, keyregData.Status)

	balance := func(raw uint64) *basics.MicroAlgos { return &basics.MicroAlgos{Raw: raw} }
	dilution := uint64(20)
	l := newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
		candidate:    {Balance: balance(1_000_000_000)},
		zeroed:       {Balance: balance(0)},
		keyregOnline: {VoteKeyDilution: &dilution},
	}})
	candidates, err := l.GetKnockOfflineCandidates(start, proto)
	require.NoError(t, err)
	// A candidate the ledger returns uses its overridden data
	require.Equal(t, uint64(1_000_000_000), candidates[candidate].MicroAlgosWithRewards.Raw)
	// The ledger skips accounts with no stake
	require.NotContains(t, candidates, zeroed)
	// An override that does not set the status to Online does not make an account a candidate
	require.NotContains(t, candidates, keyregOnline)
}

func TestOnlineOverrideCirculationBounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	zero := basics.MicroAlgos{}
	hdr, err := env.Ledger.BlockHdr(env.Ledger.Latest())
	require.NoError(t, err)
	proto := env.TxnInfo.CurrentProtocolParams()
	// Every account is emptied, except that the rewards pool keeps the minimum balance the
	// evaluator requires of it, and one account holds the largest permitted balance
	minBalance := basics.MicroAlgos{Raw: proto.MinBalance}
	maximum := basics.MicroAlgos{Raw: maxOverrideBalance(hdr, proto)}
	accounts := make(map[basics.Address]AccountOverride)
	for _, acct := range env.Accounts {
		accounts[acct.Addr] = AccountOverride{Balance: &zero}
	}
	accounts[env.FeeSinkAccount.Addr] = AccountOverride{Balance: &zero}
	accounts[env.RewardsPoolAccount.Addr] = AccountOverride{Balance: &minBalance}
	accounts[env.Accounts[0].Addr] = AccountOverride{Balance: &maximum}
	l := newOverlayLedger(t, &env, StateOverrides{Accounts: accounts})
	require.Equal(t, maximum.Raw+minBalance.Raw, l.overlay.totals.All().Raw)
	require.NotZero(t, l.overlay.onlineRemoved.Raw)

	// The replaced stake is removed before the replacement is added, so the final
	// circulation is exactly the overridden balance
	circulation, err := l.OnlineCirculation(l.overlay.balanceRound, l.start+1)
	require.NoError(t, err)
	require.Equal(t, maximum, circulation)

	// A final circulation that really exceeds the maximum must still fail.
	l.overlay.onlineRemoved = basics.MicroAlgos{}
	l.overlay.onlineAdded.Raw = math.MaxUint64
	_, err = l.OnlineCirculation(l.overlay.balanceRound, l.start+1)
	require.ErrorAs(t, err, &InvalidRequestError{})
	require.ErrorContains(t, err, "online circulation overflows")

	// Preserve saturation when the approximated original stake exceeds the total.
	l.overlay.onlineRemoved.Raw = math.MaxUint64
	l.overlay.onlineAdded = basics.MicroAlgos{Raw: 123}
	circulation, err = l.OnlineCirculation(l.overlay.balanceRound, l.start+1)
	require.NoError(t, err)
	require.Equal(t, l.overlay.onlineAdded, circulation)
}

func TestBalanceOverrideOfflineAccountAgreement(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	// Move the balance round past 0 to exercise historical agreement state
	proto := env.TxnInfo.CurrentProtocolParams()
	env.AdvanceRounds(int(agreement.BalanceLookback(proto)) + 5)

	// A new account is offline, and a balance override leaves it offline
	var offlineAddr basics.Address
	crypto.RandBytes(offlineAddr[:])
	balance := basics.MicroAlgos{Raw: 1_000_000_000}
	l := newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
		offlineAddr: {Balance: &balance},
	}})
	require.Equal(t, balance, l.overlay.accounts[offlineAddr].MicroAlgos)
	require.NotZero(t, l.overlay.balanceRound)
	require.Contains(t, l.overlay.online, offlineAddr)
	require.Zero(t, l.overlay.online[offlineAddr])
	require.Zero(t, l.overlay.onlineAdded)
	require.Zero(t, l.overlay.onlineRemoved)

	circulation, err := l.OnlineCirculation(l.overlay.balanceRound, l.start+1)
	require.NoError(t, err)
	realCirculation, err := env.Ledger.OnlineCirculation(l.overlay.balanceRound, l.start+1)
	require.NoError(t, err)
	require.Equal(t, realCirculation, circulation)

	// Bringing the same account online with a balance override does affect agreement
	online := basics.Online
	l = newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
		offlineAddr: {Balance: &balance, Status: &online},
	}})
	require.NotZero(t, l.overlay.balanceRound)
	require.Equal(t, balance, l.overlay.online[offlineAddr].MicroAlgosWithRewards)
}

func TestBalanceOverrideRecentlyOfflineAccountAgreement(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, pastLookback := range []bool{false, true} {
		t.Run(fmt.Sprintf("past lookback=%v", pastLookback), func(t *testing.T) {
			t.Parallel()
			env := simulationtesting.PrepareSimulatorTest(t)
			defer env.Close()

			proto := env.TxnInfo.CurrentProtocolParams()
			if pastLookback {
				env.AdvanceRounds(int(agreement.BalanceLookback(proto)) + 5)
			}

			// The account is offline at the start round but still online at the balance round.
			addr := env.Accounts[0].Addr
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Type: protocol.KeyRegistrationTx, Sender: addr,
			}).SignedTxn())
			start := env.Ledger.Latest()
			brnd := agreement.BalanceRound(start+1, proto)
			require.Equal(t, pastLookback, brnd > 0)
			acct, _, err := env.Ledger.LookupWithoutRewards(start, addr)
			require.NoError(t, err)
			require.Equal(t, basics.Offline, acct.Status)
			original, err := env.Ledger.LookupAgreement(brnd, addr)
			require.NoError(t, err)
			require.NotZero(t, original.VotingStake().Raw)
			realCirculation, err := env.Ledger.OnlineCirculation(brnd, start+1)
			require.NoError(t, err)
			withoutOriginal := realCirculation.Raw - original.VotingStake().Raw

			// A balance override alone replaces the stake the account had at the balance round and
			// keeps the rest of its online data there.
			balance := basics.MicroAlgos{Raw: 10_000_000}
			l := newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
				addr: {Balance: &balance},
			}})
			expected := original
			expected.MicroAlgosWithRewards = balance
			data, err := l.LookupAgreement(brnd, addr)
			require.NoError(t, err)
			require.Equal(t, expected, data)
			circulation, err := l.OnlineCirculation(brnd, start+1)
			require.NoError(t, err)
			require.Equal(t, withoutOriginal+balance.Raw, circulation.Raw)
			// The account is offline at the start round, so it is not considered for suspension
			candidates, err := l.GetKnockOfflineCandidates(start, proto)
			require.NoError(t, err)
			require.NotContains(t, candidates, addr)

			// A participation field alone is likewise applied to the balance round data.
			lastHeartbeat := basics.Round(7)
			l = newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
				addr: {LastHeartbeat: &lastHeartbeat},
			}})
			expected = original
			expected.LastHeartbeat = lastHeartbeat
			data, err = l.LookupAgreement(brnd, addr)
			require.NoError(t, err)
			require.Equal(t, expected, data)
			circulation, err = l.OnlineCirculation(brnd, start+1)
			require.NoError(t, err)
			require.Equal(t, realCirculation, circulation)

			// An explicit Offline status applies as of the balance round, removing the stake.
			offline := basics.Offline
			l = newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
				addr: {Balance: &balance, Status: &offline},
			}})
			data, err = l.LookupAgreement(brnd, addr)
			require.NoError(t, err)
			require.Zero(t, data)
			circulation, err = l.OnlineCirculation(brnd, start+1)
			require.NoError(t, err)
			require.Equal(t, withoutOriginal, circulation.Raw)

			unchanged, err := env.Ledger.LookupAgreement(brnd, addr)
			require.NoError(t, err)
			require.Equal(t, original, unchanged)
			unchangedCirculation, err := env.Ledger.OnlineCirculation(brnd, start+1)
			require.NoError(t, err)
			require.Equal(t, realCirculation, unchangedCirculation)
		})
	}
}

func TestBalanceOverrideRecentlyOnlineAccountAgreement(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	proto := env.TxnInfo.CurrentProtocolParams()
	env.AdvanceRounds(int(agreement.BalanceLookback(proto)) + 5)

	// The account is online at the start round but did not exist at the balance round.
	var addr basics.Address
	crypto.RandBytes(addr[:])
	env.TransferAlgos(env.Accounts[0].Addr, addr, 10_000_000)
	env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
		Type:            protocol.KeyRegistrationTx,
		Sender:          addr,
		VotePK:          crypto.OneTimeSignatureVerifier{1},
		SelectionPK:     crypto.VRFVerifier{2},
		StateProofPK:    merklesignature.Commitment{3},
		VoteFirst:       1,
		VoteLast:        100_000,
		VoteKeyDilution: 10,
	}).SignedTxn())
	start := env.Ledger.Latest()
	brnd := agreement.BalanceRound(start+1, proto)
	acct, _, err := env.Ledger.LookupWithoutRewards(start, addr)
	require.NoError(t, err)
	require.Equal(t, basics.Online, acct.Status)
	original, err := env.Ledger.LookupAgreement(brnd, addr)
	require.NoError(t, err)
	require.Zero(t, original)
	realCirculation, err := env.Ledger.OnlineCirculation(brnd, start+1)
	require.NoError(t, err)

	// Without a Status override the account stays not online at the balance round, so neither a
	// balance nor a participation field gives it stake there.
	balance := basics.MicroAlgos{Raw: 1_000_000_000}
	dilution := uint64(20)
	for _, override := range []AccountOverride{{Balance: &balance}, {VoteKeyDilution: &dilution}} {
		l := newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{addr: override}})
		data, err := l.LookupAgreement(brnd, addr)
		require.NoError(t, err)
		require.Zero(t, data)
		circulation, err := l.OnlineCirculation(brnd, start+1)
		require.NoError(t, err)
		require.Equal(t, realCirculation, circulation)
	}

	// An explicit Online status applies as of the balance round, with the start round state.
	online := basics.Online
	l := newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
		addr: {Balance: &balance, Status: &online},
	}})
	data, err := l.LookupAgreement(brnd, addr)
	require.NoError(t, err)
	require.Equal(t, balance, data.MicroAlgosWithRewards)
	require.Equal(t, acct.VotingData, data.VotingData)
	circulation, err := l.OnlineCirculation(brnd, start+1)
	require.NoError(t, err)
	require.Equal(t, realCirculation.Raw+balance.Raw, circulation.Raw)
}

func TestOnlineOverrides(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, pastLookback := range []bool{false, true} {
		t.Run(fmt.Sprintf("past lookback=%v", pastLookback), func(t *testing.T) {
			t.Parallel()
			env := simulationtesting.PrepareSimulatorTest(t)
			defer env.Close()

			proto := env.TxnInfo.CurrentProtocolParams()
			if pastLookback {
				// Move the balance round past 0, so that expired stake is excluded
				env.AdvanceRounds(int(agreement.BalanceLookback(proto)) + 5)
			}
			start := env.Ledger.Latest()
			brnd := agreement.BalanceRound(start+1, proto)
			require.Equal(t, pastLookback, brnd > 0)
			excludeExpired := proto.ExcludeExpiredCirculation && brnd > 0

			// Genesis accounts are online
			stillOnline := env.Accounts[0].Addr
			goneOffline := env.Accounts[1].Addr
			rekeyedOnly := env.Accounts[2].Addr
			var newOnline, expired basics.Address
			crypto.RandBytes(newOnline[:])
			crypto.RandBytes(expired[:])

			realAgreement := func(addr basics.Address) basics.OnlineAccountData {
				data, err := env.Ledger.LookupAgreement(brnd, addr)
				require.NoError(t, err)
				return data
			}
			require.NotZero(t, realAgreement(stillOnline).VotingStake().Raw)
			require.NotZero(t, realAgreement(goneOffline).VotingStake().Raw)
			realCirculation, err := env.Ledger.OnlineCirculation(brnd, start+1)
			require.NoError(t, err)

			online := basics.Online
			offline := basics.Offline
			balance := func(raw uint64) *basics.MicroAlgos { return &basics.MicroAlgos{Raw: raw} }
			voteLast := basics.Round(100_000)
			expiredLast := basics.Round(1)
			voteID := crypto.OneTimeSignatureVerifier{1}
			l := newOverlayLedger(t, &env, StateOverrides{Accounts: map[basics.Address]AccountOverride{
				stillOnline: {Balance: balance(1_000_000_000)},
				goneOffline: {Status: &offline},
				rekeyedOnly: {AuthAddr: &stillOnline},
				newOnline:   {Balance: balance(2_000_000_000), Status: &online, VoteID: &voteID, VoteLastValid: &voteLast},
				expired:     {Balance: balance(3_000_000_000), Status: &online, VoteLastValid: &expiredLast},
			}})
			require.Equal(t, brnd, l.overlay.balanceRound)

			lookup := func(addr basics.Address) basics.OnlineAccountData {
				data, err := l.LookupAgreement(brnd, addr)
				require.NoError(t, err)
				return data
			}
			require.Equal(t, uint64(1_000_000_000), lookup(stillOnline).VotingStake().Raw)
			require.Equal(t, basics.OnlineAccountData{}, lookup(goneOffline))
			// An override that does not affect agreement leaves the account's online data alone
			require.Equal(t, realAgreement(rekeyedOnly), lookup(rekeyedOnly))
			newData := lookup(newOnline)
			require.Equal(t, uint64(2_000_000_000), newData.VotingStake().Raw)
			require.Equal(t, voteID, newData.VoteID)
			require.Equal(t, voteLast, newData.VoteLastValid)

			expected := realCirculation.Raw - realAgreement(stillOnline).VotingStake().Raw -
				realAgreement(goneOffline).VotingStake().Raw + 1_000_000_000 + 2_000_000_000
			if !excludeExpired {
				expected += 3_000_000_000
			}
			circulation, err := l.OnlineCirculation(brnd, start+1)
			require.NoError(t, err)
			require.Equal(t, expected, circulation.Raw)

			// Other rounds are not overridden
			circulation, err = l.OnlineCirculation(brnd, start+2)
			require.NoError(t, err)
			realOther, err := env.Ledger.OnlineCirculation(brnd, start+2)
			require.NoError(t, err)
			require.Equal(t, realOther, circulation)
			if brnd > 0 {
				data, err := l.LookupAgreement(brnd-1, stillOnline)
				require.NoError(t, err)
				realData, err := env.Ledger.LookupAgreement(brnd-1, stillOnline)
				require.NoError(t, err)
				require.Equal(t, realData, data)
			}

			// Accounts overridden online are candidates for suspension, and those overridden
			// offline are not
			candidates, err := l.GetKnockOfflineCandidates(start, proto)
			require.NoError(t, err)
			require.NotNil(t, candidates)
			require.NotContains(t, candidates, goneOffline)
			require.Equal(t, newData, candidates[newOnline])
			require.Contains(t, candidates, expired)
			realCandidates, err := env.Ledger.GetKnockOfflineCandidates(start, proto)
			require.NoError(t, err)
			require.Contains(t, realCandidates, goneOffline, "the ledger's result was modified")

			// A nil candidate list means candidates are not considered at all, so the overlay
			// must not add the accounts it overrode online
			noStateProofs := proto
			noStateProofs.StateProofInterval = 0
			candidates, err = l.GetKnockOfflineCandidates(start, noStateProofs)
			require.NoError(t, err)
			require.Nil(t, candidates)

			// With state proofs but no cached voters, the ledger also returns nil, but accounts
			// overridden online are still candidates. A lookback equal to the interval skips the
			// ledger's genesis account handling, and no voters are cached before the lookback.
			if !pastLookback {
				noVoters := proto
				noVoters.StateProofVotersLookback = noVoters.StateProofInterval
				realCandidates, err = env.Ledger.GetKnockOfflineCandidates(start, noVoters)
				require.NoError(t, err)
				require.Nil(t, realCandidates)
				candidates, err = l.GetKnockOfflineCandidates(start, noVoters)
				require.NoError(t, err)
				require.Equal(t, map[basics.Address]basics.OnlineAccountData{
					newOnline: newData,
					expired:   lookup(expired),
				}, candidates)
			}
		})
	}
}

func TestEvalErrorAttribution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	rnd := env.Ledger.Latest()
	evalErr := errors.New("evaluator failure")

	// Without overrides, the error is returned as is
	l := simulatorLedger{Ledger: env.Ledger, start: rnd}
	require.Equal(t, evalErr, l.evalError(evalErr))

	// The ledger can evaluate an empty block from the start round, so the overrides are at fault
	l.overlay = &stateOverlay{}
	err := l.evalError(evalErr)
	require.ErrorAs(t, err, &InvalidRequestError{})
	require.ErrorIs(t, err, evalErr)

	// The ledger cannot evaluate a block from a round it does not have, so the overrides are not
	// blamed
	l.start = rnd + 10
	require.Equal(t, evalErr, l.evalError(evalErr))
}

func TestCheckPendingRewards(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var addr basics.Address
	acct := ledgercore.AccountData{}
	acct.MicroAlgos = basics.MicroAlgos{Raw: 10}
	acct.RewardsBase = 5

	// Each accepted account can have its rewards applied without panicking
	require.NoError(t, checkPendingRewards(acct, addr, 1, 5))
	require.NoError(t, checkPendingRewards(acct, addr, 1, 6))
	require.Equal(t, uint64(20), acct.WithUpdatedRewards(1, 6).MicroAlgos.Raw)

	// A rewards level below the account's rewards base
	require.ErrorContains(t, checkPendingRewards(acct, addr, 1, 4), "cannot be settled")
	// Rewards that overflow the balance
	acct.MicroAlgos.Raw = math.MaxUint64 - 5
	require.NoError(t, checkPendingRewards(acct, addr, math.MaxUint64, 6))
	require.ErrorContains(t, checkPendingRewards(acct, addr, 1, 6), "cannot be settled")
	// Rewards that overflow by themselves
	require.ErrorContains(t, checkPendingRewards(acct, addr, 1, 7), "cannot be settled")

	// A NotParticipating account accrues no rewards
	acct.Status = basics.NotParticipating
	require.NoError(t, checkPendingRewards(acct, addr, 1, 4))
	require.NoError(t, checkPendingRewards(acct, addr, 1, 7))
}

func TestRecoverPanic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	run := func(f func()) (err error) {
		defer recoverPanic(&err)
		f()
		return nil
	}
	require.NoError(t, run(func() {}))
	require.ErrorContains(t, run(func() { panic("boom") }), "simulation panicked: boom")
}

func TestStateOverridesCount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	rnd := env.Ledger.Latest()
	hdr, err := env.Ledger.BlockHdr(rnd)
	require.NoError(t, err)

	var addr basics.Address
	crypto.RandBytes(addr[:])
	overrides := StateOverrides{
		Accounts: map[basics.Address]AccountOverride{addr: {
			Assets: map[basics.AssetIndex]AssetHoldingOverride{1: {}, 2: {}},
			Apps:   map[basics.AppIndex]AppLocalStateOverride{1: {}},
		}},
		Apps: map[basics.AppIndex]AppOverride{1: {
			// Global state is not looked up per key
			GlobalDelta: basics.StateDelta{"a": {}, "b": {}},
			LocalDeltas: map[basics.Address]basics.StateDelta{addr: {"a": {}}},
			BoxDelta:    basics.StateDelta{"a": {}, "b": {}, "c": {}},
		}},
		Assets: map[basics.AssetIndex]AssetOverride{1: {}, 2: {}},
		Blocks: map[basics.Round]BlockOverride{1: {}},
	}
	require.Equal(t, 12, overrides.count())

	balances := func(n int) StateOverrides {
		accounts := make(map[basics.Address]AccountOverride, n)
		for range n {
			var a basics.Address
			crypto.RandBytes(a[:])
			accounts[a] = AccountOverride{Balance: &basics.MicroAlgos{Raw: 1}}
		}
		return StateOverrides{Accounts: accounts}
	}
	l := simulatorLedger{Ledger: env.Ledger, start: rnd}
	_, err = l.buildStateOverlay(balances(MaxStateOverrides), hdr)
	require.NoError(t, err)
	_, err = l.buildStateOverlay(balances(MaxStateOverrides+1), hdr)
	require.ErrorAs(t, err, &InvalidRequestError{})
	require.ErrorContains(t, err, "exceed maximum")
}
