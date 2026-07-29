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

package ledger

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// lookupResourceGroup identifies which address is queried in a scenario group.
type lookupResourceGroup string

const (
	lookupCreatorGroup   lookupResourceGroup = "creator"
	lookupHolderGroup    lookupResourceGroup = "holder"
	lookupDeltaOnlyGroup lookupResourceGroup = "deltaOnly"
)

// lookupAssetParamsDeltaSpec describes a creator-side asset params delta to apply in a test round.
type lookupAssetParamsDeltaSpec struct {
	params  *basics.AssetParams
	deleted bool
}

// lookupAssetHoldingDeltaSpec describes a queried-account asset holding delta to apply in a test round.
type lookupAssetHoldingDeltaSpec struct {
	holding *basics.AssetHolding
	deleted bool
}

// lookupAssetExpected is the final merged asset row expected from a lookup.
type lookupAssetExpected struct {
	excluded bool
	holding  *basics.AssetHolding
	params   *basics.AssetParams
	creator  basics.Address
}

// lookupAssetScenario keeps one asset test case's setup and expected lookup result together.
type lookupAssetScenario struct {
	name string

	group lookupResourceGroup

	creatorParams           *basics.AssetParams
	initHolding             *basics.AssetHolding
	destroyInCommittedRound bool

	creatorParamsDelta1 *lookupAssetParamsDeltaSpec
	holdingDelta1       *lookupAssetHoldingDeltaSpec
	holdingDelta2       *lookupAssetHoldingDeltaSpec

	want lookupAssetExpected
	id   basics.AssetIndex
}

// lookupAppParamsDeltaSpec describes a creator-side app params delta to apply in a test round.
type lookupAppParamsDeltaSpec struct {
	params  *basics.AppParams
	deleted bool
}

// lookupAppLocalsDeltaSpec describes a queried-account local-state delta to apply in a test round.
type lookupAppLocalsDeltaSpec struct {
	localState *basics.AppLocalState
	deleted    bool
}

// lookupAppExpected is the final merged app row expected from a lookup.
type lookupAppExpected struct {
	excluded   bool
	localState *basics.AppLocalState
	params     *basics.AppParams
	creator    basics.Address
}

// lookupAppScenario keeps one app test case's setup and expected lookup results together.
// Non-creator scenarios also carry the creator's expected view of the same app.
type lookupAppScenario struct {
	name string

	group lookupResourceGroup

	creatorParams  *basics.AppParams
	initLocalState *basics.AppLocalState

	creatorParamsDelta1 *lookupAppParamsDeltaSpec
	localsDelta1        *lookupAppLocalsDeltaSpec
	localsDelta2        *lookupAppLocalsDeltaSpec

	wantWithParams lookupAppExpected
	wantNoParams   lookupAppExpected
	// Non-creator scenarios should also assert the creator's view of the app:
	// creator has params but no local state for these cases.
	wantCreatorWithParams *lookupAppExpected
	wantCreatorNoParams   *lookupAppExpected
	id                    basics.AppIndex
}

// lookupTestAssetParams builds compact asset params fixtures for scenario tables.
func lookupTestAssetParams(total uint64, unitName string) *basics.AssetParams {
	return &basics.AssetParams{Total: total, UnitName: unitName}
}

// lookupTestAssetHolding builds compact asset holding fixtures for scenario tables.
func lookupTestAssetHolding(amount uint64) *basics.AssetHolding {
	return &basics.AssetHolding{Amount: amount}
}

// lookupTestAssetParamsDelta wraps an asset params value as a delta spec.
func lookupTestAssetParamsDelta(params *basics.AssetParams) *lookupAssetParamsDeltaSpec {
	return &lookupAssetParamsDeltaSpec{params: params}
}

// lookupTestDeletedAssetParamsDelta describes deleting asset params in a delta.
func lookupTestDeletedAssetParamsDelta() *lookupAssetParamsDeltaSpec {
	return &lookupAssetParamsDeltaSpec{deleted: true}
}

// lookupTestAssetHoldingDelta wraps an asset holding value as a delta spec.
func lookupTestAssetHoldingDelta(holding *basics.AssetHolding) *lookupAssetHoldingDeltaSpec {
	return &lookupAssetHoldingDeltaSpec{holding: holding}
}

// lookupTestDeletedAssetHoldingDelta describes deleting an asset holding in a delta.
func lookupTestDeletedAssetHoldingDelta() *lookupAssetHoldingDeltaSpec {
	return &lookupAssetHoldingDeltaSpec{deleted: true}
}

// lookupTestAppParams builds compact app params fixtures for scenario tables.
func lookupTestAppParams(approvalByte, clearByte byte) *basics.AppParams {
	return &basics.AppParams{
		ApprovalProgram:   []byte{0x06, 0x81, approvalByte},
		ClearStateProgram: []byte{0x06, 0x81, clearByte},
	}
}

// lookupTestAppLocalState builds compact app local-state fixtures for scenario tables.
func lookupTestAppLocalState(numUint uint64) *basics.AppLocalState {
	return &basics.AppLocalState{Schema: basics.StateSchema{NumUint: numUint}}
}

// lookupTestAppParamsDelta wraps an app params value as a delta spec.
func lookupTestAppParamsDelta(params *basics.AppParams) *lookupAppParamsDeltaSpec {
	return &lookupAppParamsDeltaSpec{params: params}
}

// lookupTestDeletedAppParamsDelta describes deleting app params in a delta.
func lookupTestDeletedAppParamsDelta() *lookupAppParamsDeltaSpec {
	return &lookupAppParamsDeltaSpec{deleted: true}
}

// lookupTestAppLocalsDelta wraps an app local state value as a delta spec.
func lookupTestAppLocalsDelta(localState *basics.AppLocalState) *lookupAppLocalsDeltaSpec {
	return &lookupAppLocalsDeltaSpec{localState: localState}
}

// lookupTestDeletedAppLocalsDelta describes deleting app local state in a delta.
func lookupTestDeletedAppLocalsDelta() *lookupAppLocalsDeltaSpec {
	return &lookupAppLocalsDeltaSpec{deleted: true}
}

// selectLookupTestAddresses picks three ordinary accounts to play creator, holder, and delta-only roles.
func selectLookupTestAddresses(accts map[basics.Address]basics.AccountData) (creatorAddr, holderAddr, deltaOnlyAddr basics.Address) {
	for addr := range accts {
		if addr == testSinkAddr || addr == testPoolAddr {
			continue
		}
		if creatorAddr.IsZero() {
			creatorAddr = addr
			continue
		}
		if holderAddr.IsZero() {
			holderAddr = addr
			continue
		}
		deltaOnlyAddr = addr
		break
	}
	return
}

// lookupGroupQueryAddr maps a scenario group to the address that will be queried.
func lookupGroupQueryAddr(group lookupResourceGroup, creatorAddr, holderAddr, deltaOnlyAddr basics.Address) basics.Address {
	switch group {
	case lookupCreatorGroup:
		return creatorAddr
	case lookupHolderGroup:
		return holderAddr
	case lookupDeltaOnlyGroup:
		return deltaOnlyAddr
	default:
		return basics.Address{}
	}
}

// validateLookupAssetScenario rejects structurally impossible asset fixtures before setup begins.
func validateLookupAssetScenario(t *testing.T, s lookupAssetScenario) {
	t.Helper()

	require.NotEmpty(t, s.name)
	require.NotZero(t, s.group)

	switch s.group {
	case lookupCreatorGroup:
		if s.creatorParams != nil && s.initHolding == nil {
			t.Fatalf("%s: creator with committed params must have committed holding", s.name)
		}
		if s.creatorParams == nil {
			if s.creatorParamsDelta1 == nil || s.creatorParamsDelta1.deleted || s.holdingDelta1 == nil || s.holdingDelta1.deleted {
				t.Fatalf("%s: delta-only creator asset creation must include both params and holding", s.name)
			}
		}
	case lookupHolderGroup:
		if s.creatorParams == nil {
			t.Fatalf("%s: holder scenario must carry committed creator params", s.name)
		}
		if s.initHolding == nil {
			t.Fatalf("%s: holder scenario must have committed holding", s.name)
		}
	case lookupDeltaOnlyGroup:
		t.Fatalf("%s: assets do not use the delta-only query group in this test", s.name)
	default:
		t.Fatalf("%s: unknown asset scenario group %q", s.name, s.group)
	}
}

// validateLookupAppScenario rejects structurally impossible app fixtures before setup begins.
func validateLookupAppScenario(t *testing.T, s lookupAppScenario) {
	t.Helper()

	require.NotEmpty(t, s.name)
	require.NotZero(t, s.group)

	switch s.group {
	case lookupCreatorGroup:
		if s.creatorParams == nil && (s.creatorParamsDelta1 == nil || s.creatorParamsDelta1.deleted) {
			t.Fatalf("%s: creator scenario must have committed params or a creation delta", s.name)
		}
		if s.creatorParams == nil && (s.localsDelta1 == nil || s.localsDelta1.deleted) {
			t.Fatalf("%s: delta-only creator app creation must include local state", s.name)
		}
		if s.wantCreatorWithParams != nil || s.wantCreatorNoParams != nil {
			t.Fatalf("%s: creator scenarios should not set creator-view expectations", s.name)
		}
	case lookupHolderGroup:
		if s.creatorParams == nil {
			t.Fatalf("%s: holder scenario must carry committed creator params", s.name)
		}
		if s.initLocalState == nil {
			t.Fatalf("%s: holder scenario must have committed local state", s.name)
		}
		if s.wantCreatorWithParams == nil || s.wantCreatorNoParams == nil {
			t.Fatalf("%s: holder scenario must set creator-view expectations", s.name)
		}
	case lookupDeltaOnlyGroup:
		if s.creatorParams == nil {
			t.Fatalf("%s: delta-only scenario must carry committed creator params", s.name)
		}
		if s.initLocalState != nil {
			t.Fatalf("%s: delta-only scenario must not have committed local state", s.name)
		}
		if s.wantCreatorWithParams == nil || s.wantCreatorNoParams == nil {
			t.Fatalf("%s: delta-only scenario must set creator-view expectations", s.name)
		}
	default:
		t.Fatalf("%s: unknown app scenario group %q", s.name, s.group)
	}
	if s.wantCreatorWithParams != nil && s.wantCreatorWithParams.localState != nil {
		t.Fatalf("%s: creator-view expectations should not include local state", s.name)
	}
	if s.wantCreatorNoParams != nil && s.wantCreatorNoParams.localState != nil {
		t.Fatalf("%s: creator-view expectations should not include local state", s.name)
	}
}

// lookupAssetParamsDelta converts an optional asset params spec into the delta shape used by the ledger.
func lookupAssetParamsDelta(spec *lookupAssetParamsDeltaSpec) ledgercore.AssetParamsDelta {
	if spec == nil {
		return ledgercore.AssetParamsDelta{}
	}
	return ledgercore.AssetParamsDelta{Params: spec.params, Deleted: spec.deleted}
}

// lookupAssetHoldingDelta converts an optional asset holding spec into the delta shape used by the ledger.
func lookupAssetHoldingDelta(spec *lookupAssetHoldingDeltaSpec) ledgercore.AssetHoldingDelta {
	if spec == nil {
		return ledgercore.AssetHoldingDelta{}
	}
	return ledgercore.AssetHoldingDelta{Holding: spec.holding, Deleted: spec.deleted}
}

// lookupAppParamsDelta converts an optional app params spec into the delta shape used by the ledger.
func lookupAppParamsDelta(spec *lookupAppParamsDeltaSpec) ledgercore.AppParamsDelta {
	if spec == nil {
		return ledgercore.AppParamsDelta{}
	}
	return ledgercore.AppParamsDelta{Params: spec.params, Deleted: spec.deleted}
}

// lookupAppLocalsDelta converts an optional app local-state spec into the delta shape used by the ledger.
func lookupAppLocalsDelta(spec *lookupAppLocalsDeltaSpec) ledgercore.AppLocalStateDelta {
	if spec == nil {
		return ledgercore.AppLocalStateDelta{}
	}
	return ledgercore.AppLocalStateDelta{LocalState: spec.localState, Deleted: spec.deleted}
}

// assertLookupAssetScenario compares one expected asset row against the lookup result map.
func assertLookupAssetScenario(t *testing.T, scenario lookupAssetScenario, results map[basics.AssetIndex]ledgercore.AssetResourceWithIDs) {
	t.Helper()

	got, ok := results[scenario.id]
	if scenario.want.excluded {
		require.False(t, ok, "%s: expected asset to be excluded", scenario.name)
		return
	}

	require.True(t, ok, "%s: expected asset in result map", scenario.name)
	require.Equal(t, scenario.want.holding, got.AssetHolding, "%s: unexpected holding", scenario.name)
	require.Equal(t, scenario.want.params, got.AssetParams, "%s: unexpected params", scenario.name)
	require.Equal(t, scenario.want.creator, got.Creator, "%s: unexpected creator", scenario.name)
}

// assertLookupAppScenario compares one expected app row against the queried account's lookup result map.
func assertLookupAppScenario(t *testing.T, scenario lookupAppScenario, includeParams bool, results map[basics.AppIndex]ledgercore.AppResourceWithIDs) {
	t.Helper()

	expected := scenario.wantNoParams
	mode := "includeParams=false"
	if includeParams {
		expected = scenario.wantWithParams
		mode = "includeParams=true"
	}

	got, ok := results[scenario.id]
	if expected.excluded {
		require.False(t, ok, "%s (%s): expected app to be excluded", scenario.name, mode)
		return
	}

	require.True(t, ok, "%s (%s): expected app in result map", scenario.name, mode)
	require.Equal(t, expected.localState, got.AppLocalState, "%s (%s): unexpected local state", scenario.name, mode)
	require.Equal(t, expected.params, got.AppParams, "%s (%s): unexpected params", scenario.name, mode)
	require.Equal(t, expected.creator, got.Creator, "%s (%s): unexpected creator", scenario.name, mode)
}

// assertLookupAppCreatorView compares one expected app row against the creator's view of a non-creator scenario.
func assertLookupAppCreatorView(t *testing.T, scenario lookupAppScenario, includeParams bool, results map[basics.AppIndex]ledgercore.AppResourceWithIDs) {
	t.Helper()

	var expected *lookupAppExpected
	mode := "includeParams=false"
	if includeParams {
		expected = scenario.wantCreatorWithParams
		mode = "includeParams=true"
	} else {
		expected = scenario.wantCreatorNoParams
	}
	require.NotNil(t, expected, "%s (%s): missing creator-view expectation", scenario.name, mode)

	got, ok := results[scenario.id]
	if expected.excluded {
		require.False(t, ok, "%s (creator view, %s): expected app to be excluded", scenario.name, mode)
		return
	}

	require.True(t, ok, "%s (creator view, %s): expected app in result map", scenario.name, mode)
	require.Equal(t, expected.localState, got.AppLocalState, "%s (creator view, %s): unexpected local state", scenario.name, mode)
	require.Equal(t, expected.params, got.AppParams, "%s (creator view, %s): unexpected params", scenario.name, mode)
	require.Equal(t, expected.creator, got.Creator, "%s (creator view, %s): unexpected creator", scenario.name, mode)
}

// runLookupAssetScenarioGroupTest builds one isolated ledger for an asset address group,
// commits the base fixture, applies up to two uncommitted delta rounds, and asserts the
// merged lookup output for that group's queried address.
func runLookupAssetScenarioGroupTest(t *testing.T, group lookupResourceGroup, scenarios []lookupAssetScenario) {
	t.Helper()

	// Give every scenario a stable synthetic asset ID inside this isolated ledger.
	for i := range scenarios {
		validateLookupAssetScenario(t, scenarios[i])
		scenarios[i].id = basics.AssetIndex(1000 + i)
	}

	testProtocolVersion := protocol.ConsensusCurrentVersion
	protoParams := config.Consensus[testProtocolVersion]
	accts := setupAccts(5)
	creatorAddr, holderAddr, deltaOnlyAddr := selectLookupTestAddresses(accts[0])
	queryAddr := lookupGroupQueryAddr(group, creatorAddr, holderAddr, deltaOnlyAddr)

	// Fill the expected creator field for any scenario where params still exist at lookup time.
	for i := range scenarios {
		if scenarios[i].want.excluded {
			continue
		}
		if scenarios[i].destroyInCommittedRound {
			continue
		}
		if scenarios[i].creatorParamsDelta1 != nil && scenarios[i].creatorParamsDelta1.deleted {
			continue
		}
		scenarios[i].want.creator = creatorAddr
	}

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.MaxAcctLookback = 0
	au, _ := newAcctUpdates(t, ml, conf)
	knownCreatables := make(map[basics.CreatableIndex]bool)

	// Precompute account totals for the committed round so the base fixture matches the scenario set.
	creatorTotalAssets := uint64(0)
	creatorTotalParams := uint64(0)
	holderTotalAssets := uint64(0)
	for _, scenario := range scenarios {
		if scenario.creatorParams != nil {
			creatorTotalAssets++
			creatorTotalParams++
		}
		if group == lookupHolderGroup && scenario.initHolding != nil {
			holderTotalAssets++
		}
	}

	// Round 1 commits the baseline resources for this group:
	// creator resources always exist on creatorAddr, while holder-group opt-ins
	// also get a separate holding row on holderAddr.
	{
		var updates ledgercore.AccountDeltas
		updates.Upsert(creatorAddr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{
				MicroAlgos:       basics.MicroAlgos{Raw: 1_000_000},
				TotalAssetParams: creatorTotalParams,
				TotalAssets:      creatorTotalAssets,
			},
		})
		if group == lookupHolderGroup {
			updates.Upsert(holderAddr, ledgercore.AccountData{
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:  basics.MicroAlgos{Raw: 1_000_000},
					TotalAssets: holderTotalAssets,
				},
			})
		}

		for _, scenario := range scenarios {
			if scenario.creatorParams == nil {
				continue
			}
			// In holder-group scenarios the creator still needs a real creator-side holding,
			// so synthesize one from the total supply instead of reusing the holder's opt-in.
			creatorHolding := scenario.initHolding
			if group != lookupCreatorGroup {
				creatorHolding = lookupTestAssetHolding(scenario.creatorParams.Total)
			}
			updates.UpsertAssetResource(creatorAddr, scenario.id,
				ledgercore.AssetParamsDelta{Params: scenario.creatorParams},
				ledgercore.AssetHoldingDelta{Holding: creatorHolding},
			)
			if group == lookupHolderGroup && scenario.initHolding != nil {
				updates.UpsertAssetResource(holderAddr, scenario.id,
					ledgercore.AssetParamsDelta{},
					ledgercore.AssetHoldingDelta{Holding: scenario.initHolding},
				)
			}
		}

		base := accts[0]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, 1, au, base, opts, nil)
		auCommitSync(t, 1, au, ml)

		for _, scenario := range scenarios {
			if scenario.creatorParams != nil {
				knownCreatables[basics.CreatableIndex(scenario.id)] = true
			}
		}
	}

	// Optionally commit a destruction round so holder-group lookups can exercise
	// "holding survives after creator asset was destroyed" behavior from the DB.
	destroyedCount := uint64(0)
	for _, scenario := range scenarios {
		if scenario.destroyInCommittedRound {
			destroyedCount++
		}
	}

	for i := basics.Round(2); i <= basics.Round(conf.MaxAcctLookback+2); i++ {
		var updates ledgercore.AccountDeltas
		if i == 2 && destroyedCount > 0 {
			updates.Upsert(creatorAddr, ledgercore.AccountData{
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1_000_000},
					TotalAssetParams: creatorTotalParams - destroyedCount,
					TotalAssets:      creatorTotalAssets - destroyedCount,
				},
			})
			for _, scenario := range scenarios {
				if !scenario.destroyInCommittedRound {
					continue
				}
				updates.UpsertAssetResource(creatorAddr, scenario.id,
					ledgercore.AssetParamsDelta{Deleted: true},
					ledgercore.AssetHoldingDelta{Deleted: true},
				)
			}
		}

		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, i, au, base, opts, nil)
		auCommitSync(t, i, au, ml)
	}

	// Delta round 1 applies the scenario-specific uncommitted changes:
	// creator-group combines params and holding on creatorAddr, while holder-group
	// splits creator-side params from holder-side holding deltas.
	deltaRound1 := basics.Round(conf.MaxAcctLookback + 3)
	{
		var updates ledgercore.AccountDeltas
		for _, scenario := range scenarios {
			switch group {
			case lookupCreatorGroup:
				if scenario.creatorParamsDelta1 != nil || scenario.holdingDelta1 != nil {
					updates.UpsertAssetResource(creatorAddr, scenario.id,
						lookupAssetParamsDelta(scenario.creatorParamsDelta1),
						lookupAssetHoldingDelta(scenario.holdingDelta1),
					)
				}
			case lookupHolderGroup:
				if scenario.creatorParamsDelta1 != nil {
					updates.UpsertAssetResource(creatorAddr, scenario.id,
						lookupAssetParamsDelta(scenario.creatorParamsDelta1),
						ledgercore.AssetHoldingDelta{},
					)
				}
				if scenario.holdingDelta1 != nil {
					updates.UpsertAssetResource(holderAddr, scenario.id,
						ledgercore.AssetParamsDelta{},
						lookupAssetHoldingDelta(scenario.holdingDelta1),
					)
				}
			}
		}

		base := accts[deltaRound1-1]
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, deltaRound1, au, base, opts, nil)
	}

	// Delta round 2 is only emitted for scenarios that need to prove
	// "later uncommitted delta overrides earlier uncommitted delta".
	expectedRound := deltaRound1
	hasDelta2 := false
	for _, scenario := range scenarios {
		if scenario.holdingDelta2 != nil {
			hasDelta2 = true
			break
		}
	}
	if hasDelta2 {
		expectedRound = deltaRound1 + 1
		var updates ledgercore.AccountDeltas
		for _, scenario := range scenarios {
			if scenario.holdingDelta2 == nil {
				continue
			}
			updates.UpsertAssetResource(queryAddr, scenario.id,
				ledgercore.AssetParamsDelta{},
				lookupAssetHoldingDelta(scenario.holdingDelta2),
			)
		}

		base := accts[deltaRound1-1]
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, expectedRound, au, base, opts, nil)
	}

	// Finally query the address under test and compare the merged rows against the scenario table.
	resources, rnd, err := au.LookupAssetResources(queryAddr, 0, 100)
	require.NoError(t, err)
	require.Equal(t, expectedRound, rnd)

	expectedCount := 0
	for _, scenario := range scenarios {
		if !scenario.want.excluded {
			expectedCount++
		}
	}
	require.Len(t, resources, expectedCount)

	resultMap := make(map[basics.AssetIndex]ledgercore.AssetResourceWithIDs, len(resources))
	for _, resource := range resources {
		resultMap[resource.AssetID] = resource
	}
	for _, scenario := range scenarios {
		assertLookupAssetScenario(t, scenario, resultMap)
	}
}

// runLookupAppScenarioGroupTest builds one isolated ledger for an app address group,
// commits the base fixture, applies up to two uncommitted delta rounds, and asserts both
// the queried account's view and, for non-creator groups, the creator's view of the same apps.
func runLookupAppScenarioGroupTest(t *testing.T, group lookupResourceGroup, scenarios []lookupAppScenario) {
	t.Helper()

	// Give every scenario a stable synthetic app ID inside this isolated ledger.
	for i := range scenarios {
		validateLookupAppScenario(t, scenarios[i])
		scenarios[i].id = basics.AppIndex(2000 + i)
	}

	testProtocolVersion := protocol.ConsensusCurrentVersion
	protoParams := config.Consensus[testProtocolVersion]
	accts := setupAccts(5)
	creatorAddr, holderAddr, deltaOnlyAddr := selectLookupTestAddresses(accts[0])
	queryAddr := lookupGroupQueryAddr(group, creatorAddr, holderAddr, deltaOnlyAddr)

	// Fill the expected creator field for any scenario where params still exist at lookup time.
	fillExpectedCreator := func(expected *lookupAppExpected, paramsDeleted bool) {
		if expected == nil || expected.excluded || paramsDeleted {
			return
		}
		expected.creator = creatorAddr
	}
	for i := range scenarios {
		paramsDeleted := scenarios[i].creatorParamsDelta1 != nil && scenarios[i].creatorParamsDelta1.deleted
		fillExpectedCreator(&scenarios[i].wantWithParams, paramsDeleted)
		fillExpectedCreator(&scenarios[i].wantNoParams, paramsDeleted)
		fillExpectedCreator(scenarios[i].wantCreatorWithParams, paramsDeleted)
		fillExpectedCreator(scenarios[i].wantCreatorNoParams, paramsDeleted)
	}

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.MaxAcctLookback = 0
	au, _ := newAcctUpdates(t, ml, conf)
	knownCreatables := make(map[basics.CreatableIndex]bool)

	// Precompute account totals for the committed round so the base fixture matches the scenario set.
	creatorTotalParams := uint64(0)
	creatorTotalLocals := uint64(0)
	holderTotalLocals := uint64(0)
	for _, scenario := range scenarios {
		if scenario.creatorParams != nil {
			creatorTotalParams++
		}
		if group == lookupCreatorGroup && scenario.initLocalState != nil {
			creatorTotalLocals++
		}
		if group == lookupHolderGroup && scenario.initLocalState != nil {
			holderTotalLocals++
		}
	}

	// Round 1 commits the baseline resources for this group:
	// creator resources always exist on creatorAddr, while holder-group opt-ins
	// also get a separate local-state row on holderAddr.
	{
		var updates ledgercore.AccountDeltas
		updates.Upsert(creatorAddr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{
				MicroAlgos:          basics.MicroAlgos{Raw: 1_000_000},
				TotalAppParams:      creatorTotalParams,
				TotalAppLocalStates: creatorTotalLocals,
			},
		})
		if group == lookupHolderGroup {
			updates.Upsert(holderAddr, ledgercore.AccountData{
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1_000_000},
					TotalAppLocalStates: holderTotalLocals,
				},
			})
		}

		for _, scenario := range scenarios {
			if scenario.creatorParams != nil {
				// In non-creator groups the creator still owns the app params row,
				// while the queried account's local state lives on a separate address.
				var creatorLocalState *basics.AppLocalState
				if group == lookupCreatorGroup {
					creatorLocalState = scenario.initLocalState
				}
				updates.UpsertAppResource(creatorAddr, scenario.id,
					ledgercore.AppParamsDelta{Params: scenario.creatorParams},
					ledgercore.AppLocalStateDelta{LocalState: creatorLocalState},
				)
			}
			if group == lookupHolderGroup && scenario.initLocalState != nil {
				updates.UpsertAppResource(holderAddr, scenario.id,
					ledgercore.AppParamsDelta{},
					ledgercore.AppLocalStateDelta{LocalState: scenario.initLocalState},
				)
			}
		}

		base := accts[0]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, 1, au, base, opts, nil)
		auCommitSync(t, 1, au, ml)

		for _, scenario := range scenarios {
			if scenario.creatorParams != nil {
				knownCreatables[basics.CreatableIndex(scenario.id)] = true
			}
		}
	}

	// Advance committed rounds so later lookups have to merge DB state with uncommitted deltas.
	for i := basics.Round(2); i <= basics.Round(conf.MaxAcctLookback+2); i++ {
		var updates ledgercore.AccountDeltas
		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, i, au, base, opts, nil)
		auCommitSync(t, i, au, ml)
	}

	// Delta round 1 applies the scenario-specific uncommitted changes:
	// creator-group combines params and locals on creatorAddr, while non-creator
	// groups split creator-side params from queried-account local-state deltas.
	deltaRound1 := basics.Round(conf.MaxAcctLookback + 3)
	{
		var updates ledgercore.AccountDeltas
		for _, scenario := range scenarios {
			switch group {
			case lookupCreatorGroup:
				if scenario.creatorParamsDelta1 != nil || scenario.localsDelta1 != nil {
					updates.UpsertAppResource(creatorAddr, scenario.id,
						lookupAppParamsDelta(scenario.creatorParamsDelta1),
						lookupAppLocalsDelta(scenario.localsDelta1),
					)
				}
			case lookupHolderGroup, lookupDeltaOnlyGroup:
				if scenario.creatorParamsDelta1 != nil {
					updates.UpsertAppResource(creatorAddr, scenario.id,
						lookupAppParamsDelta(scenario.creatorParamsDelta1),
						ledgercore.AppLocalStateDelta{},
					)
				}
				if scenario.localsDelta1 != nil {
					updates.UpsertAppResource(queryAddr, scenario.id,
						ledgercore.AppParamsDelta{},
						lookupAppLocalsDelta(scenario.localsDelta1),
					)
				}
			}
		}

		base := accts[deltaRound1-1]
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, deltaRound1, au, base, opts, nil)
	}

	// Delta round 2 is only emitted for scenarios that need to prove
	// "later uncommitted delta overrides earlier uncommitted delta".
	expectedRound := deltaRound1
	hasDelta2 := false
	for _, scenario := range scenarios {
		if scenario.localsDelta2 != nil {
			hasDelta2 = true
			break
		}
	}
	if hasDelta2 {
		expectedRound = deltaRound1 + 1
		var updates ledgercore.AccountDeltas
		for _, scenario := range scenarios {
			if scenario.localsDelta2 == nil {
				continue
			}
			updates.UpsertAppResource(queryAddr, scenario.id,
				ledgercore.AppParamsDelta{},
				lookupAppLocalsDelta(scenario.localsDelta2),
			)
		}

		base := accts[deltaRound1-1]
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, expectedRound, au, base, opts, nil)
	}

	// First assert the queried account's view for both includeParams modes.
	for _, includeParams := range []bool{true, false} {
		resources, rnd, err := au.LookupApplicationResources(queryAddr, 0, 100, includeParams)
		require.NoError(t, err)
		require.Equal(t, expectedRound, rnd)

		expectedCount := 0
		for _, scenario := range scenarios {
			expected := scenario.wantNoParams
			if includeParams {
				expected = scenario.wantWithParams
			}
			if !expected.excluded {
				expectedCount++
			}
		}
		require.Len(t, resources, expectedCount, "includeParams=%v", includeParams)

		resultMap := make(map[basics.AppIndex]ledgercore.AppResourceWithIDs, len(resources))
		for _, resource := range resources {
			resultMap[resource.AppID] = resource
		}
		for _, scenario := range scenarios {
			assertLookupAppScenario(t, scenario, includeParams, resultMap)
		}
	}

	if group == lookupCreatorGroup {
		return
	}

	// Then assert the creator's view of those same scenarios, which is where
	// params-only rows must survive holder close-out cases that should disappear
	// for the non-creator query address.
	for _, includeParams := range []bool{true, false} {
		resources, rnd, err := au.LookupApplicationResources(creatorAddr, 0, 100, includeParams)
		require.NoError(t, err)
		require.Equal(t, expectedRound, rnd)

		expectedCount := 0
		for _, scenario := range scenarios {
			expected := scenario.wantCreatorNoParams
			if includeParams {
				expected = scenario.wantCreatorWithParams
			}
			if expected != nil && !expected.excluded {
				expectedCount++
			}
		}
		require.Len(t, resources, expectedCount, "creatorView includeParams=%v", includeParams)

		resultMap := make(map[basics.AppIndex]ledgercore.AppResourceWithIDs, len(resources))
		for _, resource := range resources {
			resultMap[resource.AppID] = resource
		}
		for _, scenario := range scenarios {
			assertLookupAppCreatorView(t, scenario, includeParams, resultMap)
		}
	}
}

// TestLookupAssetResourcesWithDeltas verifies that lookupAssetResources properly merges
// in-memory deltas with database results to return current-round data.
// It commits resources to DB, then adds uncommitted delta modifications across two rounds,
// and checks the merged view covers: new creations, holding deletions, holding modifications,
// params-only modifications, params deletions with holding retained, and multi-round
// backwards walking that picks the most recent delta.
func TestLookupAssetResourcesWithDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("creator-group", func(t *testing.T) {
		runLookupAssetScenarioGroupTest(t, lookupCreatorGroup, []lookupAssetScenario{
			// Creator updates the same holding twice; the most recent delta should win.
			{
				name:          "holding-modified-twice",
				group:         lookupCreatorGroup,
				creatorParams: lookupTestAssetParams(1_000_000, "A1000"),
				initHolding:   lookupTestAssetHolding(100),
				holdingDelta1: lookupTestAssetHoldingDelta(lookupTestAssetHolding(9999)),
				holdingDelta2: lookupTestAssetHoldingDelta(lookupTestAssetHolding(5555)),
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(5555),
					params:  lookupTestAssetParams(1_000_000, "A1000"),
				},
			},
			// No deltas touch this asset, so the result should read straight through from DB.
			{
				name:          "unchanged",
				group:         lookupCreatorGroup,
				creatorParams: lookupTestAssetParams(1_001_000, "A1001"),
				initHolding:   lookupTestAssetHolding(100100),
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(100100),
					params:  lookupTestAssetParams(1_001_000, "A1001"),
				},
			},
			// Params change without touching the holding; the DB holding should be preserved.
			{
				name:                "params-modified",
				group:               lookupCreatorGroup,
				creatorParams:       lookupTestAssetParams(1_003_000, "A"),
				initHolding:         lookupTestAssetHolding(100300),
				creatorParamsDelta1: lookupTestAssetParamsDelta(lookupTestAssetParams(7777, "Anew")),
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(100300),
					params:  lookupTestAssetParams(7777, "Anew"),
				},
			},
			// Deleting both params and holding should remove the asset entirely.
			{
				name:                "both-deleted",
				group:               lookupCreatorGroup,
				creatorParams:       lookupTestAssetParams(1_005_000, "A1005"),
				initHolding:         lookupTestAssetHolding(100500),
				creatorParamsDelta1: lookupTestDeletedAssetParamsDelta(),
				holdingDelta1:       lookupTestDeletedAssetHoldingDelta(),
				want: lookupAssetExpected{
					excluded: true,
				},
			},
			// Delta-only creator creation should appear even though nothing exists in DB yet.
			{
				name:                "new-creation",
				group:               lookupCreatorGroup,
				creatorParamsDelta1: lookupTestAssetParamsDelta(lookupTestAssetParams(6000, "A6000")),
				holdingDelta1:       lookupTestAssetHoldingDelta(lookupTestAssetHolding(6000)),
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(6000),
					params:  lookupTestAssetParams(6000, "A6000"),
				},
			},
		})
	})

	t.Run("holder-group", func(t *testing.T) {
		runLookupAssetScenarioGroupTest(t, lookupHolderGroup, []lookupAssetScenario{
			// Holder keeps the same opt-in while the creator updates params in deltas.
			{
				name:                "cross-params-modified",
				group:               lookupHolderGroup,
				creatorParams:       lookupTestAssetParams(1_002_000, "A1002"),
				initHolding:         lookupTestAssetHolding(50),
				creatorParamsDelta1: lookupTestAssetParamsDelta(lookupTestAssetParams(7777, "Anew")),
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(50),
					params:  lookupTestAssetParams(7777, "Anew"),
				},
			},
			// Holder survives a creator-side params deletion and should see only the holding.
			{
				name:                "cross-params-deleted",
				group:               lookupHolderGroup,
				creatorParams:       lookupTestAssetParams(1_004_000, "A1004"),
				initHolding:         lookupTestAssetHolding(50),
				creatorParamsDelta1: lookupTestDeletedAssetParamsDelta(),
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(50),
					creator: basics.Address{},
				},
			},
			// Cross-address DB merge should show creator params beside the holder's opt-in.
			{
				name:          "cross-unchanged",
				group:         lookupHolderGroup,
				creatorParams: lookupTestAssetParams(1_006_000, "A1006"),
				initHolding:   lookupTestAssetHolding(50),
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(50),
					params:  lookupTestAssetParams(1_006_000, "A1006"),
				},
			},
			// A non-creator close-out should remove the asset entirely from the holder's results.
			{
				name:          "non-creator-close-out",
				group:         lookupHolderGroup,
				creatorParams: lookupTestAssetParams(1_007_000, "A1007"),
				initHolding:   lookupTestAssetHolding(50),
				holdingDelta1: lookupTestDeletedAssetHoldingDelta(),
				want: lookupAssetExpected{
					excluded: true,
				},
			},
			// After committed destruction, a surviving zero-balance holder should still be returned.
			{
				name:                    "destroyed-surviving",
				group:                   lookupHolderGroup,
				creatorParams:           lookupTestAssetParams(7000, "A7000"),
				initHolding:             lookupTestAssetHolding(0),
				destroyInCommittedRound: true,
				want: lookupAssetExpected{
					holding: lookupTestAssetHolding(0),
					creator: basics.Address{},
				},
			},
		})
	})
}

// TestLookupApplicationResourcesWithDeltas verifies that lookupApplicationResources properly
// merges in-memory deltas with database results to return current-round data.
// It covers: new creation, local state deletion, local state modification, params-only
// modification, params deletion with local state retained, multi-round backwards walking,
// and the includeParams flag.
func TestLookupApplicationResourcesWithDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("creator-group", func(t *testing.T) {
		runLookupAppScenarioGroupTest(t, lookupCreatorGroup, []lookupAppScenario{
			// Creator local state changes twice; the later delta should override the earlier one.
			{
				name:           "locals-modified-twice",
				group:          lookupCreatorGroup,
				creatorParams:  lookupTestAppParams(0x01, 0x11),
				initLocalState: lookupTestAppLocalState(0),
				localsDelta1:   lookupTestAppLocalsDelta(lookupTestAppLocalState(99)),
				localsDelta2:   lookupTestAppLocalsDelta(lookupTestAppLocalState(42)),
				wantWithParams: lookupAppExpected{
					localState: lookupTestAppLocalState(42),
					params:     lookupTestAppParams(0x01, 0x11),
				},
				wantNoParams: lookupAppExpected{
					localState: lookupTestAppLocalState(42),
				},
			},
			// Creator deletes local state but remains the app creator, so params-only should survive.
			{
				name:           "creator-locals-deleted",
				group:          lookupCreatorGroup,
				creatorParams:  lookupTestAppParams(0x01, 0x11),
				initLocalState: lookupTestAppLocalState(1),
				localsDelta1:   lookupTestDeletedAppLocalsDelta(),
				wantWithParams: lookupAppExpected{
					params: lookupTestAppParams(0x01, 0x11),
				},
				wantNoParams: lookupAppExpected{},
			},
			// Plain DB read-through for a creator-owned app with no deltas.
			{
				name:           "unchanged",
				group:          lookupCreatorGroup,
				creatorParams:  lookupTestAppParams(0x01, 0x11),
				initLocalState: lookupTestAppLocalState(2),
				wantWithParams: lookupAppExpected{
					localState: lookupTestAppLocalState(2),
					params:     lookupTestAppParams(0x01, 0x11),
				},
				wantNoParams: lookupAppExpected{
					localState: lookupTestAppLocalState(2),
				},
			},
			// Params mutate while local state stays committed.
			{
				name:                "params-modified",
				group:               lookupCreatorGroup,
				creatorParams:       lookupTestAppParams(0x01, 0x11),
				initLocalState:      lookupTestAppLocalState(3),
				creatorParamsDelta1: lookupTestAppParamsDelta(lookupTestAppParams(0x02, 0x12)),
				wantWithParams: lookupAppExpected{
					localState: lookupTestAppLocalState(3),
					params:     lookupTestAppParams(0x02, 0x12),
				},
				wantNoParams: lookupAppExpected{
					localState: lookupTestAppLocalState(3),
				},
			},
			// Params are deleted but creator local state remains, so only locals should survive.
			{
				name:                "params-deleted",
				group:               lookupCreatorGroup,
				creatorParams:       lookupTestAppParams(0x01, 0x11),
				initLocalState:      lookupTestAppLocalState(4),
				creatorParamsDelta1: lookupTestDeletedAppParamsDelta(),
				wantWithParams: lookupAppExpected{
					localState: lookupTestAppLocalState(4),
				},
				wantNoParams: lookupAppExpected{
					localState: lookupTestAppLocalState(4),
				},
			},
			// Deleting both params and locals should fully remove the app from results.
			{
				name:                "both-deleted",
				group:               lookupCreatorGroup,
				creatorParams:       lookupTestAppParams(0x01, 0x11),
				initLocalState:      lookupTestAppLocalState(5),
				creatorParamsDelta1: lookupTestDeletedAppParamsDelta(),
				localsDelta1:        lookupTestDeletedAppLocalsDelta(),
				wantWithParams: lookupAppExpected{
					excluded: true,
				},
				wantNoParams: lookupAppExpected{
					excluded: true,
				},
			},
			// Delta-only creator creation should appear in both includeParams modes.
			{
				name:                "new-creation",
				group:               lookupCreatorGroup,
				creatorParamsDelta1: lookupTestAppParamsDelta(lookupTestAppParams(0x01, 0x11)),
				localsDelta1:        lookupTestAppLocalsDelta(lookupTestAppLocalState(60)),
				wantWithParams: lookupAppExpected{
					localState: lookupTestAppLocalState(60),
					params:     lookupTestAppParams(0x01, 0x11),
				},
				wantNoParams: lookupAppExpected{
					localState: lookupTestAppLocalState(60),
				},
			},
			// Creator-only app with no opt-in covers the params-only creator path.
			{
				name:          "creator-no-optin",
				group:         lookupCreatorGroup,
				creatorParams: lookupTestAppParams(0x01, 0x11),
				wantWithParams: lookupAppExpected{
					params: lookupTestAppParams(0x01, 0x11),
				},
				wantNoParams: lookupAppExpected{},
			},
		})
	})

	t.Run("holder-group", func(t *testing.T) {
		runLookupAppScenarioGroupTest(t, lookupHolderGroup, []lookupAppScenario{
			// Holder closes out in deltas; holder should lose the app while creator still sees it.
			{
				name:           "close-out",
				group:          lookupHolderGroup,
				creatorParams:  lookupTestAppParams(0x01, 0x11),
				initLocalState: lookupTestAppLocalState(99),
				localsDelta1:   lookupTestDeletedAppLocalsDelta(),
				wantWithParams: lookupAppExpected{
					excluded: true,
				},
				wantNoParams: lookupAppExpected{
					excluded: true,
				},
				wantCreatorWithParams: &lookupAppExpected{
					params: lookupTestAppParams(0x01, 0x11),
				},
				wantCreatorNoParams: &lookupAppExpected{},
			},
			// Holder keeps local state while the creator updates params in deltas.
			{
				name:                "cross-params-modified",
				group:               lookupHolderGroup,
				creatorParams:       lookupTestAppParams(0x01, 0x11),
				initLocalState:      lookupTestAppLocalState(99),
				creatorParamsDelta1: lookupTestAppParamsDelta(lookupTestAppParams(0x02, 0x12)),
				wantWithParams: lookupAppExpected{
					localState: lookupTestAppLocalState(99),
					params:     lookupTestAppParams(0x02, 0x12),
				},
				wantNoParams: lookupAppExpected{
					localState: lookupTestAppLocalState(99),
				},
				wantCreatorWithParams: &lookupAppExpected{
					params: lookupTestAppParams(0x02, 0x12),
				},
				wantCreatorNoParams: &lookupAppExpected{},
			},
			// Creator deletes params; holder still has locals, but creator should no longer see the app.
			{
				name:                "cross-params-deleted",
				group:               lookupHolderGroup,
				creatorParams:       lookupTestAppParams(0x01, 0x11),
				initLocalState:      lookupTestAppLocalState(99),
				creatorParamsDelta1: lookupTestDeletedAppParamsDelta(),
				wantWithParams: lookupAppExpected{
					localState: lookupTestAppLocalState(99),
				},
				wantNoParams: lookupAppExpected{
					localState: lookupTestAppLocalState(99),
				},
				wantCreatorWithParams: &lookupAppExpected{
					excluded: true,
				},
				wantCreatorNoParams: &lookupAppExpected{
					excluded: true,
				},
			},
		})
	})

	t.Run("delta-only-group", func(t *testing.T) {
		runLookupAppScenarioGroupTest(t, lookupDeltaOnlyGroup, []lookupAppScenario{
			// Delta-only opt-in followed by delta-only close-out should disappear for the holder but not the creator.
			{
				name:          "delta-only-close-out",
				group:         lookupDeltaOnlyGroup,
				creatorParams: lookupTestAppParams(0x01, 0x11),
				localsDelta1:  lookupTestAppLocalsDelta(lookupTestAppLocalState(77)),
				localsDelta2:  lookupTestDeletedAppLocalsDelta(),
				wantWithParams: lookupAppExpected{
					excluded: true,
				},
				wantNoParams: lookupAppExpected{
					excluded: true,
				},
				wantCreatorWithParams: &lookupAppExpected{
					params: lookupTestAppParams(0x01, 0x11),
				},
				wantCreatorNoParams: &lookupAppExpected{},
			},
		})
	})
}

// TestLookupAppResourcesParamsOnlyDeletion exercises the scenario where an app
// creator has params but no local state in the DB (never opted in) and a delta
// deletes those params. Two bugs interact here:
//
//  1. The else fallback in the DB merge calls GetAppLocalState() without first
//     checking pd.Data.IsHolding(), producing a phantom zero-value AppLocalState
//     on a row that has no local state. This causes the deleted-params row to
//     survive the (AppLocalState != nil || AppParams != nil) filter when it
//     should be excluded.
//
//  2. numDeltaDeleted only counts State.Deleted. A params-only deletion
//     (Params.Deleted=true, State.Deleted=false) is not counted, so the DB
//     over-request is too small and the result page is short once the phantom
//     local state issue is also fixed.
//
// Setup: 4 apps (3000-3003) committed to DB. App 3000 has params only (no
// local state). Apps 3001-3003 have both params and local state.
// Delta: delete params for app 3000.
// Query with limit=3: should return 3001, 3002, 3003.
func TestLookupAppResourcesParamsOnlyDeletion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProtocolVersion := protocol.ConsensusCurrentVersion
	protoParams := config.Consensus[testProtocolVersion]

	accts := setupAccts(5)

	var creatorAddr basics.Address
	for addr := range accts[0] {
		if addr != testSinkAddr && addr != testPoolAddr {
			creatorAddr = addr
			break
		}
	}

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.MaxAcctLookback = 0
	au, _ := newAcctUpdates(t, ml, conf)

	knownCreatables := make(map[basics.CreatableIndex]bool)

	// Round 1: create apps 3000-3003.
	//   3000: params only, no local state (creator who never opted in)
	//   3001-3003: both params and local state
	{
		var updates ledgercore.AccountDeltas
		updates.Upsert(creatorAddr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{
				MicroAlgos:          basics.MicroAlgos{Raw: 1_000_000},
				TotalAppParams:      4,
				TotalAppLocalStates: 3,
			},
		})
		// 3000: params only
		updates.UpsertAppResource(creatorAddr, basics.AppIndex(3000),
			ledgercore.AppParamsDelta{
				Params: &basics.AppParams{
					ApprovalProgram: []byte{0x06, 0x81, 0x01},
				},
			},
			ledgercore.AppLocalStateDelta{})
		// 3001-3003: params + local state
		for appIdx := uint64(3001); appIdx <= 3003; appIdx++ {
			updates.UpsertAppResource(creatorAddr, basics.AppIndex(appIdx),
				ledgercore.AppParamsDelta{
					Params: &basics.AppParams{
						ApprovalProgram: []byte{0x06, 0x81, 0x01},
					},
				},
				ledgercore.AppLocalStateDelta{
					LocalState: &basics.AppLocalState{
						Schema: basics.StateSchema{NumUint: appIdx - 3000},
					},
				})
		}

		base := accts[0]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, 1, au, base, opts, nil)
		auCommitSync(t, 1, au, ml)

		for appIdx := uint64(3000); appIdx <= 3003; appIdx++ {
			knownCreatables[basics.CreatableIndex(appIdx)] = true
		}
	}

	// Flush past MaxAcctLookback
	for i := basics.Round(2); i <= basics.Round(conf.MaxAcctLookback+2); i++ {
		var updates ledgercore.AccountDeltas
		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, i, au, base, opts, nil)
		auCommitSync(t, i, au, ml)
	}

	// Delta (uncommitted): delete params for app 3000 (which has no local state).
	// State.Deleted is false because there was no local state to delete.
	deltaRound := basics.Round(conf.MaxAcctLookback + 3)
	{
		var updates ledgercore.AccountDeltas
		updates.UpsertAppResource(creatorAddr, basics.AppIndex(3000),
			ledgercore.AppParamsDelta{Deleted: true},
			ledgercore.AppLocalStateDelta{})

		base := accts[deltaRound-1]
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, deltaRound, au, base, opts, nil)
	}

	// Query with limit=3. After filtering out 3000 (both params and local state
	// nil), we should still get 3 results: 3001, 3002, 3003.
	resources, rnd, err := au.LookupApplicationResources(creatorAddr, 0, 3, true)
	require.NoError(t, err)
	require.Equal(t, deltaRound, rnd)
	require.Len(t, resources, 3, "params-only deletion should not cause a short page")
	require.Equal(t, basics.AppIndex(3001), resources[0].AppID)
	require.Equal(t, basics.AppIndex(3002), resources[1].AppID)
	require.Equal(t, basics.AppIndex(3003), resources[2].AppID)
}

// TestLookupAssetResourcesEmptyPageDoesNotError verifies that looking up an empty page
// (no resources for the account) returns an empty result and current round, not an error.
func TestLookupAssetResourcesEmptyPageDoesNotError(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProtocolVersion := protocol.ConsensusCurrentVersion
	protoParams := config.Consensus[testProtocolVersion]

	accts := setupAccts(2)
	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, accts)
	defer ml.Close()

	// Step 1: use default lookback config (do not override MaxAcctLookback).
	// We then advance enough rounds so persisted DB round moves forward.
	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)

	knownCreatables := make(map[basics.CreatableIndex]bool)
	latestRound := basics.Round(conf.MaxAcctLookback + 2)

	// Step 2: commit empty rounds to push DB round forward while keeping
	// the target address absent from all in-memory and persisted resources.
	for i := basics.Round(1); i <= latestRound; i++ {
		var updates ledgercore.AccountDeltas
		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, i, au, base, opts, nil)
		auCommitSync(t, i, au, ml)
	}

	// Step 3: choose an address that definitely does not exist in the fixture accounts.
	var missingAddr basics.Address
	missingAddr[0] = 0xA5
	for {
		if _, ok := accts[0][missingAddr]; !ok {
			break
		}
		missingAddr[0]++
	}

	// Step 4: lookup should produce an empty page at current round, not an error.
	resources, rnd, err := au.LookupAssetResources(missingAddr, 0, 10)
	require.NoError(t, err)
	require.Equal(t, latestRound, rnd)
	require.Len(t, resources, 0)
}

// TestLookupApplicationResourcesEmptyPageDoesNotError verifies that looking up an empty page
// (no resources for the account) returns an empty result and current round, not an error.
func TestLookupApplicationResourcesEmptyPageDoesNotError(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProtocolVersion := protocol.ConsensusCurrentVersion
	protoParams := config.Consensus[testProtocolVersion]

	accts := setupAccts(2)
	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, accts)
	defer ml.Close()

	// Step 1: use default lookback config (do not override MaxAcctLookback).
	// We then advance enough rounds so persisted DB round moves forward.
	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)

	knownCreatables := make(map[basics.CreatableIndex]bool)
	latestRound := basics.Round(conf.MaxAcctLookback + 2)

	// Step 2: commit empty rounds to push DB round forward while keeping
	// the target address absent from all in-memory and persisted resources.
	for i := basics.Round(1); i <= latestRound; i++ {
		var updates ledgercore.AccountDeltas
		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, i, au, base, opts, nil)
		auCommitSync(t, i, au, ml)
	}

	// Step 3: choose an address that definitely does not exist in the fixture accounts.
	var missingAddr basics.Address
	missingAddr[0] = 0x5A
	for {
		if _, ok := accts[0][missingAddr]; !ok {
			break
		}
		missingAddr[0]++
	}

	// Step 4: lookup should produce an empty page at current round, not an error.
	resources, rnd, err := au.LookupApplicationResources(missingAddr, 0, 10, true)
	require.NoError(t, err)
	require.Equal(t, latestRound, rnd)
	require.Len(t, resources, 0)
}
