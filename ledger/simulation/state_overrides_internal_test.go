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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestAppOverrideCoversAppParams ensures that every field of basics.AppParams can be overridden,
// so that new app params are not forgotten.
func TestAppOverrideCoversAppParams(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	overrideType := reflect.TypeFor[AppOverride]()
	var check func(reflect.Type)
	check = func(typ reflect.Type) {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Name == "_struct" {
				continue
			}
			if field.Anonymous {
				check(field.Type)
				continue
			}
			_, ok := overrideType.FieldByName(field.Name)
			require.True(t, ok, "AppOverride has no field for AppParams.%s", field.Name)
		}
	}
	check(reflect.TypeFor[basics.AppParams]())
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

func TestAppOverrideProtocolSupport(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sponsor := basics.Address{1}
	boxes := AppOverride{Boxes: map[string][]byte{"b": nil}}

	testCases := []struct {
		name          string
		version       protocol.ConsensusVersion
		params        basics.AppParams
		override      AppOverride
		expectedError string
	}{
		{name: "size sponsor", version: protocol.ConsensusV41, params: basics.AppParams{SizeSponsor: sponsor}, expectedError: "size sponsor is not supported"},
		{name: "foreign box reads", version: protocol.ConsensusV41, params: basics.AppParams{ForeignBoxReads: true}, expectedError: "AppForeignBoxReads is not supported"},
		{name: "family box access", version: protocol.ConsensusV41, params: basics.AppParams{FamilyBoxAccess: true}, expectedError: "AppFamilyBoxAccess is not supported"},
		{name: "boxes", version: protocol.ConsensusV35, override: boxes, expectedError: "boxes are not supported"},
		{name: "all supported", version: protocol.ConsensusV42, params: basics.AppParams{SizeSponsor: sponsor, ForeignBoxReads: true, FamilyBoxAccess: true}, override: boxes},
		// Default values are allowed in any protocol
		{name: "defaults", version: protocol.ConsensusV35},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProtocolSupport(tc.version, 1, tc.params, tc.override)
			if tc.expectedError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorAs(t, err, &InvalidRequestError{})
			require.ErrorContains(t, err, tc.expectedError)
		})
	}
}
