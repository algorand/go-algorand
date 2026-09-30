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
	"bytes"
	"cmp"
	"fmt"
	"maps"
	"math"
	"slices"

	"github.com/algorand/avm-abi/apps"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// StateOverrides describes modifications to ledger state that are applied before any evaluation
// takes place. The overrides are only visible to the simulation and are never persisted.
type StateOverrides struct {
	Accounts map[basics.Address]AccountOverride
	Apps     map[basics.AppIndex]AppOverride
}

// AccountOverride describes modifications to a single account's state. Nil fields are left unchanged.
type AccountOverride struct {
	// Balance, if set, replaces the account's balance. Pending rewards are forfeited, so the
	// account's balance at the start of simulation is exactly this value.
	Balance *basics.MicroAlgos
}

// AppOverride describes modifications to a single application's state. If the application does
// not exist, it is created. Nil fields are left unchanged.
//
// A new application's ID must not be one that could be assigned to a creatable made during
// simulation, i.e. it must be at most the current txn counter or well above it. App IDs may not
// exceed math.MaxInt64.
//
// Minimum balance bookkeeping (created apps, global schema, extra pages, boxes) is updated on the
// relevant accounts, but their balances are not, so an AccountOverride may be needed to keep them
// above their minimum balance.
type AppOverride struct {
	// Creator is required when creating an application. For an existing application, it must be
	// empty or match the existing creator.
	Creator basics.Address

	// ApprovalProgram and ClearStateProgram are required when creating an application.
	ApprovalProgram   []byte
	ClearStateProgram []byte
	GlobalStateSchema *basics.StateSchema
	LocalStateSchema  *basics.StateSchema
	ExtraProgramPages *uint32

	// GlobalState entries are set, replacing any existing value for the same key. Other existing
	// keys are left unchanged.
	GlobalState basics.TealKeyValue

	// Boxes maps box names to contents. Each box is created, or replaced if it already exists.
	// Other existing boxes are left unchanged.
	Boxes map[string][]byte
}

// reservedCreatableIDs is the number of IDs above the current txn counter that cannot be used for
// new apps, since they may be assigned to creatables made during simulation. It comfortably
// exceeds the number of transactions a single group can contain, including inner transactions.
const reservedCreatableIDs = 1000

type appOverlay struct {
	creator basics.Address
	params  basics.AppParams
}

// stateOverlay holds the overridden ledger state as of the simulation's start round.
type stateOverlay struct {
	accounts map[basics.Address]ledgercore.AccountData
	apps     map[basics.AppIndex]appOverlay
	kvs      map[string][]byte
	// totals are the start round totals, adjusted to reflect the overridden accounts
	totals ledgercore.AccountTotals
}

func invalidOverride(format string, args ...any) error {
	return InvalidRequestError{SimulatorError{fmt.Errorf("invalid state override: "+format, args...)}}
}

func sortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	return slices.Sorted(maps.Keys(m))
}

// buildStateOverlay computes the ledger state that results from applying overrides to the state
// as of l.start. It returns nil if there are no overrides.
func (l simulatorLedger) buildStateOverlay(overrides StateOverrides, prevHdr bookkeeping.BlockHeader) (*stateOverlay, error) {
	if len(overrides.Accounts) == 0 && len(overrides.Apps) == 0 {
		return nil, nil
	}

	proto := config.Consensus[prevHdr.CurrentProtocol]
	totals, err := l.Totals(l.start)
	if err != nil {
		return nil, err
	}

	o := &stateOverlay{
		accounts: make(map[basics.Address]ledgercore.AccountData),
		apps:     make(map[basics.AppIndex]appOverlay),
		kvs:      make(map[string][]byte),
	}

	// original holds the unmodified data of every account in o.accounts, to adjust totals
	original := make(map[basics.Address]ledgercore.AccountData)
	getAccount := func(addr basics.Address) (ledgercore.AccountData, error) {
		if acct, ok := o.accounts[addr]; ok {
			return acct, nil
		}
		acct, _, err := l.Ledger.LookupWithoutRewards(l.start, addr)
		if err != nil {
			return ledgercore.AccountData{}, err
		}
		original[addr] = acct
		return acct, nil
	}

	for _, aidx := range sortedKeys(overrides.Apps) {
		if err := l.overlayApp(o, getAccount, proto, prevHdr, aidx, overrides.Apps[aidx]); err != nil {
			return nil, err
		}
	}

	for addr, override := range overrides.Accounts {
		acct, err := getAccount(addr)
		if err != nil {
			return nil, err
		}
		if override.Balance != nil {
			acct.MicroAlgos = *override.Balance
			// Set the rewards base to the current rewards level so there are no pending rewards
			acct.RewardsBase = totals.RewardsLevel
		}
		o.accounts[addr] = acct
	}

	var ot basics.OverflowTracker
	for addr, acct := range o.accounts {
		totals.DelAccount(proto.RewardUnit, original[addr], &ot)
		totals.AddAccount(proto.RewardUnit, acct, &ot)
	}
	if ot.Overflowed {
		return nil, invalidOverride("account balances overflow ledger totals")
	}
	o.totals = totals

	return o, nil
}

func (l simulatorLedger) overlayApp(o *stateOverlay, getAccount func(basics.Address) (ledgercore.AccountData, error),
	proto config.ConsensusParams, prevHdr bookkeeping.BlockHeader, aidx basics.AppIndex, override AppOverride) error {
	if aidx == 0 {
		return invalidOverride("app ID must be non-zero")
	}
	// The ledger's database stores IDs as signed 64-bit integers, so larger IDs cannot be looked up
	if uint64(aidx) > math.MaxInt64 {
		return invalidOverride("app ID %d exceeds maximum %d", aidx, int64(math.MaxInt64))
	}

	creator, exists, err := l.Ledger.GetCreatorForRound(l.start, basics.CreatableIndex(aidx), basics.AppCreatable)
	if err != nil {
		return err
	}

	var params basics.AppParams
	if exists {
		if !override.Creator.IsZero() && override.Creator != creator {
			return invalidOverride("app %d exists with creator %s, which cannot be changed to %s", aidx, creator, override.Creator)
		}
		res, err := l.Ledger.LookupApplication(l.start, creator, aidx)
		if err != nil {
			return err
		}
		if res.AppParams == nil {
			return fmt.Errorf("app %d params not found for creator %s", aidx, creator)
		}
		params = *res.AppParams
		params.GlobalState = params.GlobalState.Clone()
	} else {
		// Apps created during simulation are assigned IDs just above the current txn counter, so
		// new apps must stay clear of that range to avoid colliding with them.
		if uint64(aidx) > prevHdr.TxnCounter && uint64(aidx) <= basics.AddSaturate(prevHdr.TxnCounter, reservedCreatableIDs) {
			return invalidOverride("cannot create app %d: new app IDs must not be in the range (%d, %d], which may be assigned during simulation",
				aidx, prevHdr.TxnCounter, basics.AddSaturate(prevHdr.TxnCounter, reservedCreatableIDs))
		}
		_, isAsset, err := l.Ledger.GetCreatorForRound(l.start, basics.CreatableIndex(aidx), basics.AssetCreatable)
		if err != nil {
			return err
		}
		if isAsset {
			return invalidOverride("cannot create app %d: an asset exists with that ID", aidx)
		}
		if override.Creator.IsZero() {
			return invalidOverride("cannot create app %d: creator is required", aidx)
		}
		if override.ApprovalProgram == nil || override.ClearStateProgram == nil {
			return invalidOverride("cannot create app %d: approval and clear state programs are required", aidx)
		}
		creator = override.Creator
	}

	oldGlobalSchema := params.GlobalStateSchema
	oldExtraPages := params.ExtraProgramPages

	if override.ApprovalProgram != nil {
		params.ApprovalProgram = bytes.Clone(override.ApprovalProgram)
	}
	if override.ClearStateProgram != nil {
		params.ClearStateProgram = bytes.Clone(override.ClearStateProgram)
	}
	if override.GlobalStateSchema != nil {
		params.GlobalStateSchema = *override.GlobalStateSchema
	}
	if override.LocalStateSchema != nil {
		params.LocalStateSchema = *override.LocalStateSchema
	}
	if override.ExtraProgramPages != nil {
		params.ExtraProgramPages = *override.ExtraProgramPages
	}
	for key, value := range override.GlobalState {
		if params.GlobalState == nil {
			params.GlobalState = make(basics.TealKeyValue)
		}
		if value.Type == basics.TealBytesType {
			value.Bytes = string(bytes.Clone([]byte(value.Bytes)))
		}
		params.GlobalState[key] = value
	}

	if err := validateAppParams(proto, aidx, params); err != nil {
		return err
	}

	// Update minimum balance bookkeeping for the app and its global schema and extra pages
	if !exists {
		acct, err := getAccount(creator)
		if err != nil {
			return err
		}
		acct.TotalAppParams = basics.AddSaturate(acct.TotalAppParams, 1)
		o.accounts[creator] = acct
	}
	sponsor := params.SizeSponsor
	if sponsor.IsZero() {
		sponsor = creator
	}
	acct, err := getAccount(sponsor)
	if err != nil {
		return err
	}
	acct.TotalAppSchema = acct.TotalAppSchema.SubSchema(oldGlobalSchema).AddSchema(params.GlobalStateSchema)
	acct.TotalExtraAppPages = basics.AddSaturate(basics.SubSaturate(acct.TotalExtraAppPages, oldExtraPages), params.ExtraProgramPages)
	o.accounts[sponsor] = acct

	o.apps[aidx] = appOverlay{creator: creator, params: params}

	if len(override.Boxes) == 0 {
		return nil
	}
	appAddr := aidx.Address()
	appAcct, err := getAccount(appAddr)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(override.Boxes) {
		value := override.Boxes[name]
		if len(name) == 0 || len(name) > proto.MaxAppKeyLen {
			return invalidOverride("app %d box name length %d must be between 1 and %d", aidx, len(name), proto.MaxAppKeyLen)
		}
		if uint64(len(value)) > proto.MaxBoxSize {
			return invalidOverride("app %d box %#x size %d exceeds maximum %d", aidx, name, len(value), proto.MaxBoxSize)
		}
		key := apps.MakeBoxKey(uint64(aidx), name)
		existing, err := l.Ledger.LookupKv(l.start, key)
		if err != nil {
			return err
		}
		if existing != nil {
			appAcct.TotalBoxBytes = basics.SubSaturate(appAcct.TotalBoxBytes, uint64(len(name)+len(existing)))
		} else {
			appAcct.TotalBoxes = basics.AddSaturate(appAcct.TotalBoxes, 1)
		}
		appAcct.TotalBoxBytes = basics.AddSaturate(appAcct.TotalBoxBytes, uint64(len(name)+len(value)))
		// A nil value denotes a missing box, so zero-length boxes must be non-nil
		o.kvs[key] = append([]byte{}, value...)
	}
	o.accounts[appAddr] = appAcct

	return nil
}

func validateAppParams(proto config.ConsensusParams, aidx basics.AppIndex, params basics.AppParams) error {
	if params.ExtraProgramPages > uint32(proto.MaxExtraAppProgramPages) {
		return invalidOverride("app %d extra program pages %d exceeds maximum %d", aidx, params.ExtraProgramPages, proto.MaxExtraAppProgramPages)
	}
	if params.GlobalStateSchema.NumEntries() > proto.MaxGlobalSchemaEntries {
		return invalidOverride("app %d global schema has %d entries, exceeding maximum %d", aidx, params.GlobalStateSchema.NumEntries(), proto.MaxGlobalSchemaEntries)
	}
	if params.LocalStateSchema.NumEntries() > proto.MaxLocalSchemaEntries {
		return invalidOverride("app %d local schema has %d entries, exceeding maximum %d", aidx, params.LocalStateSchema.NumEntries(), proto.MaxLocalSchemaEntries)
	}

	pages := 1 + int(params.ExtraProgramPages)
	if len(params.ApprovalProgram) > pages*proto.MaxAppProgramLen || len(params.ClearStateProgram) > pages*proto.MaxAppProgramLen ||
		len(params.ApprovalProgram)+len(params.ClearStateProgram) > pages*proto.MaxAppTotalProgramLen {
		return invalidOverride("app %d programs are too long for %d extra pages", aidx, params.ExtraProgramPages)
	}

	for key, value := range params.GlobalState {
		if len(key) > proto.MaxAppKeyLen {
			return invalidOverride("app %d global key %#x length %d exceeds maximum %d", aidx, key, len(key), proto.MaxAppKeyLen)
		}
		switch value.Type {
		case basics.TealUintType:
		case basics.TealBytesType:
			if len(value.Bytes) > proto.MaxAppBytesValueLen {
				return invalidOverride("app %d global value for key %#x length %d exceeds maximum %d", aidx, key, len(value.Bytes), proto.MaxAppBytesValueLen)
			}
			if len(key)+len(value.Bytes) > proto.MaxAppSumKeyValueLens {
				return invalidOverride("app %d global key/value for key %#x total length %d exceeds maximum %d", aidx, key, len(key)+len(value.Bytes), proto.MaxAppSumKeyValueLens)
			}
		default:
			return invalidOverride("app %d global value for key %#x has invalid type %d", aidx, key, value.Type)
		}
	}
	schema, err := params.GlobalState.ToStateSchema()
	if err != nil {
		return invalidOverride("app %d global state: %v", aidx, err)
	}
	if !params.GlobalStateSchema.Allows(schema) {
		return invalidOverride("app %d global state %v exceeds global schema %v", aidx, schema, params.GlobalStateSchema)
	}
	return nil
}

// LookupWithoutRewards is part of the ledger.Ledger interface.
// We override this to apply any account overrides.
func (l simulatorLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	if l.overlay != nil && rnd == l.start {
		if acct, ok := l.overlay.accounts[addr]; ok {
			return acct, rnd, nil
		}
	}
	return l.Ledger.LookupWithoutRewards(rnd, addr)
}

// LookupApplication is part of the ledger.Ledger interface.
// We override this to apply any app overrides.
func (l simulatorLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	res, err := l.Ledger.LookupApplication(rnd, addr, aidx)
	if err != nil || l.overlay == nil || rnd != l.start {
		return res, err
	}
	if app, ok := l.overlay.apps[aidx]; ok && app.creator == addr {
		params := app.params
		params.GlobalState = params.GlobalState.Clone()
		res.AppParams = &params
	}
	return res, nil
}

// GetCreatorForRound is part of the ledger.Ledger interface.
// We override this to apply any app overrides.
func (l simulatorLedger) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	if l.overlay != nil && rnd == l.start && ctype == basics.AppCreatable {
		if app, ok := l.overlay.apps[basics.AppIndex(cidx)]; ok {
			return app.creator, true, nil
		}
	}
	return l.Ledger.GetCreatorForRound(rnd, cidx, ctype)
}

// LookupKv is part of the ledger.Ledger interface.
// We override this to apply any box overrides.
func (l simulatorLedger) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	if l.overlay != nil && rnd == l.start {
		if value, ok := l.overlay.kvs[key]; ok {
			return append([]byte{}, value...), nil
		}
	}
	return l.Ledger.LookupKv(rnd, key)
}
