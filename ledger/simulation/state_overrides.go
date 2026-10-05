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
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"

	"github.com/algorand/avm-abi/apps"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// StateOverrides describes modifications to ledger state that are applied before any evaluation
// takes place. The overrides are only visible to the simulation and are never persisted.
type StateOverrides struct {
	Accounts map[basics.Address]AccountOverride
	Apps     map[basics.AppIndex]AppOverride
	Assets   map[basics.AssetIndex]AssetOverride
	Blocks   map[basics.Round]BlockOverride
}

// BlockOverride describes modifications to the header of a block at or before the start round.
// Nil fields are left unchanged. Overridden headers are seen by the block opcode, and by anything
// else that reads past block headers, such as the validation of heartbeats.
//
// The start round's header is the previous header of the block being simulated, so its overrides
// also affect that block where it is derived from the previous header: global LatestTimestamp is
// TimeStamp, the simulated block's timestamp is no earlier than it, its bonus is derived from
// Bonus, and its fees are paid to FeeSink.
type BlockOverride struct {
	TimeStamp      *int64
	Seed           *committee.Seed
	Proposer       *basics.Address
	FeeSink        *basics.Address
	FeesCollected  *basics.MicroAlgos
	Bonus          *basics.MicroAlgos
	ProposerPayout *basics.MicroAlgos
}

// AccountOverride describes modifications to a single account's state. Nil fields are left unchanged.
type AccountOverride struct {
	// Balance, if set, replaces the account's balance. Pending rewards are forfeited, so the
	// account's balance at the start of simulation is exactly this value.
	//
	// If Balance or any of the consensus participation fields below are set, the account is
	// treated as though it has been in its overridden state since the balance round used for
	// agreement. Its online data (e.g. as seen by voter_params_get) and its contribution to the
	// online stake (e.g. as seen by online_stake) reflect the overridden account.
	Balance *basics.MicroAlgos

	// AuthAddr, if set, replaces the address whose signature authorizes the account's
	// transactions. The zero address means the account is not rekeyed.
	AuthAddr *basics.Address

	// Status, VotingData fields, IncentiveEligible, LastProposed and LastHeartbeat replace the
	// account's consensus participation state. The account's balance moves between the online,
	// offline and not participating totals if its status changes, and as with Balance, the
	// overridden state is also used for agreement.
	Status            *basics.Status
	VoteID            *crypto.OneTimeSignatureVerifier
	SelectionID       *crypto.VRFVerifier
	StateProofID      *merklesignature.Commitment
	VoteFirstValid    *basics.Round
	VoteLastValid     *basics.Round
	VoteKeyDilution   *uint64
	IncentiveEligible *bool
	LastProposed      *basics.Round
	LastHeartbeat     *basics.Round

	// Assets maps asset IDs to overrides of the account's holdings. If the account is not opted in
	// to an asset, it is opted in. The asset must exist, either on the ledger or by an
	// AssetOverride.
	Assets map[basics.AssetIndex]AssetHoldingOverride

	// Apps maps app IDs to overrides of the account's local state. If the account is not opted in
	// to an app, it is opted in, unless the override opts it out. The app must exist, either on the
	// ledger or by an AppOverride.
	Apps map[basics.AppIndex]AppLocalStateOverride
}

// AppLocalStateOverride describes modifications to an account's local state for an app. Nil fields
// are left unchanged. For a new opt-in, the schema defaults to the app's LocalStateSchema.
type AppLocalStateOverride struct {
	// Schema, if set, replaces the local schema recorded when the account opted in, which
	// determines how much local state the account may hold, and its minimum balance.
	Schema *basics.StateSchema

	// KeyValue entries are set, replacing any existing value for the same key. Other existing keys
	// are left unchanged.
	KeyValue basics.TealKeyValue

	// DeleteKeyValue lists local state keys to delete. Each key must exist, and must not also be
	// set in KeyValue.
	DeleteKeyValue []string

	// OptOut, if true, removes the account's local state. The account must be opted in, and no
	// other field may be set.
	OptOut bool
}

// AssetHoldingOverride describes modifications to an account's holding of an asset. Nil fields are
// left unchanged. For a new holding, they default to an amount of zero and the asset's
// DefaultFrozen.
type AssetHoldingOverride struct {
	Amount *uint64
	Frozen *bool
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
//
// Overrides are not checked against the consensus parameters of the simulation round, so they may
// use features or exceed limits that the protocol does not allow.
type AppOverride struct {
	// Creator is required when creating an application. For an existing application, it must be
	// empty or match the existing creator.
	Creator basics.Address

	// ApprovalProgram and ClearStateProgram are required when creating an application.
	ApprovalProgram   []byte
	ClearStateProgram []byte
	GlobalStateSchema *basics.StateSchema
	// LocalStateSchema only applies to accounts that opt in during simulation, or by an
	// AppLocalStateOverride. Accounts that are already opted in keep the local schema, and
	// minimum balance, from when they opted in, unless an AppLocalStateOverride replaces it.
	LocalStateSchema  *basics.StateSchema
	ExtraProgramPages *uint32
	Version           *uint64

	// SizeSponsor, if set, replaces the account that holds the minimum balance for the global
	// schema and extra program pages. The zero address makes the creator hold it.
	SizeSponsor *basics.Address

	ForeignBoxReads *bool
	FamilyBoxAccess *bool

	// GlobalState entries are set, replacing any existing value for the same key. Other existing
	// keys are left unchanged.
	GlobalState basics.TealKeyValue

	// DeleteGlobalState lists global state keys to delete. Each key must exist, and must not also
	// be set in GlobalState.
	DeleteGlobalState []string

	// Boxes maps box names to contents. Each box is created, or replaced if it already exists.
	// Other existing boxes are left unchanged.
	Boxes map[string][]byte

	// DeleteBoxes lists the names of boxes to delete. Each box must exist, and must not also be set
	// in Boxes.
	DeleteBoxes []string
}

// AssetOverride describes modifications to a single asset's params. If the asset does not exist,
// it is created. Nil fields are left unchanged.
//
// New asset IDs are subject to the same restrictions as new app IDs. A new asset's creator is opted
// in to it with a holding of the asset's total, which an AccountOverride may then modify.
//
// Holdings are not checked against the asset's total, and, as for apps, overrides are not checked
// against the consensus parameters of the simulation round.
type AssetOverride struct {
	// Creator is required when creating an asset. For an existing asset, it must be empty or match
	// the existing creator.
	Creator basics.Address

	Total         *uint64
	Decimals      *uint32
	DefaultFrozen *bool
	UnitName      *string
	AssetName     *string
	URL           *string
	MetadataHash  *[32]byte
	Manager       *basics.Address
	Reserve       *basics.Address
	Freeze        *basics.Address
	Clawback      *basics.Address
}

// reservedCreatableIDs is the number of IDs above the current txn counter that cannot be used for
// new apps, since they may be assigned to creatables made during simulation. It comfortably
// exceeds the number of transactions a single group can contain, including inner transactions.
const reservedCreatableIDs = 1000

type appOverlay struct {
	creator basics.Address
	params  basics.AppParams
}

type assetOverlay struct {
	creator basics.Address
	params  basics.AssetParams
}

type holdingKey struct {
	addr basics.Address
	aidx basics.AssetIndex
}

type localStateKey struct {
	addr basics.Address
	aidx basics.AppIndex
}

// stateOverlay holds the overridden ledger state as of the simulation's start round.
type stateOverlay struct {
	accounts map[basics.Address]ledgercore.AccountData
	apps     map[basics.AppIndex]appOverlay
	assets   map[basics.AssetIndex]assetOverlay
	holdings map[holdingKey]basics.AssetHolding
	// localStates holds overridden local states, where a nil value denotes an opted out account
	localStates map[localStateKey]*basics.AppLocalState
	// kvs holds overridden boxes, where a nil value denotes a deleted box
	kvs map[string][]byte
	// blocks holds overrides of block headers at or before the start round
	blocks map[basics.Round]BlockOverride
	// totals are the start round totals, adjusted to reflect the overridden accounts
	totals ledgercore.AccountTotals

	// balanceRound is the round whose online state agreement uses for the round being simulated
	balanceRound basics.Round
	// online holds the online data of accounts whose agreement state is overridden. Accounts
	// that are not online have empty online data.
	online map[basics.Address]basics.OnlineAccountData
	// onlineAdded and onlineRemoved are the stake that the accounts in online add to and remove
	// from the online circulation at balanceRound
	onlineAdded   basics.MicroAlgos
	onlineRemoved basics.MicroAlgos
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
	if len(overrides.Accounts) == 0 && len(overrides.Apps) == 0 && len(overrides.Assets) == 0 && len(overrides.Blocks) == 0 {
		return nil, nil
	}

	proto := config.Consensus[prevHdr.CurrentProtocol]
	totals, err := l.Totals(l.start)
	if err != nil {
		return nil, err
	}

	o := &stateOverlay{
		accounts:    make(map[basics.Address]ledgercore.AccountData),
		apps:        make(map[basics.AppIndex]appOverlay),
		assets:      make(map[basics.AssetIndex]assetOverlay),
		holdings:    make(map[holdingKey]basics.AssetHolding),
		localStates: make(map[localStateKey]*basics.AppLocalState),
		kvs:         make(map[string][]byte),
		blocks:      make(map[basics.Round]BlockOverride),
		online:      make(map[basics.Address]basics.OnlineAccountData),
	}

	for _, rnd := range sortedKeys(overrides.Blocks) {
		if err := l.overlayBlock(o, rnd, overrides.Blocks[rnd]); err != nil {
			return nil, err
		}
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
		if err := l.overlayApp(o, getAccount, prevHdr, aidx, overrides.Apps[aidx]); err != nil {
			return nil, err
		}
	}
	// Assets come after apps, so that new assets can check for collisions with new apps
	for _, aidx := range sortedKeys(overrides.Assets) {
		if err := l.overlayAsset(o, getAccount, prevHdr, aidx, overrides.Assets[aidx]); err != nil {
			return nil, err
		}
	}

	// Sort accounts so that errors are deterministic
	addrs := slices.SortedFunc(maps.Keys(overrides.Accounts), func(a, b basics.Address) int {
		return bytes.Compare(a[:], b[:])
	})
	for _, addr := range addrs {
		override := overrides.Accounts[addr]
		acct, err := getAccount(addr)
		if err != nil {
			return nil, err
		}
		if override.Balance != nil {
			acct.MicroAlgos = *override.Balance
			// Set the rewards base to the current rewards level so there are no pending rewards
			acct.RewardsBase = totals.RewardsLevel
		}
		if err = overlayAccountFields(&acct, addr, override); err != nil {
			return nil, err
		}
		for _, aidx := range sortedKeys(override.Assets) {
			if acct, err = l.overlayHolding(o, acct, addr, aidx, override.Assets[aidx]); err != nil {
				return nil, err
			}
		}
		for _, aidx := range sortedKeys(override.Apps) {
			if acct, err = l.overlayLocalState(o, acct, addr, aidx, override.Apps[aidx]); err != nil {
				return nil, err
			}
		}
		o.accounts[addr] = acct
	}

	var ot basics.OverflowTracker
	// Remove all original balances before adding replacements. Otherwise an increase
	// can overflow the totals temporarily even when the final totals fit.
	for addr := range o.accounts {
		totals.DelAccount(proto.RewardUnit, original[addr], &ot)
	}
	for _, acct := range o.accounts {
		totals.AddAccount(proto.RewardUnit, acct, &ot)
	}
	// Each status total may fit even when their combined balance does not. Check
	// the sum here, since AccountTotals.All and Participating panic on overflow.
	participating := ot.AddA(totals.Online.Money, totals.Offline.Money)
	_ = ot.AddA(participating, totals.NotParticipating.Money)
	if ot.Overflowed {
		return nil, invalidOverride("account balances overflow ledger totals")
	}
	o.totals = totals

	if err = l.overlayOnline(o, overrides, proto, prevHdr); err != nil {
		return nil, err
	}

	return o, nil
}

// affectsAgreement reports whether the override modifies state that agreement uses.
func (override AccountOverride) affectsAgreement() bool {
	return override.Balance != nil || override.Status != nil || override.VoteID != nil ||
		override.SelectionID != nil || override.StateProofID != nil || override.VoteFirstValid != nil ||
		override.VoteLastValid != nil || override.VoteKeyDilution != nil || override.IncentiveEligible != nil ||
		override.LastProposed != nil || override.LastHeartbeat != nil
}

// overlayOnline computes the online state used for agreement, for accounts whose overrides affect
// it. Such accounts are treated as though they have been in their overridden state since the
// balance round.
func (l simulatorLedger) overlayOnline(o *stateOverlay, overrides StateOverrides, proto config.ConsensusParams, prevHdr bookkeeping.BlockHeader) error {
	if !slices.ContainsFunc(slices.Collect(maps.Values(overrides.Accounts)), AccountOverride.affectsAgreement) {
		return nil
	}

	// Match the evaluator's choice of balance round for the round being simulated
	current := l.start + 1
	paramsHdr, err := l.Ledger.BlockHdr(agreement.ParamsRound(current))
	if err != nil {
		return err
	}
	o.balanceRound = agreement.BalanceRound(current, config.Consensus[paramsHdr.CurrentProtocol])

	balanceHdr, err := l.Ledger.BlockHdr(o.balanceRound)
	if err != nil {
		return err
	}
	// Match the ledger's exclusion of expired stake from the online circulation
	excludeExpired := config.Consensus[balanceHdr.CurrentProtocol].ExcludeExpiredCirculation && o.balanceRound != 0
	circulating := func(data basics.OnlineAccountData) basics.MicroAlgos {
		if excludeExpired && data.VoteLastValid > 0 && data.VoteLastValid < current {
			return basics.MicroAlgos{}
		}
		return data.VotingStake()
	}

	var ot basics.OverflowTracker
	for addr, override := range overrides.Accounts {
		if !override.affectsAgreement() {
			continue
		}
		original, err := l.Ledger.LookupAgreement(o.balanceRound, addr)
		if err != nil {
			return err
		}
		// Rewards are applied as of the start round, since the account's rewards base may be later
		// than the balance round
		data := o.accounts[addr].OnlineAccountData(proto.RewardUnit, prevHdr.RewardsLevel)
		o.online[addr] = data
		o.onlineRemoved = ot.AddA(o.onlineRemoved, circulating(original))
		o.onlineAdded = ot.AddA(o.onlineAdded, circulating(data))
	}
	if ot.Overflowed {
		return invalidOverride("account balances overflow online circulation")
	}
	return nil
}

func (l simulatorLedger) overlayBlock(o *stateOverlay, rnd basics.Round, override BlockOverride) error {
	if rnd > l.start {
		return invalidOverride("cannot override block %d: it is after the start round %d", rnd, l.start)
	}
	if _, err := l.Ledger.BlockHdr(rnd); err != nil {
		return invalidOverride("cannot override block %d: %v", rnd, err)
	}
	if override.TimeStamp != nil && *override.TimeStamp < 0 {
		return invalidOverride("block %d timestamp %d must not be negative", rnd, *override.TimeStamp)
	}
	o.blocks[rnd] = override
	return nil
}

// apply applies the override to hdr.
func (override BlockOverride) apply(hdr *bookkeeping.BlockHeader) {
	if override.TimeStamp != nil {
		hdr.TimeStamp = *override.TimeStamp
	}
	if override.Seed != nil {
		hdr.Seed = *override.Seed
	}
	if override.Proposer != nil {
		hdr.Proposer = *override.Proposer
	}
	if override.FeeSink != nil {
		hdr.FeeSink = *override.FeeSink
	}
	if override.FeesCollected != nil {
		hdr.FeesCollected = *override.FeesCollected
	}
	if override.Bonus != nil {
		hdr.Bonus = *override.Bonus
	}
	if override.ProposerPayout != nil {
		hdr.ProposerPayout = *override.ProposerPayout
	}
}

// overlayAccountFields applies the overrides of an account's own fields, other than its balance.
func overlayAccountFields(acct *ledgercore.AccountData, addr basics.Address, override AccountOverride) error {
	if override.Status != nil {
		switch *override.Status {
		case basics.Offline, basics.Online, basics.NotParticipating:
			acct.Status = *override.Status
		default:
			return invalidOverride("account %s status %d is not valid", addr, *override.Status)
		}
	}
	if override.AuthAddr != nil {
		acct.AuthAddr = *override.AuthAddr
	}
	if override.VoteID != nil {
		acct.VoteID = *override.VoteID
	}
	if override.SelectionID != nil {
		acct.SelectionID = *override.SelectionID
	}
	if override.StateProofID != nil {
		acct.StateProofID = *override.StateProofID
	}
	if override.VoteFirstValid != nil {
		acct.VoteFirstValid = *override.VoteFirstValid
	}
	if override.VoteLastValid != nil {
		acct.VoteLastValid = *override.VoteLastValid
	}
	if override.VoteKeyDilution != nil {
		acct.VoteKeyDilution = *override.VoteKeyDilution
	}
	if override.IncentiveEligible != nil {
		acct.IncentiveEligible = *override.IncentiveEligible
	}
	if override.LastProposed != nil {
		acct.LastProposed = *override.LastProposed
	}
	if override.LastHeartbeat != nil {
		acct.LastHeartbeat = *override.LastHeartbeat
	}
	return nil
}

func (l simulatorLedger) overlayApp(o *stateOverlay, getAccount func(basics.Address) (ledgercore.AccountData, error),
	prevHdr bookkeeping.BlockHeader, aidx basics.AppIndex, override AppOverride) error {
	if err := checkCreatableID(basics.CreatableIndex(aidx), "app"); err != nil {
		return err
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
		var res ledgercore.AppResource
		res, err = l.Ledger.LookupApplication(l.start, creator, aidx)
		if err != nil {
			return err
		}
		if res.AppParams == nil {
			return fmt.Errorf("app %d params not found for creator %s", aidx, creator)
		}
		// Deep copy so nothing here can modify the ledger's own data
		params = res.AppParams.Clone()
	} else {
		if err = checkNewCreatableID(basics.CreatableIndex(aidx), "app", prevHdr); err != nil {
			return err
		}
		var isAsset bool
		_, isAsset, err = l.Ledger.GetCreatorForRound(l.start, basics.CreatableIndex(aidx), basics.AssetCreatable)
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

	// For a new app, these are zero values and so release nothing from the creator
	oldSponsor := sizeSponsor(params, creator)
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
	if override.Version != nil {
		params.Version = *override.Version
	}
	if override.SizeSponsor != nil {
		params.SizeSponsor = *override.SizeSponsor
	}
	if override.ForeignBoxReads != nil {
		params.ForeignBoxReads = *override.ForeignBoxReads
	}
	if override.FamilyBoxAccess != nil {
		params.FamilyBoxAccess = *override.FamilyBoxAccess
	}
	params.GlobalState, err = applyKeyValueOverride(params.GlobalState, override.GlobalState, override.DeleteGlobalState)
	if err != nil {
		return invalidOverride("app %d global state: %v", aidx, err)
	}

	if err = validateAppParams(aidx, params); err != nil {
		return err
	}

	// Update minimum balance bookkeeping for the app and its global schema and extra pages
	var acct ledgercore.AccountData
	if !exists {
		acct, err = getAccount(creator)
		if err != nil {
			return err
		}
		acct.TotalAppParams = basics.AddSaturate(acct.TotalAppParams, 1)
		o.accounts[creator] = acct
	}
	// Release the old charge from the old sponsor before adding the new charge to the new sponsor,
	// which may be the same account
	acct, err = getAccount(oldSponsor)
	if err != nil {
		return err
	}
	acct.TotalAppSchema = acct.TotalAppSchema.SubSchema(oldGlobalSchema)
	acct.TotalExtraAppPages = basics.SubSaturate(acct.TotalExtraAppPages, oldExtraPages)
	o.accounts[oldSponsor] = acct

	newSponsor := sizeSponsor(params, creator)
	acct, err = getAccount(newSponsor)
	if err != nil {
		return err
	}
	acct.TotalAppSchema = acct.TotalAppSchema.AddSchema(params.GlobalStateSchema)
	acct.TotalExtraAppPages = basics.AddSaturate(acct.TotalExtraAppPages, params.ExtraProgramPages)
	o.accounts[newSponsor] = acct

	o.apps[aidx] = appOverlay{creator: creator, params: params}

	if len(override.Boxes) == 0 && len(override.DeleteBoxes) == 0 {
		return nil
	}
	appAddr := aidx.Address()
	appAcct, err := getAccount(appAddr)
	if err != nil {
		return err
	}
	for _, name := range override.DeleteBoxes {
		if _, ok := override.Boxes[name]; ok {
			return invalidOverride("app %d box %#x cannot be both set and deleted", aidx, name)
		}
		key := apps.MakeBoxKey(uint64(aidx), name)
		existing, err := l.Ledger.LookupKv(l.start, key)
		if err != nil {
			return err
		}
		if deleted, ok := o.kvs[key]; existing == nil || (ok && deleted == nil) {
			return invalidOverride("cannot delete app %d box %#x: box does not exist", aidx, name)
		}
		appAcct.TotalBoxes = basics.SubSaturate(appAcct.TotalBoxes, 1)
		appAcct.TotalBoxBytes = basics.SubSaturate(appAcct.TotalBoxBytes, uint64(len(name)+len(existing)))
		o.kvs[key] = nil
	}
	for _, name := range sortedKeys(override.Boxes) {
		value := override.Boxes[name]
		if len(name) == 0 {
			return invalidOverride("app %d box name must not be empty", aidx)
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

func checkCreatableID(cidx basics.CreatableIndex, kind string) error {
	if cidx == 0 {
		return invalidOverride("%s ID must be non-zero", kind)
	}
	// The ledger's database stores IDs as signed 64-bit integers, so larger IDs cannot be looked up
	if uint64(cidx) > math.MaxInt64 {
		return invalidOverride("%s ID %d exceeds maximum %d", kind, cidx, int64(math.MaxInt64))
	}
	return nil
}

func checkNewCreatableID(cidx basics.CreatableIndex, kind string, prevHdr bookkeeping.BlockHeader) error {
	// Creatables made during simulation are assigned IDs just above the current txn counter, so
	// new ones must stay clear of that range to avoid colliding with them.
	if uint64(cidx) > prevHdr.TxnCounter && uint64(cidx) <= basics.AddSaturate(prevHdr.TxnCounter, reservedCreatableIDs) {
		return invalidOverride("cannot create %s %d: new %s IDs must not be in the range (%d, %d], which may be assigned during simulation",
			kind, cidx, kind, prevHdr.TxnCounter, basics.AddSaturate(prevHdr.TxnCounter, reservedCreatableIDs))
	}
	return nil
}

func (l simulatorLedger) overlayAsset(o *stateOverlay, getAccount func(basics.Address) (ledgercore.AccountData, error),
	prevHdr bookkeeping.BlockHeader, aidx basics.AssetIndex, override AssetOverride) error {
	if err := checkCreatableID(basics.CreatableIndex(aidx), "asset"); err != nil {
		return err
	}

	creator, exists, err := l.Ledger.GetCreatorForRound(l.start, basics.CreatableIndex(aidx), basics.AssetCreatable)
	if err != nil {
		return err
	}

	var params basics.AssetParams
	if exists {
		if !override.Creator.IsZero() && override.Creator != creator {
			return invalidOverride("asset %d exists with creator %s, which cannot be changed to %s", aidx, creator, override.Creator)
		}
		var res ledgercore.AssetResource
		res, err = l.Ledger.LookupAsset(l.start, creator, aidx)
		if err != nil {
			return err
		}
		if res.AssetParams == nil {
			return fmt.Errorf("asset %d params not found for creator %s", aidx, creator)
		}
		params = *res.AssetParams
	} else {
		if err = checkNewCreatableID(basics.CreatableIndex(aidx), "asset", prevHdr); err != nil {
			return err
		}
		var isApp bool
		_, isApp, err = l.Ledger.GetCreatorForRound(l.start, basics.CreatableIndex(aidx), basics.AppCreatable)
		if err != nil {
			return err
		}
		if _, ok := o.apps[basics.AppIndex(aidx)]; isApp || ok {
			return invalidOverride("cannot create asset %d: an app exists with that ID", aidx)
		}
		if override.Creator.IsZero() {
			return invalidOverride("cannot create asset %d: creator is required", aidx)
		}
		creator = override.Creator
	}

	if override.Total != nil {
		params.Total = *override.Total
	}
	if override.Decimals != nil {
		params.Decimals = *override.Decimals
	}
	if override.DefaultFrozen != nil {
		params.DefaultFrozen = *override.DefaultFrozen
	}
	if override.UnitName != nil {
		params.UnitName = *override.UnitName
	}
	if override.AssetName != nil {
		params.AssetName = *override.AssetName
	}
	if override.URL != nil {
		params.URL = *override.URL
	}
	if override.MetadataHash != nil {
		params.MetadataHash = *override.MetadataHash
	}
	if override.Manager != nil {
		params.Manager = *override.Manager
	}
	if override.Reserve != nil {
		params.Reserve = *override.Reserve
	}
	if override.Freeze != nil {
		params.Freeze = *override.Freeze
	}
	if override.Clawback != nil {
		params.Clawback = *override.Clawback
	}

	o.assets[aidx] = assetOverlay{creator: creator, params: params}

	if exists {
		return nil
	}
	// As when an asset is created, the creator holds the entire supply
	acct, err := getAccount(creator)
	if err != nil {
		return err
	}
	acct.TotalAssetParams = basics.AddSaturate(acct.TotalAssetParams, 1)
	// Asset creation leaves the creator's holding unfrozen, even if opt-ins are
	// frozen by default. A subsequent account override may still change it.
	frozen := false
	acct, err = l.overlayHolding(o, acct, creator, aidx, AssetHoldingOverride{Amount: &params.Total, Frozen: &frozen})
	if err != nil {
		return err
	}
	o.accounts[creator] = acct
	return nil
}

// overlayHolding applies a holding override to the account addr, whose current data is acct, and
// returns the updated account data. The asset must already be in o.assets, or on the ledger.
func (l simulatorLedger) overlayHolding(o *stateOverlay, acct ledgercore.AccountData, addr basics.Address,
	aidx basics.AssetIndex, override AssetHoldingOverride) (ledgercore.AccountData, error) {
	key := holdingKey{addr: addr, aidx: aidx}
	holding, ok := o.holdings[key]
	if !ok {
		res, err := l.Ledger.LookupAsset(l.start, addr, aidx)
		if err != nil {
			return ledgercore.AccountData{}, err
		}
		if res.AssetHolding != nil {
			holding = *res.AssetHolding
		} else {
			// Opt the account in, which requires the asset to exist
			var params basics.AssetParams
			if asset, exists := o.assets[aidx]; exists {
				params = asset.params
			} else {
				creator, exists, err := l.Ledger.GetCreatorForRound(l.start, basics.CreatableIndex(aidx), basics.AssetCreatable)
				if err != nil {
					return ledgercore.AccountData{}, err
				}
				if !exists {
					return ledgercore.AccountData{}, invalidOverride("cannot opt %s in to asset %d: asset does not exist", addr, aidx)
				}
				res, err = l.Ledger.LookupAsset(l.start, creator, aidx)
				if err != nil {
					return ledgercore.AccountData{}, err
				}
				if res.AssetParams == nil {
					return ledgercore.AccountData{}, fmt.Errorf("asset %d params not found for creator %s", aidx, creator)
				}
				params = *res.AssetParams
			}
			holding = basics.AssetHolding{Frozen: params.DefaultFrozen}
			acct.TotalAssets = basics.AddSaturate(acct.TotalAssets, 1)
		}
	}
	if override.Amount != nil {
		holding.Amount = *override.Amount
	}
	if override.Frozen != nil {
		holding.Frozen = *override.Frozen
	}
	o.holdings[key] = holding
	return acct, nil
}

// overlayLocalState applies a local state override to the account addr, whose current data is
// acct, and returns the updated account data. The app must already be in o.apps, or on the ledger.
func (l simulatorLedger) overlayLocalState(o *stateOverlay, acct ledgercore.AccountData, addr basics.Address,
	aidx basics.AppIndex, override AppLocalStateOverride) (ledgercore.AccountData, error) {
	res, err := l.Ledger.LookupApplication(l.start, addr, aidx)
	if err != nil {
		return ledgercore.AccountData{}, err
	}
	state := res.AppLocalState

	if override.OptOut {
		if override.Schema != nil || override.KeyValue != nil || override.DeleteKeyValue != nil {
			return ledgercore.AccountData{}, invalidOverride("account %s app %d local state cannot be both modified and opted out", addr, aidx)
		}
		if state == nil {
			return ledgercore.AccountData{}, invalidOverride("cannot opt %s out of app %d: account is not opted in", addr, aidx)
		}
		acct.TotalAppLocalStates = basics.SubSaturate(acct.TotalAppLocalStates, 1)
		acct.TotalAppSchema = acct.TotalAppSchema.SubSchema(state.Schema)
		o.localStates[localStateKey{addr: addr, aidx: aidx}] = nil
		return acct, nil
	}

	var newState basics.AppLocalState
	if state != nil {
		newState = *state
		// Release the old schema, as it may be replaced
		acct.TotalAppSchema = acct.TotalAppSchema.SubSchema(state.Schema)
	} else {
		// Opt the account in, which requires the app to exist
		app, exists := o.apps[aidx]
		if !exists {
			creator, ok, err := l.Ledger.GetCreatorForRound(l.start, basics.CreatableIndex(aidx), basics.AppCreatable)
			if err != nil {
				return ledgercore.AccountData{}, err
			}
			if !ok {
				return ledgercore.AccountData{}, invalidOverride("cannot opt %s in to app %d: app does not exist", addr, aidx)
			}
			res, err = l.Ledger.LookupApplication(l.start, creator, aidx)
			if err != nil {
				return ledgercore.AccountData{}, err
			}
			if res.AppParams == nil {
				return ledgercore.AccountData{}, fmt.Errorf("app %d params not found for creator %s", aidx, creator)
			}
			app.params = *res.AppParams
		}
		newState.Schema = app.params.LocalStateSchema
		acct.TotalAppLocalStates = basics.AddSaturate(acct.TotalAppLocalStates, 1)
	}

	if override.Schema != nil {
		newState.Schema = *override.Schema
	}
	newState.KeyValue, err = applyKeyValueOverride(newState.KeyValue, override.KeyValue, override.DeleteKeyValue)
	if err != nil {
		return ledgercore.AccountData{}, invalidOverride("account %s app %d local state: %v", addr, aidx, err)
	}
	if err = validateTealKeyValue(newState.KeyValue, newState.Schema); err != nil {
		return ledgercore.AccountData{}, invalidOverride("account %s app %d local state: %v", addr, aidx, err)
	}

	acct.TotalAppSchema = acct.TotalAppSchema.AddSchema(newState.Schema)
	o.localStates[localStateKey{addr: addr, aidx: aidx}] = &newState
	return acct, nil
}

// sizeSponsor returns the account that holds the minimum balance for an app's global schema and
// extra program pages.
func sizeSponsor(params basics.AppParams, creator basics.Address) basics.Address {
	if params.SizeSponsor.IsZero() {
		return creator
	}
	return params.SizeSponsor
}

func validateAppParams(aidx basics.AppIndex, params basics.AppParams) error {
	if err := validateTealKeyValue(params.GlobalState, params.GlobalStateSchema); err != nil {
		return invalidOverride("app %d global state: %v", aidx, err)
	}
	return nil
}

// validateTealKeyValue checks that every value in kv is well formed, and that kv fits in schema.
func validateTealKeyValue(kv basics.TealKeyValue, schema basics.StateSchema) error {
	for key, value := range kv {
		switch value.Type {
		case basics.TealUintType:
			if len(value.Bytes) != 0 {
				return fmt.Errorf("uint value for key %#x must not have bytes", key)
			}
		case basics.TealBytesType:
			if value.Uint != 0 {
				return fmt.Errorf("bytes value for key %#x must not have a uint", key)
			}
		default:
			return fmt.Errorf("value for key %#x has invalid type %d", key, value.Type)
		}
	}
	used, err := kv.ToStateSchema()
	if err != nil {
		return err
	}
	if !schema.Allows(used) {
		return fmt.Errorf("%v exceeds schema %v", used, schema)
	}
	return nil
}

// applyKeyValueOverride returns kv with the keys in del deleted, and the entries in set set. kv is
// not modified.
func applyKeyValueOverride(kv basics.TealKeyValue, set basics.TealKeyValue, del []string) (basics.TealKeyValue, error) {
	kv = kv.Clone()
	for _, key := range del {
		if _, ok := set[key]; ok {
			return nil, fmt.Errorf("key %#x cannot be both set and deleted", key)
		}
		if _, ok := kv[key]; !ok {
			return nil, fmt.Errorf("cannot delete key %#x: key does not exist", key)
		}
		delete(kv, key)
	}
	for key, value := range set {
		if kv == nil {
			kv = make(basics.TealKeyValue)
		}
		kv[key] = value
	}
	return kv, nil
}

// BlockHdr is part of the ledger.Ledger interface.
// We override this to apply any block header overrides.
func (l simulatorLedger) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	hdr, err := l.Ledger.BlockHdr(rnd)
	if err != nil || l.overlay == nil {
		return hdr, err
	}
	if override, ok := l.overlay.blocks[rnd]; ok {
		override.apply(&hdr)
	}
	return hdr, nil
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

// LookupAgreement is part of the ledger.Ledger interface.
// We override this to apply any account overrides that affect agreement.
func (l simulatorLedger) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	if l.overlay != nil && rnd == l.overlay.balanceRound {
		if data, ok := l.overlay.online[addr]; ok {
			return data, nil
		}
	}
	return l.Ledger.LookupAgreement(rnd, addr)
}

// OnlineCirculation is part of the ledger.Ledger interface.
// We override this to apply any account overrides that affect agreement.
func (l simulatorLedger) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	total, err := l.Ledger.OnlineCirculation(rnd, voteRnd)
	if err != nil || l.overlay == nil || rnd != l.overlay.balanceRound || voteRnd != l.start+1 {
		return total, err
	}
	// The original stake was approximated per account, so saturate rather than fail if it
	// slightly exceeds the total
	total.Raw = basics.SubSaturate(total.Raw, l.overlay.onlineRemoved.Raw)
	// Remove the original stake before adding its replacement, so an intermediate
	// sum cannot overflow when the final circulation fits.
	var ot basics.OverflowTracker
	total = ot.AddA(total, l.overlay.onlineAdded)
	if ot.Overflowed {
		return basics.MicroAlgos{}, errors.New("overridden online circulation overflows")
	}
	return total, nil
}

// GetKnockOfflineCandidates is part of the ledger.Ledger interface.
// We override this so that accounts overridden to be online are considered for suspension, and
// accounts overridden to not be online are not.
func (l simulatorLedger) GetKnockOfflineCandidates(rnd basics.Round, proto config.ConsensusParams) (map[basics.Address]basics.OnlineAccountData, error) {
	candidates, err := l.Ledger.GetKnockOfflineCandidates(rnd, proto)
	// A nil result means candidates are not considered at all
	if err != nil || candidates == nil || l.overlay == nil || rnd != l.start || len(l.overlay.online) == 0 {
		return candidates, err
	}
	// Copy, so the ledger's result is not modified
	candidates = maps.Clone(candidates)
	for addr, data := range l.overlay.online {
		if l.overlay.accounts[addr].Status != basics.Online {
			delete(candidates, addr)
			continue
		}
		candidates[addr] = data
	}
	return candidates, nil
}

// LookupApplication is part of the ledger.Ledger interface.
// We override this to apply any app and local state overrides.
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
	if state, ok := l.overlay.localStates[localStateKey{addr: addr, aidx: aidx}]; ok {
		if state == nil {
			// The account was opted out
			res.AppLocalState = nil
		} else {
			local := *state
			local.KeyValue = local.KeyValue.Clone()
			res.AppLocalState = &local
		}
	}
	return res, nil
}

// LookupAsset is part of the ledger.Ledger interface.
// We override this to apply any asset and holding overrides.
func (l simulatorLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	res, err := l.Ledger.LookupAsset(rnd, addr, aidx)
	if err != nil || l.overlay == nil || rnd != l.start {
		return res, err
	}
	if asset, ok := l.overlay.assets[aidx]; ok && asset.creator == addr {
		params := asset.params
		res.AssetParams = &params
	}
	if holding, ok := l.overlay.holdings[holdingKey{addr: addr, aidx: aidx}]; ok {
		res.AssetHolding = &holding
	}
	return res, nil
}

// GetCreatorForRound is part of the ledger.Ledger interface.
// We override this to apply any app and asset overrides.
func (l simulatorLedger) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	if l.overlay != nil && rnd == l.start {
		switch ctype {
		case basics.AppCreatable:
			if app, ok := l.overlay.apps[basics.AppIndex(cidx)]; ok {
				return app.creator, true, nil
			}
		case basics.AssetCreatable:
			if asset, ok := l.overlay.assets[basics.AssetIndex(cidx)]; ok {
				return asset.creator, true, nil
			}
		}
	}
	return l.Ledger.GetCreatorForRound(rnd, cidx, ctype)
}

// LookupKv is part of the ledger.Ledger interface.
// We override this to apply any box overrides.
func (l simulatorLedger) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	if l.overlay != nil && rnd == l.start {
		if value, ok := l.overlay.kvs[key]; ok {
			if value == nil {
				// The box was deleted
				return nil, nil
			}
			return append([]byte{}, value...), nil
		}
	}
	return l.Ledger.LookupKv(rnd, key)
}
