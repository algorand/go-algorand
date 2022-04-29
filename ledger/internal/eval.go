// Copyright (C) 2019-2022 Algorand, Inc.
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

package internal

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/ledger/internal/prefetcher"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

// LedgerForCowBase represents subset of Ledger functionality needed for cow business
type LedgerForCowBase interface {
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error
	LookupWithoutRewards(basics.Round, basics.Address) (ledgercore.AccountData, basics.Round, error)
	LookupAsset(basics.Round, basics.Address, basics.AssetIndex) (ledgercore.AssetResource, error)
	LookupApplication(basics.Round, basics.Address, basics.AppIndex) (ledgercore.AppResource, error)
	LookupKv(basics.Round, string) (*string, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
}

// ErrRoundZero is self-explanatory
var ErrRoundZero = errors.New("cannot start evaluator for round 0")

// ErrNotInCowCache is returned when a lookup method requests a cached value, but it can't be found.
// the error is always being invoked by the roundCowBase object, but it would typically propage upstream
// through the roundCowState as a generic "missing object in cache".
var ErrNotInCowCache = errors.New("can't find object in cow cache")

// averageEncodedTxnSizeHint is an estimation for the encoded transaction size
// which is used for preallocating memory upfront in the payset. Preallocating
// helps to avoid re-allocating storage during the evaluation/validation which
// is considerably slower.
const averageEncodedTxnSizeHint = 150

// Creatable represent a single creatable object.
type creatable struct {
	cindex basics.CreatableIndex
	ctype  basics.CreatableType
}

// foundAddress is a wrapper for an address and a boolean.
type foundAddress struct {
	address basics.Address
	exists  bool
}

// cachedAppParams contains cached value and existence flag for app params
type cachedAppParams struct {
	value  basics.AppParams
	exists bool
}

// cachedAssetParams contains cached value and existence flag for asset params
type cachedAssetParams struct {
	value  basics.AssetParams
	exists bool
}

// cachedAppLocalState contains cached value and existence flag for app local state
type cachedAppLocalState struct {
	value  basics.AppLocalState
	exists bool
}

// cachedAssetHolding contains cached value and existence flag for asset holding
type cachedAssetHolding struct {
	value  basics.AssetHolding
	exists bool
}

type roundCowBase struct {
	l LedgerForCowBase

	// The round number of the previous block, for looking up prior state.
	rnd basics.Round

	// TxnCounter from previous block header.
	txnCount uint64

	// Round of the next expected compact cert.  In the common case this
	// is CompactCertNextRound from previous block header, except when
	// compact certs are first enabled, in which case this gets set
	// appropriately at the first block where compact certs are enabled.
	compactCertNextRnd basics.Round

	// The current protocol consensus params.
	proto config.ConsensusParams

	// The accounts that we're already accessed during this round evaluation. This is a caching
	// buffer used to avoid looking up the same account data more than once during a single evaluator
	// execution. The AccountData is always an historical one, then therefore won't be changing.
	// The underlying (accountupdates) infrastructure may provide additional cross-round caching which
	// are beyond the scope of this cache.
	// The account data store here is always the account data without the rewards.
	accounts map[basics.Address]ledgercore.AccountData

	// Similarly to accounts cache that stores base account data, there are caches for params, states, holdings.
	appParams      map[ledgercore.AccountApp]cachedAppParams
	assetParams    map[ledgercore.AccountAsset]cachedAssetParams
	appLocalStates map[ledgercore.AccountApp]cachedAppLocalState
	assets         map[ledgercore.AccountAsset]cachedAssetHolding

	// Similar cache for asset/app creators.
	creators map[creatable]foundAddress

	// Similar cache for kv entries. A nil entry means ledger has no such pair
	kvStore map[string]*string
}

func makeRoundCowBase(l LedgerForCowBase, rnd basics.Round, txnCount uint64, compactCertNextRnd basics.Round, proto config.ConsensusParams) *roundCowBase {
	return &roundCowBase{
		l:                  l,
		rnd:                rnd,
		txnCount:           txnCount,
		compactCertNextRnd: compactCertNextRnd,
		proto:              proto,
		accounts:           make(map[basics.Address]ledgercore.AccountData),
		appParams:          make(map[ledgercore.AccountApp]cachedAppParams),
		assetParams:        make(map[ledgercore.AccountAsset]cachedAssetParams),
		appLocalStates:     make(map[ledgercore.AccountApp]cachedAppLocalState),
		assets:             make(map[ledgercore.AccountAsset]cachedAssetHolding),
		creators:           make(map[creatable]foundAddress),
		kvStore:            make(map[string]*string),
	}
}

func (x *roundCowBase) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	creatable := creatable{cindex: cidx, ctype: ctype}

	if foundAddress, ok := x.creators[creatable]; ok {
		return foundAddress.address, foundAddress.exists, nil
	}

	address, exists, err := x.l.GetCreatorForRound(x.rnd, cidx, ctype)
	if err != nil {
		return basics.Address{}, false, fmt.Errorf(
			"roundCowBase.getCreator() cidx: %d ctype: %v err: %w", cidx, ctype, err)
	}

	x.creators[creatable] = foundAddress{address: address, exists: exists}
	return address, exists, nil
}

// lookup returns the non-rewarded account data for the provided account address. It uses the internal per-round cache
// first, and if it cannot find it there, it would defer to the underlaying implementation.
// note that errors in accounts data retrivals are not cached as these typically cause the transaction evaluation to fail.
func (x *roundCowBase) lookup(addr basics.Address) (ledgercore.AccountData, error) {
	if accountData, found := x.accounts[addr]; found {
		return accountData, nil
	}

	ad, _, err := x.l.LookupWithoutRewards(x.rnd, addr)
	if err != nil {
		return ledgercore.AccountData{}, err
	}

	x.accounts[addr] = ad
	return ad, err
}

func (x *roundCowBase) updateAssetResourceCache(aa ledgercore.AccountAsset, r ledgercore.AssetResource) {
	// cache AssetParams and AssetHolding returned by LookupResource
	if r.AssetParams == nil {
		x.assetParams[aa] = cachedAssetParams{exists: false}
	} else {
		x.assetParams[aa] = cachedAssetParams{value: *r.AssetParams, exists: true}
	}
	if r.AssetHolding == nil {
		x.assets[aa] = cachedAssetHolding{exists: false}
	} else {
		x.assets[aa] = cachedAssetHolding{value: *r.AssetHolding, exists: true}
	}
}

func (x *roundCowBase) updateAppResourceCache(aa ledgercore.AccountApp, r ledgercore.AppResource) {
	// cache AppParams and AppLocalState returned by LookupResource
	if r.AppParams == nil {
		x.appParams[aa] = cachedAppParams{exists: false}
	} else {
		x.appParams[aa] = cachedAppParams{value: *r.AppParams, exists: true}
	}
	if r.AppLocalState == nil {
		x.appLocalStates[aa] = cachedAppLocalState{exists: false}
	} else {
		x.appLocalStates[aa] = cachedAppLocalState{value: *r.AppLocalState, exists: true}
	}
}

func (x *roundCowBase) lookupAppParams(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppParamsDelta, bool, error) {
	aa := ledgercore.AccountApp{Address: addr, App: aidx}
	if result, ok := x.appParams[aa]; ok {
		if !result.exists {
			return ledgercore.AppParamsDelta{}, false, nil
		}
		return ledgercore.AppParamsDelta{Params: &result.value}, true, nil
	}

	if cacheOnly { // hasn't been found yet; we were asked not to query DB
		return ledgercore.AppParamsDelta{}, false, fmt.Errorf("lookupAppParams couldn't find addr %s aidx %d in cache: %w", addr.String(), aidx, ErrNotInCowCache)
	}

	resourceData, err := x.l.LookupApplication(x.rnd, addr, aidx)
	if err != nil {
		return ledgercore.AppParamsDelta{}, false, err
	}

	x.updateAppResourceCache(aa, resourceData)

	if resourceData.AppParams == nil {
		return ledgercore.AppParamsDelta{}, false, nil
	}
	return ledgercore.AppParamsDelta{Params: resourceData.AppParams}, true, nil
}

func (x *roundCowBase) lookupAssetParams(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetParamsDelta, bool, error) {
	aa := ledgercore.AccountAsset{Address: addr, Asset: aidx}
	if result, ok := x.assetParams[aa]; ok {
		if !result.exists {
			return ledgercore.AssetParamsDelta{}, false, nil
		}
		return ledgercore.AssetParamsDelta{Params: &result.value}, true, nil
	}

	if cacheOnly { // hasn't been found yet; we were asked not to query DB
		return ledgercore.AssetParamsDelta{}, false, fmt.Errorf("lookupAssetParams couldn't find addr %s aidx %d in cache: %w", addr.String(), aidx, ErrNotInCowCache)
	}

	resourceData, err := x.l.LookupAsset(x.rnd, addr, aidx)
	if err != nil {
		return ledgercore.AssetParamsDelta{}, false, err
	}

	x.updateAssetResourceCache(aa, resourceData)

	if resourceData.AssetParams == nil {
		return ledgercore.AssetParamsDelta{}, false, nil
	}
	return ledgercore.AssetParamsDelta{Params: resourceData.AssetParams}, true, nil
}

func (x *roundCowBase) lookupAppLocalState(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppLocalStateDelta, bool, error) {
	aa := ledgercore.AccountApp{Address: addr, App: aidx}
	if result, ok := x.appLocalStates[aa]; ok {
		if !result.exists {
			return ledgercore.AppLocalStateDelta{}, false, nil
		}
		return ledgercore.AppLocalStateDelta{LocalState: &result.value}, true, nil
	}

	if cacheOnly { // hasn't been found yet; we were asked not to query DB
		return ledgercore.AppLocalStateDelta{}, false, fmt.Errorf("lookupAppLocalState couldn't find addr %s aidx %d in cache: %w", addr.String(), aidx, ErrNotInCowCache)
	}

	resourceData, err := x.l.LookupApplication(x.rnd, addr, aidx)
	if err != nil {
		return ledgercore.AppLocalStateDelta{}, false, err
	}

	x.updateAppResourceCache(aa, resourceData)

	if resourceData.AppLocalState == nil {
		return ledgercore.AppLocalStateDelta{}, false, nil
	}
	return ledgercore.AppLocalStateDelta{LocalState: resourceData.AppLocalState}, true, nil
}

func (x *roundCowBase) lookupAssetHolding(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetHoldingDelta, bool, error) {
	aa := ledgercore.AccountAsset{Address: addr, Asset: aidx}
	if result, ok := x.assets[aa]; ok {
		if !result.exists {
			return ledgercore.AssetHoldingDelta{}, false, nil
		}
		return ledgercore.AssetHoldingDelta{Holding: &result.value}, true, nil
	}

	if cacheOnly { // hasn't been found yet; we were asked not to query DB
		return ledgercore.AssetHoldingDelta{}, false, fmt.Errorf("lookupAssetHolding couldn't find addr %s aidx %d in cache: %w", addr.String(), aidx, ErrNotInCowCache)
	}

	resourceData, err := x.l.LookupAsset(x.rnd, addr, aidx)
	if err != nil {
		return ledgercore.AssetHoldingDelta{}, false, err
	}

	x.updateAssetResourceCache(aa, resourceData)

	if resourceData.AssetHolding == nil {
		return ledgercore.AssetHoldingDelta{}, false, nil
	}
	return ledgercore.AssetHoldingDelta{Holding: resourceData.AssetHolding}, true, nil
}

func (x *roundCowBase) checkDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	return x.l.CheckDup(x.proto, x.rnd+1, firstValid, lastValid, txid, txl)
}

func (x *roundCowBase) Counter() uint64 {
	return x.txnCount
}

func (x *roundCowBase) compactCertNext() basics.Round {
	return x.compactCertNextRnd
}

func (x *roundCowBase) blockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return x.l.BlockHdr(r)
}

func (x *roundCowBase) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	// For global, check if app params exist
	if global {
		_, ok, err := x.lookupAppParams(addr, aidx, false)
		return ok, err
	}

	// Otherwise, check app local states
	_, ok, err := x.lookupAppLocalState(addr, aidx, false)
	return ok, err
}

// getKey gets the value for a particular key in some storage
// associated with an application globally or locally
func (x *roundCowBase) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	var err error
	exist := false
	kv := basics.TealKeyValue{}
	if global {
		var app ledgercore.AppParamsDelta
		app, exist, err = x.lookupAppParams(addr, aidx, false)
		if err != nil {
			return basics.TealValue{}, false, err
		}
		if app.Deleted {
			return basics.TealValue{}, false, fmt.Errorf("getKey: lookupAppParams returned deleted entry for (%s, %d, %v)", addr.String(), aidx, global)
		}
		if exist {
			kv = app.Params.GlobalState
		}
	} else {
		var ls ledgercore.AppLocalStateDelta
		ls, exist, err = x.lookupAppLocalState(addr, aidx, false)
		if err != nil {
			return basics.TealValue{}, false, err
		}
		if ls.Deleted {
			return basics.TealValue{}, false, fmt.Errorf("getKey: lookupAppLocalState returned deleted entry for (%s, %d, %v)", addr.String(), aidx, global)
		}

		if exist {
			kv = ls.LocalState.KeyValue
		}
	}
	if !exist {
		err = fmt.Errorf("cannot fetch key, %v", errNoStorage(addr, aidx, global))
		return basics.TealValue{}, false, err
	}

	val, exist := kv[key]
	return val, exist, nil
}

// getStorageCounts counts the storage types used by some account
// associated with an application globally or locally
func (x *roundCowBase) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	var err error
	count := basics.StateSchema{}
	exist := false
	kv := basics.TealKeyValue{}
	if global {
		var app ledgercore.AppParamsDelta
		app, exist, err = x.lookupAppParams(addr, aidx, false)
		if err != nil {
			return basics.StateSchema{}, err
		}
		if app.Deleted {
			return basics.StateSchema{}, fmt.Errorf("getStorageCounts: lookupAppParams returned deleted entry for (%s, %d, %v)", addr.String(), aidx, global)
		}
		if exist {
			kv = app.Params.GlobalState
		}
	} else {
		var ls ledgercore.AppLocalStateDelta
		ls, exist, err = x.lookupAppLocalState(addr, aidx, false)
		if err != nil {
			return basics.StateSchema{}, err
		}
		if ls.Deleted {
			return basics.StateSchema{}, fmt.Errorf("getStorageCounts: lookupAppLocalState returned deleted entry for (%s, %d, %v)", addr.String(), aidx, global)
		}
		if exist {
			kv = ls.LocalState.KeyValue
		}
	}
	if !exist {
		return count, nil
	}

	for _, v := range kv {
		if v.Type == basics.TealUintType {
			count.NumUint++
		} else {
			count.NumByteSlice++
		}
	}
	return count, nil
}

func (x *roundCowBase) getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	creator, exists, err := x.getCreator(basics.CreatableIndex(aidx), basics.AppCreatable)
	if err != nil {
		return basics.StateSchema{}, err
	}

	// App doesn't exist, so no storage may be allocated.
	if !exists {
		return basics.StateSchema{}, nil
	}

	params, ok, err := x.lookupAppParams(creator, aidx, false)
	if err != nil {
		return basics.StateSchema{}, err
	}
	if params.Deleted {
		return basics.StateSchema{}, fmt.Errorf("getStorageLimits: lookupAppParams returned deleted entry for (%s, %d, %v)", addr.String(), aidx, global)
	}
	if !ok {
		// This should never happen. If app exists then we should have
		// found the creator successfully.
		err = fmt.Errorf("app %d not found in account %s", aidx, creator.String())
		return basics.StateSchema{}, err
	}

	if global {
		return params.Params.GlobalStateSchema, nil
	}
	return params.Params.LocalStateSchema, nil
}

// wrappers for roundCowState to satisfy the (current) apply.Balances interface
func (cs *roundCowState) Get(addr basics.Address, withPendingRewards bool) (ledgercore.AccountData, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return ledgercore.AccountData{}, err
	}
	if withPendingRewards {
		acct = acct.WithUpdatedRewards(cs.proto, cs.rewardsLevel())
	}
	return acct, nil
}

func (cs *roundCowState) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return cs.getCreator(cidx, ctype)
}

func (cs *roundCowState) Put(addr basics.Address, acct ledgercore.AccountData) error {
	return cs.putAccount(addr, acct)
}

func (cs *roundCowState) CloseAccount(addr basics.Address) error {
	return cs.putAccount(addr, ledgercore.AccountData{})
}

func (cs *roundCowState) putAccount(addr basics.Address, acct ledgercore.AccountData) error {
	cs.mods.Accts.Upsert(addr, acct)
	return nil
}

func (cs *roundCowState) MinBalance(addr basics.Address, proto *config.ConsensusParams) (res basics.MicroAlgos, err error) {
	acct, err := cs.lookup(addr) // pending rewards unneeded
	if err != nil {
		return
	}
	return acct.MinBalance(proto), nil
}

func (cs *roundCowState) Move(from basics.Address, to basics.Address, amt basics.MicroAlgos, fromRewards *basics.MicroAlgos, toRewards *basics.MicroAlgos) error {
	rewardlvl := cs.rewardsLevel()

	fromBal, err := cs.lookup(from)
	if err != nil {
		return err
	}
	fromBalNew := fromBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if fromRewards != nil {
		var ot basics.OverflowTracker
		newFromRewards := ot.AddA(*fromRewards, ot.SubA(fromBalNew.MicroAlgos, fromBal.MicroAlgos))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of fromRewards for account %v: %d + (%d - %d)", from, *fromRewards, fromBalNew.MicroAlgos, fromBal.MicroAlgos)
		}
		*fromRewards = newFromRewards
	}

	var overflowed bool
	fromBalNew.MicroAlgos, overflowed = basics.OSubA(fromBalNew.MicroAlgos, amt)
	if overflowed {
		return fmt.Errorf("overspend (account %v, data %+v, tried to spend %v)", from, fromBal, amt)
	}
	err = cs.putAccount(from, fromBalNew)
	if err != nil {
		return err
	}

	toBal, err := cs.lookup(to)
	if err != nil {
		return err
	}
	toBalNew := toBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if toRewards != nil {
		var ot basics.OverflowTracker
		newToRewards := ot.AddA(*toRewards, ot.SubA(toBalNew.MicroAlgos, toBal.MicroAlgos))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of toRewards for account %v: %d + (%d - %d)", to, *toRewards, toBalNew.MicroAlgos, toBal.MicroAlgos)
		}
		*toRewards = newToRewards
	}

	toBalNew.MicroAlgos, overflowed = basics.OAddA(toBalNew.MicroAlgos, amt)
	if overflowed {
		return fmt.Errorf("balance overflow (account %v, data %+v, was going to receive %v)", to, toBal, amt)
	}
	err = cs.putAccount(to, toBalNew)
	if err != nil {
		return err
	}

	return nil
}

func (cs *roundCowState) ConsensusParams() config.ConsensusParams {
	return cs.proto
}

func (cs *roundCowState) compactCert(certRnd basics.Round, certType protocol.CompactCertType, cert compactcert.Cert, atRound basics.Round, validate bool) error {
	if certType != protocol.CompactCertBasic {
		return fmt.Errorf("compact cert type %d not supported", certType)
	}

	nextCertRnd := cs.compactCertNext()

	certHdr, err := cs.blockHdr(certRnd)
	if err != nil {
		return err
	}

	proto := config.Consensus[certHdr.CurrentProtocol]

	if validate {
		votersRnd := certRnd.SubSaturate(basics.Round(proto.CompactCertRounds))
		votersHdr, err := cs.blockHdr(votersRnd)
		if err != nil {
			return err
		}

		err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
		if err != nil {
			return err
		}
	}

	cs.setCompactCertNext(certRnd + basics.Round(proto.CompactCertRounds))
	return nil
}

// BlockEvaluator represents an in-progress evaluation of a block
// against the ledger.
type BlockEvaluator struct {
	state    *roundCowState
	validate bool
	generate bool

	prevHeader  bookkeeping.BlockHeader // cached
	proto       config.ConsensusParams
	genesisHash crypto.Digest

	block        bookkeeping.Block
	blockTxBytes int
	specials     transactions.SpecialAddresses

	blockGenerated bool // prevent repeated GenerateBlock calls

	l LedgerForEvaluator

	maxTxnBytesPerBlock int
}

// LedgerForEvaluator defines the ledger interface needed by the evaluator.
type LedgerForEvaluator interface {
	LedgerForCowBase
	GenesisHash() crypto.Digest
	GenesisProto() config.ConsensusParams
	LatestTotals() (basics.Round, ledgercore.AccountTotals, error)
	CompactCertVoters(basics.Round) (*ledgercore.VotersForRound, error)
}

// EvaluatorOptions defines the evaluator creation options
type EvaluatorOptions struct {
	PaysetHint          int
	Validate            bool
	Generate            bool
	MaxTxnBytesPerBlock int
	ProtoParams         *config.ConsensusParams
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate. If the length of the
// payset being evaluated is known in advance, a paysetHint >= 0 can be
// passed, avoiding unnecessary payset slice growth.
func StartEvaluator(l LedgerForEvaluator, hdr bookkeeping.BlockHeader, evalOpts EvaluatorOptions) (*BlockEvaluator, error) {
	var proto config.ConsensusParams
	if evalOpts.ProtoParams == nil {
		var ok bool
		proto, ok = config.Consensus[hdr.CurrentProtocol]
		if !ok {
			return nil, protocol.Error(hdr.CurrentProtocol)
		}
	} else {
		proto = *evalOpts.ProtoParams
	}

	// if the caller did not provide a valid block size limit, default to the consensus params defaults.
	if evalOpts.MaxTxnBytesPerBlock <= 0 || evalOpts.MaxTxnBytesPerBlock > proto.MaxTxnBytesPerBlock {
		evalOpts.MaxTxnBytesPerBlock = proto.MaxTxnBytesPerBlock
	}

	if hdr.Round == 0 {
		return nil, ErrRoundZero
	}

	prevHeader, err := l.BlockHdr(hdr.Round - 1)
	if err != nil {
		return nil, fmt.Errorf(
			"can't evaluate block %d without previous header: %v", hdr.Round, err)
	}

	prevProto, ok := config.Consensus[prevHeader.CurrentProtocol]
	if !ok {
		return nil, protocol.Error(prevHeader.CurrentProtocol)
	}

	// Round that lookups come from is previous block.  We validate
	// the block at this round below, so underflow will be caught.
	// If we are not validating, we must have previously checked
	// an agreement.Certificate attesting that hdr is valid.
	base := makeRoundCowBase(
		l, hdr.Round-1, prevHeader.TxnCounter, basics.Round(0), proto)

	eval := &BlockEvaluator{
		validate:   evalOpts.Validate,
		generate:   evalOpts.Generate,
		prevHeader: prevHeader,
		block:      bookkeeping.Block{BlockHeader: hdr},
		specials: transactions.SpecialAddresses{
			FeeSink:     hdr.FeeSink,
			RewardsPool: hdr.RewardsPool,
		},
		proto:               proto,
		genesisHash:         l.GenesisHash(),
		l:                   l,
		maxTxnBytesPerBlock: evalOpts.MaxTxnBytesPerBlock,
	}

	// Preallocate space for the payset so that we don't have to
	// dynamically grow a slice (if evaluating a whole block).
	if evalOpts.PaysetHint > 0 {
		maxPaysetHint := evalOpts.MaxTxnBytesPerBlock / averageEncodedTxnSizeHint
		if evalOpts.PaysetHint > maxPaysetHint {
			evalOpts.PaysetHint = maxPaysetHint
		}
		eval.block.Payset = make([]transactions.SignedTxnInBlock, 0, evalOpts.PaysetHint)
	}

	base.compactCertNextRnd = eval.prevHeader.CompactCert[protocol.CompactCertBasic].CompactCertNextRound

	// Check if compact certs are being enabled as of this block.
	if base.compactCertNextRnd == 0 && proto.CompactCertRounds != 0 {
		// Determine the first block that will contain a Merkle
		// commitment to the voters.  We need to account for the
		// fact that the voters come from CompactCertVotersLookback
		// rounds ago.
		votersRound := (hdr.Round + basics.Round(proto.CompactCertVotersLookback)).RoundUpToMultipleOf(basics.Round(proto.CompactCertRounds))

		// The first compact cert will appear CompactCertRounds after that.
		base.compactCertNextRnd = votersRound + basics.Round(proto.CompactCertRounds)
	}

	latestRound, prevTotals, err := l.LatestTotals()
	if err != nil {
		return nil, err
	}
	if latestRound != eval.prevHeader.Round {
		return nil, ledgercore.ErrNonSequentialBlockEval{EvaluatorRound: hdr.Round, LatestRound: latestRound}
	}

	poolAddr := eval.prevHeader.RewardsPool
	// get the reward pool account data without any rewards
	incentivePoolData, _, err := l.LookupWithoutRewards(eval.prevHeader.Round, poolAddr)
	if err != nil {
		return nil, err
	}

	// this is expected to be a no-op, but update the rewards on the rewards pool if it was configured to receive rewards ( unlike mainnet ).
	incentivePoolData = incentivePoolData.WithUpdatedRewards(prevProto, eval.prevHeader.RewardsLevel)

	if evalOpts.Generate {
		if eval.proto.SupportGenesisHash {
			eval.block.BlockHeader.GenesisHash = eval.genesisHash
		}
		eval.block.BlockHeader.RewardsState = eval.prevHeader.NextRewardsState(hdr.Round, proto, incentivePoolData.MicroAlgos, prevTotals.RewardUnits(), logging.Base())
	}
	// set the eval state with the current header
	eval.state = makeRoundCowState(base, eval.block.BlockHeader, proto, eval.prevHeader.TimeStamp, prevTotals, evalOpts.PaysetHint)

	if evalOpts.Validate {
		err := eval.block.BlockHeader.PreCheck(eval.prevHeader)
		if err != nil {
			return nil, err
		}

		// Check that the rewards rate, level and residue match expected values
		expectedRewardsState := eval.prevHeader.NextRewardsState(hdr.Round, proto, incentivePoolData.MicroAlgos, prevTotals.RewardUnits(), logging.Base())
		if eval.block.RewardsState != expectedRewardsState {
			return nil, fmt.Errorf("bad rewards state: %+v != %+v", eval.block.RewardsState, expectedRewardsState)
		}

		// For backwards compatibility: introduce Genesis Hash value
		if eval.proto.SupportGenesisHash && eval.block.BlockHeader.GenesisHash != eval.genesisHash {
			return nil, fmt.Errorf("wrong genesis hash: %s != %s", eval.block.BlockHeader.GenesisHash, eval.genesisHash)
		}
	}

	// Withdraw rewards from the incentive pool
	var ot basics.OverflowTracker
	rewardsPerUnit := ot.Sub(eval.block.BlockHeader.RewardsLevel, eval.prevHeader.RewardsLevel)
	if ot.Overflowed {
		return nil, fmt.Errorf("overflowed subtracting rewards(%d, %d) levels for block %v", eval.block.BlockHeader.RewardsLevel, eval.prevHeader.RewardsLevel, hdr.Round)
	}

	poolOld, err := eval.state.Get(poolAddr, true)
	if err != nil {
		return nil, err
	}

	// hotfix for testnet stall 08/26/2019; move some algos from testnet bank to rewards pool to give it enough time until protocol upgrade occur.
	// hotfix for testnet stall 11/07/2019; the same bug again, account ran out before the protocol upgrade occurred.
	poolOld, err = eval.workaroundOverspentRewards(poolOld, hdr.Round)
	if err != nil {
		return nil, err
	}

	poolNew := poolOld
	poolNew.MicroAlgos = ot.SubA(poolOld.MicroAlgos, basics.MicroAlgos{Raw: ot.Mul(prevTotals.RewardUnits(), rewardsPerUnit)})
	if ot.Overflowed {
		return nil, fmt.Errorf("overflowed subtracting reward unit for block %v", hdr.Round)
	}

	err = eval.state.Put(poolAddr, poolNew)
	if err != nil {
		return nil, err
	}

	// ensure that we have at least MinBalance after withdrawing rewards
	ot.SubA(poolNew.MicroAlgos, basics.MicroAlgos{Raw: proto.MinBalance})
	if ot.Overflowed {
		// TODO this should never happen; should we panic here?
		return nil, fmt.Errorf("overflowed subtracting rewards for block %v", hdr.Round)
	}

	return eval, nil
}

// hotfix for testnet stall 08/26/2019; move some algos from testnet bank to rewards pool to give it enough time until protocol upgrade occur.
// hotfix for testnet stall 11/07/2019; do the same thing
func (eval *BlockEvaluator) workaroundOverspentRewards(rewardPoolBalance ledgercore.AccountData, headerRound basics.Round) (poolOld ledgercore.AccountData, err error) {
	// verify that we patch the correct round.
	if headerRound != 1499995 && headerRound != 2926564 {
		return rewardPoolBalance, nil
	}
	// verify that we're patching the correct genesis ( i.e. testnet )
	testnetGenesisHash, _ := crypto.DigestFromString("JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA")
	if eval.genesisHash != testnetGenesisHash {
		return rewardPoolBalance, nil
	}

	// get the testnet bank ( dispenser ) account address.
	bankAddr, _ := basics.UnmarshalChecksumAddress("GD64YIY3TWGDMCNPP553DZPPR6LDUSFQOIJVFDPPXWEG3FVOJCCDBBHU5A")
	amount := basics.MicroAlgos{Raw: 20000000000}
	err = eval.state.Move(bankAddr, eval.prevHeader.RewardsPool, amount, nil, nil)
	if err != nil {
		err = fmt.Errorf("unable to move funds from testnet bank to incentive pool: %v", err)
		return
	}
	poolOld, err = eval.state.Get(eval.prevHeader.RewardsPool, true)

	return
}

// PaySetSize returns the number of top-level transactions that have been added to the block evaluator so far.
func (eval *BlockEvaluator) PaySetSize() int {
	return len(eval.block.Payset)
}

// Round returns the round number of the block being evaluated by the BlockEvaluator.
func (eval *BlockEvaluator) Round() basics.Round {
	return eval.block.Round()
}

// ResetTxnBytes resets the number of bytes tracked by the BlockEvaluator to
// zero.  This is a specialized operation used by the transaction pool to
// simulate the effect of putting pending transactions in multiple blocks.
func (eval *BlockEvaluator) ResetTxnBytes() {
	eval.blockTxBytes = 0
}

// TestTransactionGroup performs basic duplicate detection and well-formedness checks
// on a transaction group, but does not actually add the transactions to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) TestTransactionGroup(txgroup []transactions.SignedTxn) error {
	// Nothing to do if there are no transactions.
	if len(txgroup) == 0 {
		return nil
	}

	if len(txgroup) > eval.proto.MaxTxGroupSize {
		return fmt.Errorf("group size %d exceeds maximum %d", len(txgroup), eval.proto.MaxTxGroupSize)
	}

	cow := eval.state.child(len(txgroup))

	var group transactions.TxGroup
	for gi, txn := range txgroup {
		err := eval.TestTransaction(txn, cow)
		if err != nil {
			return err
		}

		// Make sure all transactions in group have the same group value
		if txn.Txn.Group != txgroup[0].Txn.Group {
			return fmt.Errorf("transactionGroup: inconsistent group values: %v != %v",
				txn.Txn.Group, txgroup[0].Txn.Group)
		}

		if !txn.Txn.Group.IsZero() {
			txWithoutGroup := txn.Txn
			txWithoutGroup.Group = crypto.Digest{}

			group.TxGroupHashes = append(group.TxGroupHashes, crypto.Digest(txWithoutGroup.ID()))
		} else if len(txgroup) > 1 {
			return fmt.Errorf("transactionGroup: [%d] had zero Group but was submitted in a group of %d", gi, len(txgroup))
		}
	}

	// If we had a non-zero Group value, check that all group members are present.
	if group.TxGroupHashes != nil {
		if txgroup[0].Txn.Group != crypto.HashObj(group) {
			return fmt.Errorf("transactionGroup: incomplete group: %v != %v (%v)",
				txgroup[0].Txn.Group, crypto.HashObj(group), group)
		}
	}

	return nil
}

// TestTransaction performs basic duplicate detection and well-formedness checks
// on a single transaction, but does not actually add the transaction to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) TestTransaction(txn transactions.SignedTxn, cow *roundCowState) error {
	// Transaction valid (not expired)?
	err := txn.Txn.Alive(eval.block)
	if err != nil {
		return err
	}

	err = txn.Txn.WellFormed(eval.specials, eval.proto)
	if err != nil {
		return fmt.Errorf("transaction %v: malformed: %v", txn.ID(), err)
	}

	// Transaction already in the ledger?
	txid := txn.ID()
	err = cow.checkDup(txn.Txn.First(), txn.Txn.Last(), txid, ledgercore.Txlease{Sender: txn.Txn.Sender, Lease: txn.Txn.Lease})
	if err != nil {
		return err
	}

	return nil
}

// Transaction tentatively adds a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) Transaction(txn transactions.SignedTxn, ad transactions.ApplyData) error {
	return eval.TransactionGroup([]transactions.SignedTxnWithAD{
		{
			SignedTxn: txn,
			ApplyData: ad,
		},
	})
}

// TransactionGroup tentatively adds a new transaction group as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) TransactionGroup(txads []transactions.SignedTxnWithAD) error {
	return eval.transactionGroup(txads)
}

// transactionGroup tentatively executes a group of transactions as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) transactionGroup(txgroup []transactions.SignedTxnWithAD) error {
	// Nothing to do if there are no transactions.
	if len(txgroup) == 0 {
		return nil
	}

	if len(txgroup) > eval.proto.MaxTxGroupSize {
		return fmt.Errorf("group size %d exceeds maximum %d", len(txgroup), eval.proto.MaxTxGroupSize)
	}

	var txibs []transactions.SignedTxnInBlock
	var group transactions.TxGroup
	var groupTxBytes int

	cow := eval.state.child(len(txgroup))
	evalParams := logic.NewEvalParams(txgroup, &eval.proto, &eval.specials)

	// Evaluate each transaction in the group
	txibs = make([]transactions.SignedTxnInBlock, 0, len(txgroup))
	for gi, txad := range txgroup {
		var txib transactions.SignedTxnInBlock

		err := eval.transaction(txad.SignedTxn, evalParams, gi, txad.ApplyData, cow, &txib)
		if err != nil {
			return err
		}

		txibs = append(txibs, txib)

		if eval.validate {
			groupTxBytes += txib.GetEncodedLength()
			if eval.blockTxBytes+groupTxBytes > eval.maxTxnBytesPerBlock {
				return ledgercore.ErrNoSpace
			}
		}

		// Make sure all transactions in group have the same group value
		if txad.SignedTxn.Txn.Group != txgroup[0].SignedTxn.Txn.Group {
			return fmt.Errorf("transactionGroup: inconsistent group values: %v != %v",
				txad.SignedTxn.Txn.Group, txgroup[0].SignedTxn.Txn.Group)
		}

		if !txad.SignedTxn.Txn.Group.IsZero() {
			txWithoutGroup := txad.SignedTxn.Txn
			txWithoutGroup.Group = crypto.Digest{}

			group.TxGroupHashes = append(group.TxGroupHashes, crypto.Digest(txWithoutGroup.ID()))
		} else if len(txgroup) > 1 {
			return fmt.Errorf("transactionGroup: [%d] had zero Group but was submitted in a group of %d", gi, len(txgroup))
		}
	}

	// If we had a non-zero Group value, check that all group members are present.
	if group.TxGroupHashes != nil {
		if txgroup[0].SignedTxn.Txn.Group != crypto.HashObj(group) {
			return fmt.Errorf("transactionGroup: incomplete group: %v != %v (%v)",
				txgroup[0].SignedTxn.Txn.Group, crypto.HashObj(group), group)
		}
	}

	eval.block.Payset = append(eval.block.Payset, txibs...)
	eval.blockTxBytes += groupTxBytes
	cow.commitToParent()

	return nil
}

// Check the minimum balance requirement for the modified accounts in `cow`.
func (eval *BlockEvaluator) checkMinBalance(cow *roundCowState) error {
	rewardlvl := cow.rewardsLevel()
	for _, addr := range cow.modifiedAccounts() {
		// Skip FeeSink, RewardsPool, and CompactCertSender MinBalance checks here.
		// There's only a few accounts, so space isn't an issue, and we don't
		// expect them to have low balances, but if they do, it may cause
		// surprises.
		if addr == eval.block.FeeSink || addr == eval.block.RewardsPool ||
			addr == transactions.CompactCertSender {
			continue
		}

		data, err := cow.lookup(addr)
		if err != nil {
			return err
		}

		// It's always OK to have the account move to an empty state,
		// because the accounts DB can delete it.  Otherwise, we will
		// enforce MinBalance.
		if data.IsZero() {
			continue
		}

		dataNew := data.WithUpdatedRewards(eval.proto, rewardlvl)
		effectiveMinBalance := dataNew.MinBalance(&eval.proto)
		if dataNew.MicroAlgos.Raw < effectiveMinBalance.Raw {
			return fmt.Errorf("account %v balance %d below min %d (%d assets)",
				addr, dataNew.MicroAlgos.Raw, effectiveMinBalance.Raw, dataNew.TotalAssets)
		}

		// Check if we have exceeded the maximum minimum balance
		if eval.proto.MaximumMinimumBalance != 0 {
			if effectiveMinBalance.Raw > eval.proto.MaximumMinimumBalance {
				return fmt.Errorf("account %v would use too much space after this transaction. Minimum balance requirements would be %d (greater than max %d)", addr, effectiveMinBalance.Raw, eval.proto.MaximumMinimumBalance)
			}
		}
	}

	return nil
}

// transaction tentatively executes a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) transaction(txn transactions.SignedTxn, evalParams *logic.EvalParams, gi int, ad transactions.ApplyData, cow *roundCowState, txib *transactions.SignedTxnInBlock) error {
	var err error

	// Only compute the TxID once
	txid := txn.ID()

	if eval.validate {
		err = txn.Txn.Alive(eval.block)
		if err != nil {
			return err
		}

		// Transaction already in the ledger?
		err := cow.checkDup(txn.Txn.First(), txn.Txn.Last(), txid, ledgercore.Txlease{Sender: txn.Txn.Sender, Lease: txn.Txn.Lease})
		if err != nil {
			return err
		}

		// Does the address that authorized the transaction actually match whatever address the sender has rekeyed to?
		// i.e., the sig/lsig/msig was checked against the txn.Authorizer() address, but does this match the sender's balrecord.AuthAddr?
		acctdata, err := cow.lookup(txn.Txn.Sender)
		if err != nil {
			return err
		}
		correctAuthorizer := acctdata.AuthAddr
		if (correctAuthorizer == basics.Address{}) {
			correctAuthorizer = txn.Txn.Sender
		}
		if txn.Authorizer() != correctAuthorizer {
			return fmt.Errorf("transaction %v: should have been authorized by %v but was actually authorized by %v", txn.ID(), correctAuthorizer, txn.Authorizer())
		}
	}

	// Apply the transaction, updating the cow balances
	applyData, err := eval.applyTransaction(txn.Txn, cow, evalParams, gi, cow.Counter())
	if err != nil {
		return fmt.Errorf("transaction %v: %v", txid, err)
	}

	// Validate applyData if we are validating an existing block.
	// If we are validating and generating, we have no ApplyData yet.
	if eval.validate && !eval.generate {
		if eval.proto.ApplyData {
			if !ad.Equal(applyData) {
				return fmt.Errorf("transaction %v: applyData mismatch: %v != %v", txid, ad, applyData)
			}
		} else {
			if !ad.Equal(transactions.ApplyData{}) {
				return fmt.Errorf("transaction %v: applyData not supported", txid)
			}
		}
	}

	// Check if the transaction fits in the block, now that we can encode it.
	*txib, err = eval.block.EncodeSignedTxn(txn, applyData)
	if err != nil {
		return err
	}

	// Check if any affected accounts dipped below MinBalance (unless they are
	// completely zero, which means the account will be deleted.)
	// Only do those checks if we are validating or generating. It is useful to skip them
	// if we cannot provide account data that contains enough information to
	// compute the correct minimum balance (the case with indexer which does not store it).
	if eval.validate || eval.generate {
		err := eval.checkMinBalance(cow)
		if err != nil {
			return fmt.Errorf("transaction %v: %w", txid, err)
		}
	}

	// Remember this txn
	cow.addTx(txn.Txn, txid)

	return nil
}

// applyTransaction changes the balances according to this transaction.
func (eval *BlockEvaluator) applyTransaction(tx transactions.Transaction, balances *roundCowState, evalParams *logic.EvalParams, gi int, ctr uint64) (ad transactions.ApplyData, err error) {
	params := balances.ConsensusParams()

	// move fee to pool
	err = balances.Move(tx.Sender, eval.specials.FeeSink, tx.Fee, &ad.SenderRewards, nil)
	if err != nil {
		return
	}

	err = apply.Rekey(balances, &tx)
	if err != nil {
		return
	}

	switch tx.Type {
	case protocol.PaymentTx:
		err = apply.Payment(tx.PaymentTxnFields, tx.Header, balances, eval.specials, &ad)

	case protocol.KeyRegistrationTx:
		err = apply.Keyreg(tx.KeyregTxnFields, tx.Header, balances, eval.specials, &ad, balances.Round())

	case protocol.AssetConfigTx:
		err = apply.AssetConfig(tx.AssetConfigTxnFields, tx.Header, balances, eval.specials, &ad, ctr)

	case protocol.AssetTransferTx:
		err = apply.AssetTransfer(tx.AssetTransferTxnFields, tx.Header, balances, eval.specials, &ad)

	case protocol.AssetFreezeTx:
		err = apply.AssetFreeze(tx.AssetFreezeTxnFields, tx.Header, balances, eval.specials, &ad)

	case protocol.ApplicationCallTx:
		err = apply.ApplicationCall(tx.ApplicationCallTxnFields, tx.Header, balances, &ad, gi, evalParams, ctr)

	case protocol.CompactCertTx:
		// in case of a CompactCertTx transaction, we want to "apply" it only in validate or generate mode. This will deviate the cow's CompactCertNext depending of
		// whether we're in validate/generate mode or not, however - given that this variable in only being used in these modes, it would be safe.
		// The reason for making this into an exception is that during initialization time, the accounts update is "converting" the recent 320 blocks into deltas to
		// be stored in memory. These deltas don't care about the compact certificate, and so we can improve the node load time. Additionally, it save us from
		// performing the validation during catchup, which is another performance boost.
		if eval.validate || eval.generate {
			err = balances.compactCert(tx.CertRound, tx.CertType, tx.Cert, tx.Header.FirstValid, eval.validate)
		}

	default:
		err = fmt.Errorf("unknown transaction type %v", tx.Type)
	}

	// Record first, so that details can all be used in logic evaluation, even
	// if cleared below. For example, `gaid`, introduced in v28 is now
	// implemented in terms of the AD fields introduced in v30.
	evalParams.RecordAD(gi, ad)

	// If the protocol does not support rewards in ApplyData,
	// clear them out.
	if !params.RewardsInApplyData {
		ad.SenderRewards = basics.MicroAlgos{}
		ad.ReceiverRewards = basics.MicroAlgos{}
		ad.CloseRewards = basics.MicroAlgos{}
	}

	// No separate config for activating these AD fields because inner
	// transactions require their presence, so the consensus update to add
	// inners also stores these IDs.
	if params.MaxInnerTransactions == 0 {
		ad.ApplicationID = 0
		ad.ConfigAsset = 0
	}

	return
}

// compactCertVotersAndTotal returns the expected values of CompactCertVoters
// and CompactCertVotersTotal for a block.
func (eval *BlockEvaluator) compactCertVotersAndTotal() (root crypto.GenericDigest, total basics.MicroAlgos, err error) {
	if eval.proto.CompactCertRounds == 0 {
		return
	}

	if eval.block.Round()%basics.Round(eval.proto.CompactCertRounds) != 0 {
		return
	}

	lookback := eval.block.Round().SubSaturate(basics.Round(eval.proto.CompactCertVotersLookback))
	voters, err := eval.l.CompactCertVoters(lookback)
	if err != nil {
		return
	}

	if voters != nil {
		root, total = voters.Tree.Root(), voters.TotalWeight
	}

	return
}

// TestingTxnCounter - the method returns the current evaluator transaction counter. The method is used for testing purposes only.
func (eval *BlockEvaluator) TestingTxnCounter() uint64 {
	return eval.state.Counter()
}

// Call "endOfBlock" after all the block's rewards and transactions are processed.
func (eval *BlockEvaluator) endOfBlock() error {
	if eval.generate {
		var err error
		eval.block.TxnCommitments, err = eval.block.PaysetCommit()
		if err != nil {
			return err
		}

		if eval.proto.TxnCounter {
			eval.block.TxnCounter = eval.state.Counter()
		} else {
			eval.block.TxnCounter = 0
		}

		eval.generateExpiredOnlineAccountsList()

		if eval.proto.CompactCertRounds > 0 {
			var basicCompactCert bookkeeping.CompactCertState
			basicCompactCert.CompactCertVoters, basicCompactCert.CompactCertVotersTotal, err = eval.compactCertVotersAndTotal()
			if err != nil {
				return err
			}

			basicCompactCert.CompactCertNextRound = eval.state.compactCertNext()

			eval.block.CompactCert = make(map[protocol.CompactCertType]bookkeeping.CompactCertState)
			eval.block.CompactCert[protocol.CompactCertBasic] = basicCompactCert
		}
	}

	err := eval.validateExpiredOnlineAccounts()
	if err != nil {
		return err
	}

	err = eval.resetExpiredOnlineAccountsParticipationKeys()
	if err != nil {
		return err
	}

	eval.state.mods.OptimizeAllocatedMemory(eval.proto)

	if eval.validate {
		// check commitments
		txnRoot, err := eval.block.PaysetCommit()
		if err != nil {
			return err
		}
		if txnRoot != eval.block.TxnCommitments {
			return fmt.Errorf("txn root wrong: %v != %v", txnRoot, eval.block.TxnCommitments)
		}

		var expectedTxnCount uint64
		if eval.proto.TxnCounter {
			expectedTxnCount = eval.state.Counter()
		}
		if eval.block.TxnCounter != expectedTxnCount {
			return fmt.Errorf("txn count wrong: %d != %d", eval.block.TxnCounter, expectedTxnCount)
		}

		expectedVoters, expectedVotersWeight, err := eval.compactCertVotersAndTotal()
		if err != nil {
			return err
		}
		if !eval.block.CompactCert[protocol.CompactCertBasic].CompactCertVoters.IsEqual(expectedVoters) {
			return fmt.Errorf("CompactCertVoters wrong: %v != %v", eval.block.CompactCert[protocol.CompactCertBasic].CompactCertVoters, expectedVoters)
		}
		if eval.block.CompactCert[protocol.CompactCertBasic].CompactCertVotersTotal != expectedVotersWeight {
			return fmt.Errorf("CompactCertVotersTotal wrong: %v != %v", eval.block.CompactCert[protocol.CompactCertBasic].CompactCertVotersTotal, expectedVotersWeight)
		}
		if eval.block.CompactCert[protocol.CompactCertBasic].CompactCertNextRound != eval.state.compactCertNext() {
			return fmt.Errorf("CompactCertNextRound wrong: %v != %v", eval.block.CompactCert[protocol.CompactCertBasic].CompactCertNextRound, eval.state.compactCertNext())
		}
		for ccType := range eval.block.CompactCert {
			if ccType != protocol.CompactCertBasic {
				return fmt.Errorf("CompactCertType %d unexpected", ccType)
			}
		}
	}

	err = eval.state.CalculateTotals()
	if err != nil {
		return err
	}

	return nil
}

// generateExpiredOnlineAccountsList creates the list of the expired participation accounts by traversing over the
// modified accounts in the state deltas and testing if any of them needs to be reset.
func (eval *BlockEvaluator) generateExpiredOnlineAccountsList() {
	if !eval.generate {
		return
	}
	// We are going to find the list of modified accounts and the
	// current round that is being evaluated.
	// Then we are going to go through each modified account and
	// see if it meets the criteria for adding it to the expired
	// participation accounts list.
	modifiedAccounts := eval.state.modifiedAccounts()
	currentRound := eval.Round()

	expectedMaxNumberOfExpiredAccounts := eval.proto.MaxProposedExpiredOnlineAccounts

	for i := 0; i < len(modifiedAccounts) && len(eval.block.ParticipationUpdates.ExpiredParticipationAccounts) < expectedMaxNumberOfExpiredAccounts; i++ {
		accountAddr := modifiedAccounts[i]
		acctDelta, found := eval.state.mods.Accts.GetData(accountAddr)
		if !found {
			continue
		}

		// true if the account is online
		isOnline := acctDelta.Status == basics.Online
		// true if the accounts last valid round has passed
		pastCurrentRound := acctDelta.VoteLastValid < currentRound

		if isOnline && pastCurrentRound {
			eval.block.ParticipationUpdates.ExpiredParticipationAccounts = append(
				eval.block.ParticipationUpdates.ExpiredParticipationAccounts,
				accountAddr,
			)
		}
	}
}

// validateExpiredOnlineAccounts tests the expired online accounts specified in ExpiredParticipationAccounts, and verify
// that they have all expired and need to be reset.
func (eval *BlockEvaluator) validateExpiredOnlineAccounts() error {
	if !eval.validate {
		return nil
	}
	expectedMaxNumberOfExpiredAccounts := eval.proto.MaxProposedExpiredOnlineAccounts
	lengthOfExpiredParticipationAccounts := len(eval.block.ParticipationUpdates.ExpiredParticipationAccounts)

	// If the length of the array is strictly greater than our max then we have an error.
	// This works when the expected number of accounts is zero (i.e. it is disabled) as well
	if lengthOfExpiredParticipationAccounts > expectedMaxNumberOfExpiredAccounts {
		return fmt.Errorf("length of expired accounts (%d) was greater than expected (%d)",
			lengthOfExpiredParticipationAccounts, expectedMaxNumberOfExpiredAccounts)
	}

	// For security reasons, we need to make sure that all addresses in the expired participation accounts
	// are unique.  We make this map to keep track of previously seen address
	addressSet := make(map[basics.Address]bool, lengthOfExpiredParticipationAccounts)

	// Validate that all expired accounts meet the current criteria
	currentRound := eval.Round()
	for _, accountAddr := range eval.block.ParticipationUpdates.ExpiredParticipationAccounts {

		if _, exists := addressSet[accountAddr]; exists {
			// We shouldn't have duplicate addresses...
			return fmt.Errorf("duplicate address found: %v", accountAddr)
		}

		// Record that we have seen this address
		addressSet[accountAddr] = true

		acctData, err := eval.state.lookup(accountAddr)
		if err != nil {
			return fmt.Errorf("endOfBlock was unable to retrieve account %v : %w", accountAddr, err)
		}

		// true if the account is online
		isOnline := acctData.Status == basics.Online
		// true if the accounts last valid round has passed
		pastCurrentRound := acctData.VoteLastValid < currentRound

		if !isOnline {
			return fmt.Errorf("endOfBlock found %v was not online but %v", accountAddr, acctData.Status)
		}

		if !pastCurrentRound {
			return fmt.Errorf("endOfBlock found %v round (%d) was not less than current round (%d)", accountAddr, acctData.VoteLastValid, currentRound)
		}
	}
	return nil
}

// resetExpiredOnlineAccountsParticipationKeys after all transactions and rewards are processed, modify the accounts so that their status is offline
func (eval *BlockEvaluator) resetExpiredOnlineAccountsParticipationKeys() error {
	expectedMaxNumberOfExpiredAccounts := eval.proto.MaxProposedExpiredOnlineAccounts
	lengthOfExpiredParticipationAccounts := len(eval.block.ParticipationUpdates.ExpiredParticipationAccounts)

	// If the length of the array is strictly greater than our max then we have an error.
	// This works when the expected number of accounts is zero (i.e. it is disabled) as well
	if lengthOfExpiredParticipationAccounts > expectedMaxNumberOfExpiredAccounts {
		return fmt.Errorf("length of expired accounts (%d) was greater than expected (%d)",
			lengthOfExpiredParticipationAccounts, expectedMaxNumberOfExpiredAccounts)
	}

	for _, accountAddr := range eval.block.ParticipationUpdates.ExpiredParticipationAccounts {
		acctData, err := eval.state.lookup(accountAddr)
		if err != nil {
			return fmt.Errorf("resetExpiredOnlineAccountsParticipationKeys was unable to retrieve account %v : %w", accountAddr, err)
		}

		// Reset the appropriate account data
		acctData.ClearOnlineState()

		// Update the account information
		err = eval.state.putAccount(accountAddr, acctData)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateBlock produces a complete block from the BlockEvaluator.  This is
// used during proposal to get an actual block that will be proposed, after
// feeding in tentative transactions into this block evaluator.
//
// After a call to GenerateBlock, the BlockEvaluator can still be used to
// accept transactions.  However, to guard against reuse, subsequent calls
// to GenerateBlock on the same BlockEvaluator will fail.
func (eval *BlockEvaluator) GenerateBlock() (*ledgercore.ValidatedBlock, error) {
	if !eval.generate {
		logging.Base().Panicf("GenerateBlock() called but generate is false")
	}

	if eval.blockGenerated {
		return nil, fmt.Errorf("GenerateBlock already called on this BlockEvaluator")
	}

	err := eval.endOfBlock()
	if err != nil {
		return nil, err
	}

	vb := ledgercore.MakeValidatedBlock(eval.block, eval.state.deltas())
	eval.blockGenerated = true
	proto, ok := config.Consensus[eval.block.BlockHeader.CurrentProtocol]
	if !ok {
		return nil, fmt.Errorf(
			"unknown consensus version: %s", eval.block.BlockHeader.CurrentProtocol)
	}
	eval.state = makeRoundCowState(
		eval.state, eval.block.BlockHeader, proto, eval.prevHeader.TimeStamp, eval.state.mods.Totals,
		len(eval.block.Payset))
	return &vb, nil
}

type evalTxValidator struct {
	txcache          verify.VerifiedTransactionCache
	block            bookkeeping.Block
	verificationPool execpool.BacklogPool

	ctx      context.Context
	txgroups [][]transactions.SignedTxnWithAD
	done     chan error
}

func (validator *evalTxValidator) run() {
	defer close(validator.done)
	specialAddresses := transactions.SpecialAddresses{
		FeeSink:     validator.block.BlockHeader.FeeSink,
		RewardsPool: validator.block.BlockHeader.RewardsPool,
	}

	var unverifiedTxnGroups [][]transactions.SignedTxn
	unverifiedTxnGroups = make([][]transactions.SignedTxn, 0, len(validator.txgroups))
	for _, group := range validator.txgroups {
		signedTxnGroup := make([]transactions.SignedTxn, len(group))
		for j, txn := range group {
			signedTxnGroup[j] = txn.SignedTxn
			err := txn.SignedTxn.Txn.Alive(validator.block)
			if err != nil {
				validator.done <- err
				return
			}
		}
		unverifiedTxnGroups = append(unverifiedTxnGroups, signedTxnGroup)
	}

	unverifiedTxnGroups = validator.txcache.GetUnverifiedTranscationGroups(unverifiedTxnGroups, specialAddresses, validator.block.BlockHeader.CurrentProtocol)

	err := verify.PaysetGroups(validator.ctx, unverifiedTxnGroups, validator.block.BlockHeader, validator.verificationPool, validator.txcache)
	if err != nil {
		validator.done <- err
	}
}

// Eval is the main evaluator entrypoint (in addition to StartEvaluator)
// used by Ledger.Validate() Ledger.AddBlock() Ledger.trackerEvalVerified()(accountUpdates.loadFromDisk())
//
// Validate: Eval(ctx, l, blk, true, txcache, executionPool)
// AddBlock: Eval(context.Background(), l, blk, false, txcache, nil)
// tracker:  Eval(context.Background(), l, blk, false, txcache, nil)
func Eval(ctx context.Context, l LedgerForEvaluator, blk bookkeeping.Block, validate bool, txcache verify.VerifiedTransactionCache, executionPool execpool.BacklogPool) (ledgercore.StateDelta, error) {
	eval, err := StartEvaluator(l, blk.BlockHeader,
		EvaluatorOptions{
			PaysetHint: len(blk.Payset),
			Validate:   validate,
			Generate:   false,
		})
	if err != nil {
		return ledgercore.StateDelta{}, err
	}

	validationCtx, validationCancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		validationCancel()
		wg.Wait()
	}()

	// Next, transactions
	paysetgroups, err := blk.DecodePaysetGroups()
	if err != nil {
		return ledgercore.StateDelta{}, err
	}

	accountLoadingCtx, accountLoadingCancel := context.WithCancel(ctx)
	preloadedTxnsData := prefetcher.PrefetchAccounts(accountLoadingCtx, l, blk.Round()-1, paysetgroups, blk.BlockHeader.FeeSink, blk.ConsensusProtocol())
	// ensure that before we exit from this method, the account loading is no longer active.
	defer func() {
		accountLoadingCancel()
		// wait for the paysetgroupsCh to get closed.
		for range preloadedTxnsData {
		}
	}()

	var txvalidator evalTxValidator
	if validate {
		_, ok := config.Consensus[blk.CurrentProtocol]
		if !ok {
			return ledgercore.StateDelta{}, protocol.Error(blk.CurrentProtocol)
		}
		txvalidator.txcache = txcache
		txvalidator.block = blk
		txvalidator.verificationPool = executionPool

		txvalidator.ctx = validationCtx
		txvalidator.txgroups = paysetgroups
		txvalidator.done = make(chan error, 1)
		go txvalidator.run()
	}

	base := eval.state.lookupParent.(*roundCowBase)
transactionGroupLoop:
	for {
		select {
		case txgroup, ok := <-preloadedTxnsData:
			if !ok {
				break transactionGroupLoop
			} else if txgroup.Err != nil {
				return ledgercore.StateDelta{}, txgroup.Err
			}

			for _, br := range txgroup.Accounts {
				if _, have := base.accounts[*br.Address]; !have {
					base.accounts[*br.Address] = *br.Data
				}
			}
			for _, lr := range txgroup.Resources {
				if lr.Address == nil {
					// we attempted to look for the creator, and failed.
					base.creators[creatable{cindex: lr.CreatableIndex, ctype: lr.CreatableType}] =
						foundAddress{exists: false}
					continue
				}
				if lr.CreatableType == basics.AssetCreatable {
					if lr.Resource.AssetHolding != nil {
						base.assets[ledgercore.AccountAsset{Address: *lr.Address, Asset: basics.AssetIndex(lr.CreatableIndex)}] = cachedAssetHolding{value: *lr.Resource.AssetHolding, exists: true}
					} else {
						base.assets[ledgercore.AccountAsset{Address: *lr.Address, Asset: basics.AssetIndex(lr.CreatableIndex)}] = cachedAssetHolding{exists: false}
					}
					if lr.Resource.AssetParams != nil {
						base.assetParams[ledgercore.AccountAsset{Address: *lr.Address, Asset: basics.AssetIndex(lr.CreatableIndex)}] = cachedAssetParams{value: *lr.Resource.AssetParams, exists: true}
						base.creators[creatable{cindex: lr.CreatableIndex, ctype: basics.AssetCreatable}] = foundAddress{address: *lr.Address, exists: true}
					} else {
						base.assetParams[ledgercore.AccountAsset{Address: *lr.Address, Asset: basics.AssetIndex(lr.CreatableIndex)}] = cachedAssetParams{exists: false}

					}
				} else {
					if lr.Resource.AppLocalState != nil {
						base.appLocalStates[ledgercore.AccountApp{Address: *lr.Address, App: basics.AppIndex(lr.CreatableIndex)}] = cachedAppLocalState{value: *lr.Resource.AppLocalState, exists: true}
					} else {
						base.appLocalStates[ledgercore.AccountApp{Address: *lr.Address, App: basics.AppIndex(lr.CreatableIndex)}] = cachedAppLocalState{exists: false}
					}
					if lr.Resource.AppParams != nil {
						base.appParams[ledgercore.AccountApp{Address: *lr.Address, App: basics.AppIndex(lr.CreatableIndex)}] = cachedAppParams{value: *lr.Resource.AppParams, exists: true}
						base.creators[creatable{cindex: lr.CreatableIndex, ctype: basics.AppCreatable}] = foundAddress{address: *lr.Address, exists: true}
					} else {
						base.appParams[ledgercore.AccountApp{Address: *lr.Address, App: basics.AppIndex(lr.CreatableIndex)}] = cachedAppParams{exists: false}
					}
				}
			}
			err = eval.TransactionGroup(txgroup.TxnGroup)
			if err != nil {
				return ledgercore.StateDelta{}, err
			}
		case <-ctx.Done():
			return ledgercore.StateDelta{}, ctx.Err()
		case err, open := <-txvalidator.done:
			// if we're not validating, then `txvalidator.done` would be nil, in which case this case statement would never be executed.
			if open && err != nil {
				return ledgercore.StateDelta{}, err
			}
		}
	}

	// Finally, process any pending end-of-block state changes.
	err = eval.endOfBlock()
	if err != nil {
		return ledgercore.StateDelta{}, err
	}

	// If validating, do final block checks that depend on our new state
	if validate {
		// wait for the signature validation to complete.
		select {
		case <-ctx.Done():
			return ledgercore.StateDelta{}, ctx.Err()
		case err, open := <-txvalidator.done:
			if !open {
				break
			}
			if err != nil {
				return ledgercore.StateDelta{}, err
			}
		}
	}

	return eval.state.deltas(), nil
}
