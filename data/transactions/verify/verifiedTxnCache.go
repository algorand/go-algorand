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

package verify

import (
	"errors"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

const entriesPerBucket = 8179 // the default bucket size; a prime number could promote a lower hash collisions in case the hash function isn't perfect.
const maxPinnedEntries = 500000

// VerifiedTxnCacheError helps to identifiy the errors of a cache error and diffrenciate these from a general verification errors.
type VerifiedTxnCacheError struct {
	inner error
}

// Unwrap provides accesss to the underlying error
func (e *VerifiedTxnCacheError) Unwrap() error {
	return e.inner
}

// Error formats the underlying error message
func (e *VerifiedTxnCacheError) Error() string {
	return e.inner.Error()
}

// errTooManyPinnedEntries is being generated when we attempt to pin an transaction while we've already exceeded the maximum number of allows
// transactions in the verification cache.
var errTooManyPinnedEntries = &VerifiedTxnCacheError{errors.New("Too many pinned entries")}

// errMissingPinnedEntry is being generated when we're trying to pin a transaction that does not appear in the cache
var errMissingPinnedEntry = &VerifiedTxnCacheError{errors.New("Missing pinned entry")}

// VerifiedTransactionCache provides a cached store of recently verified transactions. The cache is desiged two have two separate "levels". On the
// bottom tier, the cache would be using a cyclic buffer, where old transactions would end up overridden by new ones. In order to support transactions
// that goes into the transaction pool, we have a higher tier of pinned cache. Pinned transactions would not be cycled-away by new incoming transactions,
// and would only get eliminated by updates to the transaction pool, which would inform the cache of updates to the pinned items.
type VerifiedTransactionCache interface {
	// Add adds a given transaction group and it's associated group context to the cache. If any of the transactions already appear
	// in the cache, the new entry overrides the old one.
	Add(txgroup []transactions.SignedTxn, groupCtx *GroupContext)
	// AddPayset works in a similar way to Add, but is intended for adding an array of transaction groups, along with their corresponding contexts.
	AddPayset(txgroup [][]transactions.SignedTxn, groupCtxs []*GroupContext) error
	// GetUnverifiedTranscationGroups compares the provided payset against the currently cached transactions and figure which transaction groups aren't fully cached.
	GetUnverifiedTranscationGroups(payset [][]transactions.SignedTxn, CurrSpecAddrs transactions.SpecialAddresses, CurrProto protocol.ConsensusVersion) [][]transactions.SignedTxn
	// UpdatePinned replaces the pinned entries with the one provided in the pinnedTxns map. This is typically expected to be a subset of the
	// already-pinned transactions. If a transaction is not currently pinned, and it's can't be found in the cache, a errMissingPinnedEntry error would be generated.
	UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) error
	// Pin function would mark the given transaction group as pinned.
	Pin(txgroup []transactions.SignedTxn) error
	// PinGroups function would mark the given transaction groups as pinned.
	PinGroups(txgroups []transactions.SignedTxGroup) error
}

// verifiedTransactionCache provides an implementation of the VerifiedTransactionCache interface
type verifiedTransactionCache struct {
	// bucketsLock is the lock for syncornizing the access to the cache
	bucketsLock deadlock.Mutex
	// buckets is the circular cache buckets buffer
	buckets []map[transactions.Txid]*GroupContext
	// pinned is the pinned transactions entries map.
	pinned map[transactions.Txid]*GroupContext
	// base is the index into the buckets array where the next transaction entry would be written.
	base int
}

// MakeVerifiedTransactionCache creates an instance of verifiedTransactionCache and returns it.
func MakeVerifiedTransactionCache(cacheSize int) VerifiedTransactionCache {
	bucketsCount := 1 + (cacheSize / entriesPerBucket)
	impl := &verifiedTransactionCache{
		buckets: make([]map[transactions.Txid]*GroupContext, bucketsCount),
		pinned:  make(map[transactions.Txid]*GroupContext, cacheSize),
		base:    0,
	}
	for i := 0; i < bucketsCount; i++ {
		impl.buckets[i] = make(map[transactions.Txid]*GroupContext, entriesPerBucket)
	}
	return impl
}

// Add adds a given transaction group and it's associated group context to the cache. If any of the transactions already appear
// in the cache, the new entry overrides the old one.
func (v *verifiedTransactionCache) Add(txgroup []transactions.SignedTxn, groupCtx *GroupContext) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	v.add(txgroup, groupCtx)
}

// AddPayset works in a similar way to Add, but is intended for adding an array of transaction groups, along with their corresponding contexts.
func (v *verifiedTransactionCache) AddPayset(txgroup [][]transactions.SignedTxn, groupCtxs []*GroupContext) error {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	for i := range txgroup {
		v.add(txgroup[i], groupCtxs[i])
	}
	return nil
}

// GetUnverifiedTranscationGroups compares the provided payset against the currently cached transactions and figure which transaction groups aren't fully cached.
func (v *verifiedTransactionCache) GetUnverifiedTranscationGroups(txnGroups [][]transactions.SignedTxn, currSpecAddrs transactions.SpecialAddresses, currProto protocol.ConsensusVersion) (unverifiedGroups [][]transactions.SignedTxn) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	groupCtx := &GroupContext{
		specAddrs:        currSpecAddrs,
		consensusVersion: currProto,
	}
	unverifiedGroups = make([][]transactions.SignedTxn, 0, len(txnGroups))

	for txnGroupIndex := 0; txnGroupIndex < len(txnGroups); txnGroupIndex++ {
		signedTxnGroup := txnGroups[txnGroupIndex]
		verifiedTxn := 0
		groupCtx.minTealVersion = logic.ComputeMinTealVersion(signedTxnGroup)

		baseBucket := v.base
		for txnIdx := 0; txnIdx < len(signedTxnGroup); txnIdx++ {
			txn := &signedTxnGroup[txnIdx]
			id := txn.Txn.ID()
			// check pinned first
			entryGroup := v.pinned[id]
			// if not found in the pinned map, try to find in the verified buckets:
			if entryGroup == nil {
				// try to look in the previously verified buckets.
				// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
				for offsetBucketIdx := baseBucket + len(v.buckets); offsetBucketIdx > baseBucket; offsetBucketIdx-- {
					bucketIdx := offsetBucketIdx % len(v.buckets)
					if params, has := v.buckets[bucketIdx][id]; has {
						entryGroup = params
						baseBucket = bucketIdx
						break
					}
				}
			}

			if entryGroup == nil {
				break
			}

			if !entryGroup.Equal(groupCtx) {
				break
			}

			if entryGroup.signedGroupTxns[txnIdx].Sig != txn.Sig || (!entryGroup.signedGroupTxns[txnIdx].Msig.Equal(txn.Msig)) || (!entryGroup.signedGroupTxns[txnIdx].Lsig.Equal(&txn.Lsig)) || (entryGroup.signedGroupTxns[txnIdx].AuthAddr != txn.AuthAddr) {
				break
			}
			verifiedTxn++
		}
		if verifiedTxn != len(signedTxnGroup) || verifiedTxn == 0 {
			unverifiedGroups = append(unverifiedGroups, signedTxnGroup)
		}
	}
	return
}

// UpdatePinned replaces the pinned entries with the one provided in the pinnedTxns map. This is typically expected to be a subset of the
// already-pinned transactions. If a transaction is not currently pinned, and it's can't be found in the cache, a errMissingPinnedEntry error would be generated.
func (v *verifiedTransactionCache) UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) (err error) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	pinned := make(map[transactions.Txid]*GroupContext, len(pinnedTxns))
	for txID := range pinnedTxns {
		if groupEntry, has := v.pinned[txID]; has {
			pinned[txID] = groupEntry
			continue
		}

		// entry isn't in pinned; maybe we have it in one of the buckets ?
		found := false
		// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
		for offsetBucketIdx := v.base + len(v.buckets); offsetBucketIdx > v.base; offsetBucketIdx-- {
			bucketIdx := offsetBucketIdx % len(v.buckets)
			if groupEntry, has := v.buckets[bucketIdx][txID]; has {
				pinned[txID] = groupEntry
				found = true
				break
			}
		}
		if !found {
			err = errMissingPinnedEntry
		}

	}
	v.pinned = pinned
	return err
}

// Pin sets a given transaction group as pinned items, after they have already been verified.
func (v *verifiedTransactionCache) Pin(txgroup []transactions.SignedTxn) (err error) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	return v.pin(txgroup)
}

// PinGroups function would mark the given transaction groups as pinned.
func (v *verifiedTransactionCache) PinGroups(txgroups []transactions.SignedTxGroup) error {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	var outError error
	for _, txgroup := range txgroups {
		err := v.pin(txgroup.Transactions)
		if err != nil {
			outError = err
		}
	}
	return outError
}

// Pin sets a given transaction group as pinned items, after they have already been verified.
func (v *verifiedTransactionCache) pin(txgroup []transactions.SignedTxn) (err error) {
	transactionMissing := false
	if len(v.pinned)+len(txgroup) > maxPinnedEntries {
		// reaching this number likely means that we have an issue not removing entries from the pinned map.
		// return an error ( which would get logged )
		return errTooManyPinnedEntries
	}
	baseBucket := v.base
	for _, txn := range txgroup {
		txID := txn.ID()
		if _, has := v.pinned[txID]; has {
			// it's already pinned; keep going.
			continue
		}

		// entry isn't in pinned; maybe we have it in one of the buckets ?
		found := false
		// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
		for offsetBucketIdx := baseBucket + len(v.buckets); offsetBucketIdx > baseBucket; offsetBucketIdx-- {
			bucketIdx := offsetBucketIdx % len(v.buckets)
			if ctx, has := v.buckets[bucketIdx][txID]; has {
				// move it to the pinned items :
				v.pinned[txID] = ctx
				delete(v.buckets[bucketIdx], txID)
				found = true
				baseBucket = bucketIdx
				break
			}
		}
		if !found {
			transactionMissing = true
		}
	}
	if transactionMissing {
		err = errMissingPinnedEntry
	}
	return
}

// add is the internal implementation of Add/AddPayset which adds a transaction group to the buffer.
func (v *verifiedTransactionCache) add(txgroup []transactions.SignedTxn, groupCtx *GroupContext) {
	if len(v.buckets[v.base])+len(txgroup) > entriesPerBucket {
		// move to the next bucket while deleting the content of the next bucket.
		v.base = (v.base + 1) % len(v.buckets)
		v.buckets[v.base] = make(map[transactions.Txid]*GroupContext, entriesPerBucket)
	}
	currentBucket := v.buckets[v.base]
	for _, txn := range txgroup {
		currentBucket[txn.ID()] = groupCtx
	}
}

var alwaysVerifiedCache = mockedCache{true}
var neverVerifiedCache = mockedCache{false}

type mockedCache struct {
	alwaysVerified bool
}

func (v *mockedCache) Add(txgroup []transactions.SignedTxn, groupCtx *GroupContext) {
	return
}

func (v *mockedCache) AddPayset(txgroup [][]transactions.SignedTxn, groupCtxs []*GroupContext) error {
	return nil
}

func (v *mockedCache) GetUnverifiedTranscationGroups(txnGroups [][]transactions.SignedTxn, currSpecAddrs transactions.SpecialAddresses, currProto protocol.ConsensusVersion) (unverifiedGroups [][]transactions.SignedTxn) {
	if v.alwaysVerified {
		return nil
	}
	return txnGroups
}

func (v *mockedCache) UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) (err error) {
	return nil
}

func (v *mockedCache) PinGroups(txgroups []transactions.SignedTxGroup) error {
	return nil
}

func (v *mockedCache) Pin(txgroup []transactions.SignedTxn) (err error) {
	return nil
}

// GetMockedCache returns a mocked transaction cache implementation
func GetMockedCache(alwaysVerified bool) VerifiedTransactionCache {
	if alwaysVerified {
		return &alwaysVerifiedCache
	}
	return &neverVerifiedCache
}
