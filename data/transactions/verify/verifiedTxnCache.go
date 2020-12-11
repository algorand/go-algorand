// Copyright (C) 2019-2020 Algorand, Inc.
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

const entriesPerBucket = 8179 // pick a prime number to promote lower collisions.
const maxPinnedEntries = 500000

var errTooManyPinnedEntries = errors.New("Too many pinned entries")
var errMissingPinnedEntry = errors.New("Missing pinned entry")

// VerifiedTransactionCache provides a cached store of recently verified transactions
type VerifiedTransactionCache interface {
	Add(txgroup []transactions.SignedTxn, verifyContext []Context, pinned bool) error
	Check(txgroup []transactions.SignedTxn, verifyContext []Context) bool
	GetUnverifiedTranscationGroups(payset [][]transactions.SignedTxn, CurrSpecAddrs transactions.SpecialAddresses, CurrProto protocol.ConsensusVersion) [][]transactions.SignedTxn
	UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) error
	Pin(txgroup []transactions.SignedTxn) error
}

// VerifiedTransactionCacheImpl provides an implementation of the VerifiedTransactionCache interface
type verifiedTransactionCacheImpl struct {
	bucketsLock deadlock.RWMutex
	buckets     []map[transactions.Txid]Context
	pinned      map[transactions.Txid]Context
	base        int
}

// MakeVerifiedTransactionCache creates an instance of verifiedTransactionCacheImpl and returns it.
func MakeVerifiedTransactionCache(cacheSize int) VerifiedTransactionCache {
	bucketsCount := 1 + (cacheSize / entriesPerBucket)
	impl := &verifiedTransactionCacheImpl{
		buckets: make([]map[transactions.Txid]Context, bucketsCount),
		pinned:  make(map[transactions.Txid]Context, cacheSize),
		base:    0,
	}
	for i := 0; i < bucketsCount; i++ {
		impl.buckets[i] = make(map[transactions.Txid]Context, entriesPerBucket)
	}
	return impl
}

func (v *verifiedTransactionCacheImpl) Add(txgroup []transactions.SignedTxn, verifyContext []Context, pinned bool) error {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	if pinned {
		if len(v.pinned)+len(txgroup) > maxPinnedEntries {
			// reaching this number likely means that we have an issue not removing entries from the pinned map.
			// return an error ( which would get logged )
			return errTooManyPinnedEntries
		}
		for i, txn := range txgroup {
			v.pinned[txn.ID()] = verifyContext[i]
		}
		return nil
	}
	if len(v.buckets[v.base])+len(txgroup) > entriesPerBucket {
		// move to the next bucket while deleting the content of the next bucket.
		v.base = (v.base + 1) % len(v.buckets)
		v.buckets[v.base] = make(map[transactions.Txid]Context, entriesPerBucket)
	}
	currentBucket := v.buckets[v.base]
	for i, txn := range txgroup {
		currentBucket[txn.ID()] = verifyContext[i]
	}
	return nil
}

func (v *verifiedTransactionCacheImpl) Check(txgroup []transactions.SignedTxn, verifyContext []Context) (found bool) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	found = false
	for i, txn := range txgroup {
		id := txn.ID()
		found = false
		// check pinned first
		if ctx, has := v.pinned[id]; has && ctx.Equal(verifyContext[i]) {
			found = true
		}
		if !found {
			// try to look in the previously verified buckets.
			// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
			for offsetBucketIdx := v.base + len(v.buckets); offsetBucketIdx > v.base; offsetBucketIdx-- {
				bucketIdx := offsetBucketIdx % len(v.buckets)
				if ctx, has := v.buckets[bucketIdx][id]; has && ctx.Equal(verifyContext[i]) {
					found = true
					break
				}
			}
			if !found {
				return
			}
		}
	}
	return
}

func (v *verifiedTransactionCacheImpl) GetUnverifiedTranscationGroups(txnGroups [][]transactions.SignedTxn, currSpecAddrs transactions.SpecialAddresses, currProto protocol.ConsensusVersion) (unverifiedGroups [][]transactions.SignedTxn) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	groupParams := GroupParams{
		CurrSpecAddrs: currSpecAddrs,
		CurrProto:     currProto,
	}
	unverifiedGroups = make([][]transactions.SignedTxn, len(txnGroups))
	for _, signedTxnGroup := range txnGroups {
		verifiedTxn := 0

		groupParams.MinTealVersion = logic.ComputeMinTealVersion(signedTxnGroup)
		for i, txn := range signedTxnGroup {
			txnContext := Context{
				groupParams: &groupParams,
				groupIndex:  i,
			}
			id := txn.ID()
			// check pinned first
			if entryCtx, has := v.pinned[id]; has && entryCtx.Equal(txnContext) {
				verifiedTxn++
				continue
			}
			// try to look in the previously verified buckets.
			// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
			for offsetBucketIdx := v.base + len(v.buckets); offsetBucketIdx > v.base; offsetBucketIdx-- {
				bucketIdx := offsetBucketIdx % len(v.buckets)
				if entryCtx, has := v.buckets[bucketIdx][id]; has && entryCtx.Equal(txnContext) {
					verifiedTxn++
					break
				}
			}
		}
		if verifiedTxn == len(signedTxnGroup) && verifiedTxn > 0 {
			unverifiedGroups = append(unverifiedGroups, signedTxnGroup)
		}
	}
	return nil
}

func (v *verifiedTransactionCacheImpl) UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) (err error) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	pinned := make(map[transactions.Txid]Context, len(pinnedTxns))
	for txID := range pinnedTxns {
		if ctx, has := v.pinned[txID]; has {
			pinned[txID] = ctx
			continue
		}

		// entry isn't in pinned; maybe we have it in one of the buckets ?
		found := false
		// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
		for offsetBucketIdx := v.base + len(v.buckets); offsetBucketIdx > v.base; offsetBucketIdx-- {
			bucketIdx := offsetBucketIdx % len(v.buckets)
			if ctx, has := v.buckets[bucketIdx][txID]; has {
				pinned[txID] = ctx
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
func (v *verifiedTransactionCacheImpl) Pin(txgroup []transactions.SignedTxn) (err error) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	transcationMissing := false
	if len(v.pinned)+len(txgroup) > maxPinnedEntries {
		// reaching this number likely means that we have an issue not removing entries from the pinned map.
		// return an error ( which would get logged )
		return errTooManyPinnedEntries
	}
	for _, txn := range txgroup {
		txID := txn.ID()
		if _, has := v.pinned[txID]; has {
			// it's already pinned; keep going.
			continue
		}

		// entry isn't in pinned; maybe we have it in one of the buckets ?
		found := false
		// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
		for offsetBucketIdx := v.base + len(v.buckets); offsetBucketIdx > v.base; offsetBucketIdx-- {
			bucketIdx := offsetBucketIdx % len(v.buckets)
			if ctx, has := v.buckets[bucketIdx][txID]; has {
				// move it to the pinned items :
				v.pinned[txID] = ctx
				delete(v.buckets[bucketIdx], txID)
				found = true
				break
			}
		}
		if !found {
			transcationMissing = true
		}
	}
	if transcationMissing {
		err = errMissingPinnedEntry
	}
	return
}
