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

package verify

import (
	"errors"
	"unique"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const maxPinnedEntries = 500000

// VerifiedTxnCacheError helps to identify the errors of a cache error and diffrenciate these from a general verification errors.
type VerifiedTxnCacheError struct {
	inner error
}

// Unwrap provides access to the underlying error
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

// VerifiedTransactionCache provides a cached store of recently verified transactions. The cache is designed to have two separate "levels". On the
// bottom tier, the cache would be using a cyclic buffer, where old transactions would end up overridden by new ones. In order to support transactions
// that goes into the transaction pool, we have a higher tier of pinned cache. Pinned transactions would not be cycled-away by new incoming transactions,
// and would only get eliminated by updates to the transaction pool, which would inform the cache of updates to the pinned items.
type VerifiedTransactionCache interface {
	// Add adds a given transaction group and its associated group context to the cache. If any of the transactions already appear
	// in the cache, the new entry overrides the old one.
	Add(groupCtx *GroupContext)
	// AddPayset works in a similar way to Add, but is intended for adding an array of transaction groups, along with their corresponding contexts.
	AddPayset(groupCtxs []*GroupContext)
	// GetUnverifiedTransactionGroups compares the provided payset against the currently cached transactions and figure which transaction groups aren't fully cached.
	GetUnverifiedTransactionGroups(payset [][]transactions.SignedTxn, CurrSpecAddrs transactions.SpecialAddresses, CurrProto protocol.ConsensusVersion) [][]transactions.SignedTxn
	// UpdatePinned replaces the pinned entries with the one provided in the pinnedTxns map. This is typically expected to be a subset of the
	// already-pinned transactions. If a transaction is not currently pinned, and it's can't be found in the cache, a errMissingPinnedEntry error would be generated.
	UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) error
	// Pin function would mark the given transaction group as pinned.
	Pin(txgroup []transactions.SignedTxn) error
}

// verifiedTransactionCache provides an implementation of the VerifiedTransactionCache interface
type verifiedTransactionCache struct {
	// Number of entries in each map (bucket).
	entriesPerBucket int
	// bucketsLock is the lock for synchronizing access to the cache
	bucketsLock deadlock.Mutex
	// buckets is the circular cache buckets buffer
	buckets []map[transactions.Txid]*verifiedTxnCtx
	// pinned is the pinned transactions entries map.
	pinned map[transactions.Txid]*verifiedTxnCtx
	// base is the index into the buckets array where the next transaction entry would be written.
	base int
}

type txnAuth struct {
	sig      crypto.Signature
	authAddr basics.Address
	lsig     *transactions.LogicSig // 232B struct that is almost always nil
	msig     *crypto.MultisigSig    // 32B struct
	pqsig    *transactions.PQSig    // 56B struct
}

// emptyLogicSig is the emptiness test for the out-of-line LogicSig. It is deliberately
// Equal against the zero value rather than Blank(): Blank() treats a non-nil empty slice
// as empty, while Equal() -- the comparison matches() actually performs -- distinguishes
// it from nil. Compressing on Blank() would let those two forms collide in the cache and
// report a hit where a full comparison would not. Never written to.
var emptyLogicSig transactions.LogicSig

// verificationContext is the external state a past verification depended on,
// both fields move together and are shared by every entry so they are interned as a unit.
// This makes the entry as a single 8-byte handle and reduces the comparison in matches() to a pointer equality.
type verificationContext struct {
	specAddrs        transactions.SpecialAddresses
	consensusVersion protocol.ConsensusVersion
}

type verifiedTxnCtx struct {
	vctx unique.Handle[verificationContext]
	sigs txnAuth
}

// matches reports whether this cached entry records a verification that still applies to
// txn. Both halves are required: the entry must have been verified under the same
// specAddrs and consensus version, and txn must carry the same authorization material
// that was verified back then.
func (v *verifiedTxnCtx) matches(vctx unique.Handle[verificationContext], txn *transactions.SignedTxn) bool {
	isEqual := v.vctx == vctx &&
		v.sigs.sig == txn.Sig &&
		v.sigs.authAddr == txn.AuthAddr

	if !isEqual {
		return false
	}

	txnLsigEmpty := txn.Lsig.Equal(&emptyLogicSig)
	txnPQsigBlank := txn.PQsig.Blank()
	txnMsigBlank := txn.Msig.Blank()
	lsigNotNil := v.sigs.lsig != nil
	pqsigNotNil := v.sigs.pqsig != nil
	msigNotNil := v.sigs.msig != nil

	if lsigNotNil && txnLsigEmpty || !lsigNotNil && !txnLsigEmpty {
		return false
	}
	if lsigNotNil {
		isEqual = v.sigs.lsig.Equal(&txn.Lsig)
	}

	if msigNotNil && txnMsigBlank || !msigNotNil && !txnMsigBlank {
		return false
	}
	if msigNotNil {
		isEqual = isEqual && v.sigs.msig.Equal(txn.Msig)
	}

	if pqsigNotNil && txnPQsigBlank || !pqsigNotNil && !txnPQsigBlank {
		return false
	}

	if pqsigNotNil {
		isEqual = isEqual && v.sigs.pqsig.Equal(txn.PQsig)
	}
	return isEqual
}

// MakeVerifiedTransactionCache creates an instance of verifiedTransactionCache and returns it.
func MakeVerifiedTransactionCache(cacheSize int) VerifiedTransactionCache {
	impl := &verifiedTransactionCache{
		entriesPerBucket: (cacheSize + 1) / 2,
		buckets:          make([]map[transactions.Txid]*verifiedTxnCtx, 3),
		pinned:           make(map[transactions.Txid]*verifiedTxnCtx, cacheSize),
		base:             0,
	}
	for i := 0; i < len(impl.buckets); i++ {
		impl.buckets[i] = make(map[transactions.Txid]*verifiedTxnCtx, impl.entriesPerBucket)
	}
	return impl
}

// Add adds a given transaction group and it's associated group context to the cache. If any of the transactions already appear
// in the cache, the new entry overrides the old one.
func (v *verifiedTransactionCache) Add(groupCtx *GroupContext) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	v.add(groupCtx)
}

// AddPayset works in a similar way to Add, but is intended for adding an array of transaction groups, along with their corresponding contexts.
func (v *verifiedTransactionCache) AddPayset(groupCtxs []*GroupContext) {
	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	for _, groupCtx := range groupCtxs {
		v.add(groupCtx)
	}
}

// GetUnverifiedTransactionGroups compares the provided payset against the currently cached transactions and figure which transaction groups aren't fully cached.
func (v *verifiedTransactionCache) GetUnverifiedTransactionGroups(txnGroups [][]transactions.SignedTxn, currSpecAddrs transactions.SpecialAddresses, currProto protocol.ConsensusVersion) (unverifiedGroups [][]transactions.SignedTxn) {
	vctx := unique.Make(verificationContext{specAddrs: currSpecAddrs, consensusVersion: currProto})

	v.bucketsLock.Lock()
	defer v.bucketsLock.Unlock()
	unverifiedGroups = make([][]transactions.SignedTxn, 0, len(txnGroups))

	for txnGroupIndex := 0; txnGroupIndex < len(txnGroups); txnGroupIndex++ {
		signedTxnGroup := txnGroups[txnGroupIndex]
		verifiedTxn := 0

		baseBucket := v.base
		for txnIdx := 0; txnIdx < len(signedTxnGroup); txnIdx++ {
			txn := &signedTxnGroup[txnIdx]
			id := txn.Txn.ID()
			// check pinned first
			entryTxnCtx := v.pinned[id]
			// if not found in the pinned map, try to find in the verified buckets:
			if entryTxnCtx == nil {
				// try to look in the previously verified buckets.
				// we use the (base + W) % W trick here so we can go backward and wrap around the zero.
				for offsetBucketIdx := baseBucket + len(v.buckets); offsetBucketIdx > baseBucket; offsetBucketIdx-- {
					bucketIdx := offsetBucketIdx % len(v.buckets)
					if params, has := v.buckets[bucketIdx][id]; has {
						entryTxnCtx = params
						baseBucket = bucketIdx
						break
					}
				}
			}

			if entryTxnCtx == nil {
				break
			}
			if !entryTxnCtx.matches(vctx, txn) {
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
	pinned := make(map[transactions.Txid]*verifiedTxnCtx, len(pinnedTxns))
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
func (v *verifiedTransactionCache) add(groupCtx *GroupContext) {
	if len(v.buckets[v.base])+len(groupCtx.signedGroupTxns) > v.entriesPerBucket {
		// move to the next bucket while deleting the content of the next bucket.
		v.base = (v.base + 1) % len(v.buckets)
		v.buckets[v.base] = make(map[transactions.Txid]*verifiedTxnCtx, v.entriesPerBucket)
	}
	currentBucket := v.buckets[v.base]
	vctx := unique.Make(verificationContext{
		specAddrs:        groupCtx.specAddrs,
		consensusVersion: groupCtx.consensusVersion,
	})
	for _, txn := range groupCtx.signedGroupTxns {
		entry := &verifiedTxnCtx{
			vctx: vctx,
			sigs: txnAuth{
				sig:      txn.Sig,
				authAddr: txn.AuthAddr,
			},
		}
		if !txn.Lsig.Equal(&emptyLogicSig) {
			lsig := txn.Lsig // local copy to avoid the entire SignedTxn being referenced
			entry.sigs.lsig = &lsig
		}
		if !txn.Msig.Blank() {
			msig := txn.Msig
			entry.sigs.msig = &msig
		}
		if !txn.PQsig.Blank() {
			pqsig := txn.PQsig
			entry.sigs.pqsig = &pqsig
		}
		currentBucket[txn.ID()] = entry
	}
}

var alwaysVerifiedCache = mockedCache{true}
var neverVerifiedCache = mockedCache{false}

type mockedCache struct {
	alwaysVerified bool
}

func (v *mockedCache) Add(groupCtx *GroupContext) {
}

func (v *mockedCache) AddPayset(groupCtxs []*GroupContext) {
}

func (v *mockedCache) GetUnverifiedTransactionGroups(txnGroups [][]transactions.SignedTxn, currSpecAddrs transactions.SpecialAddresses, currProto protocol.ConsensusVersion) (unverifiedGroups [][]transactions.SignedTxn) {
	if v.alwaysVerified {
		return nil
	}
	return txnGroups
}

func (v *mockedCache) UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) (err error) {
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
