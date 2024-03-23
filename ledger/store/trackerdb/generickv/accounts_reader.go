// Copyright (C) 2019-2024 Algorand, Inc.
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

package generickv

import (
	"errors"
	"fmt"
	"io"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

// KvRead is a low level KV db interface for reading.
type KvRead interface {
	Get(key []byte) ([]byte, io.Closer, error)
	NewIter(low, high []byte, reverse bool) KvIter
}

// KvIter is a low level KV iterator.
type KvIter interface {
	Next() bool
	Key() []byte
	KeySlice() Slice
	Value() ([]byte, error)
	ValueSlice() (Slice, error)
	Valid() bool
	Close()
}

// Slice is a low level slice used during the KV iterator.
type Slice interface {
	Data() []byte
	Free()
	Size() int
	Exists() bool
}

type accountsReader struct {
	kvr   KvRead
	proto config.ConsensusParams
}

// MakeAccountsReader returns a kv db agnostic AccountsReader.
func MakeAccountsReader(kvr KvRead, proto config.ConsensusParams) *accountsReader {
	return &accountsReader{kvr, proto}
}

func (r *accountsReader) LookupAccount(addr basics.Address) (data trackerdb.PersistedAccountData, err error) {
	// SQL impl at time of writing:
	//
	// SELECT
	// 		accountbase.rowid,
	// 		acctrounds.rnd,
	// 		accountbase.data
	// FROM acctrounds
	// 		LEFT JOIN accountbase ON address=?
	// WHERE id='acctbase'

	data.Addr = addr

	// read the current db round
	data.Round, err = r.AccountsRound()
	if err != nil {
		return
	}

	key := accountKey(addr)
	value, closer, err := r.kvr.Get(key[:])
	if err == trackerdb.ErrNotFound {
		// Note: the SQL implementation returns a data value and no error even when the account does not exist.
		return data, nil
	} else if err != nil {
		return
	}
	defer closer.Close()

	err = protocol.Decode(value, &data.AccountData)
	if err != nil {
		return
	}

	data.Ref = accountRef{addr}

	return
}

func (r *accountsReader) LookupResources(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (data trackerdb.PersistedResourcesData, err error) {
	data.Aidx = aidx

	// read the current db round
	data.Round, err = r.AccountsRound()
	if err != nil {
		return
	}

	key := resourceKey(addr, aidx)
	value, closer, err := r.kvr.Get(key[:])
	if err == trackerdb.ErrNotFound {
		// Note: the SQL implementation returns a data value and no error even when the account does not exist.
		data.Data = trackerdb.MakeResourcesData(0)
		return data, nil
	} else if err != nil {
		err = fmt.Errorf("unable to query resource data for address %v aidx %v ctype %v : %w", addr, aidx, ctype, err)
		return
	}
	defer closer.Close()

	err = protocol.Decode(value, &data.Data)
	if err != nil {
		return
	}

	// Note: the ctype is not filtered during the query, but rather asserted to be what the caller expected
	if ctype == basics.AssetCreatable && !data.Data.IsAsset() {
		err = fmt.Errorf("lookupResources asked for an asset but got %v", data.Data)
	}
	if ctype == basics.AppCreatable && !data.Data.IsApp() {
		err = fmt.Errorf("lookupResources asked for an app but got %v", data.Data)
	}

	data.AcctRef = accountRef{addr}

	return
}

func (r *accountsReader) LookupAllResources(addr basics.Address) (data []trackerdb.PersistedResourcesData, rnd basics.Round, err error) {
	low, high := resourceAddrOnlyRangePrefix(addr)

	iter := r.kvr.NewIter(low[:], high[:], false)
	defer iter.Close()

	var value []byte

	// read the current db round
	rnd, err = r.AccountsRound()
	if err != nil {
		return
	}

	for iter.Next() {
		pitem := trackerdb.PersistedResourcesData{AcctRef: accountRef{addr}, Round: rnd}

		key := iter.Key()

		// extract aidx from key
		pitem.Aidx = extractResourceAidx(key)

		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return
		}
		// decode raw value
		err = protocol.Decode(value, &pitem.Data)
		if err != nil {
			return
		}
		// append entry to accum
		data = append(data, pitem)
	}

	return
}

func (r *accountsReader) LookupLimitedResources(_ basics.Address, _ basics.CreatableIndex, _ uint64, _ basics.CreatableType) ([]trackerdb.PersistedResourcesDataWithCreator, basics.Round, error) {
	return nil, 0, errors.New("not supported")
}

func (r *accountsReader) LookupKeyValue(key string) (pv trackerdb.PersistedKVData, err error) {
	// read the current db round
	pv.Round, err = r.AccountsRound()
	if err != nil {
		return
	}

	value, closer, err := r.kvr.Get(appKvKey(key))
	if err == trackerdb.ErrNotFound {
		// Note: the SQL implementation returns a data value and no error even when the account does not exist.
		return pv, nil
	} else if err != nil {
		return
	}
	defer closer.Close()

	pv.Value = value

	return
}

// TODO: lifted from sql.go, we might want to refactor it
func keyPrefixIntervalPreprocessing(prefix []byte) ([]byte, []byte) {
	if prefix == nil {
		prefix = []byte{}
	}
	prefixIncr := make([]byte, len(prefix))
	copy(prefixIncr, prefix)
	for i := len(prefix) - 1; i >= 0; i-- {
		currentByteIncr := int(prefix[i]) + 1
		if currentByteIncr > 0xFF {
			prefixIncr = prefixIncr[:len(prefixIncr)-1]
			continue
		}
		prefixIncr[i] = byte(currentByteIncr)
		return prefix, prefixIncr
	}
	return prefix, nil
}

func (r *accountsReader) LookupKeysByPrefix(prefix string, maxKeyNum uint64, results map[string]bool, resultCount uint64) (round basics.Round, err error) {
	// SQL at time of writing:
	//
	// SELECT acctrounds.rnd, kvstore.key
	// FROM acctrounds LEFT JOIN kvstore ON kvstore.key >= ? AND kvstore.key < ?
	// WHERE id='acctbase'

	// read the current db round
	round, err = r.AccountsRound()
	if err != nil {
		return
	}

	start, end := keyPrefixIntervalPreprocessing([]byte(prefix))

	iter := r.kvr.NewIter(start, end, false)
	defer iter.Close()

	var value []byte

	for iter.Next() {
		// end iteration if we reached max results
		if resultCount == maxKeyNum {
			return
		}

		// read the key
		key := string(iter.Key())

		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return
		}

		// mark if the key has data on the result map
		results[key] = len(value) > 0

		// inc results in range
		resultCount++
	}

	return
}

func (r *accountsReader) LookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, ok bool, dbRound basics.Round, err error) {
	// The old SQL impl:
	//
	// SELECT
	// 		acctrounds.rnd,
	// 		assetcreators.creator
	// FROM acctrounds
	// 		LEFT JOIN assetcreators ON asset = ? AND ctype = ?
	// WHERE id='acctbase'

	// read the current db round
	dbRound, err = r.AccountsRound()
	if err != nil {
		return
	}

	key := creatableKey(cidx)
	value, closer, err := r.kvr.Get(key[:])
	if err == trackerdb.ErrNotFound {
		// the record does not exist
		// clean up the error and just return ok=false
		err = nil
		ok = false
		return
	} else if err != nil {
		return
	}
	defer closer.Close()

	// decode the raw value
	var entry creatableEntry
	err = protocol.Decode(value, &entry)
	if err != nil {
		return
	}

	// assert that the ctype is the one expected
	if entry.Ctype != ctype {
		ok = false
		return
	}

	// copy the addr to the return
	copy(addr[:], entry.CreatorAddr)

	// mark result as ok
	ok = true

	return
}

func (r *accountsReader) Close() {

}
