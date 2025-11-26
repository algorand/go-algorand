// Copyright (C) 2019-2025 Algorand, Inc.
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

package dualdriver

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/google/go-cmp/cmp"
)

type accountsReader struct {
	primary   trackerdb.AccountsReader
	secondary trackerdb.AccountsReader
}

// Close implements trackerdb.AccountsReader
func (ar *accountsReader) Close() {
	ar.primary.Close()
	ar.secondary.Close()
}

// LookupAccount implements trackerdb.AccountsReader
func (ar *accountsReader) LookupAccount(addr basics.Address) (data trackerdb.PersistedAccountData, err error) {
	dataP, errP := ar.primary.LookupAccount(addr)
	dataS, errS := ar.secondary.LookupAccount(addr)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// coalesce refs
	ref, err := coalesceAccountRefs(dataP.Ref, dataS.Ref)
	if err != nil {
		return
	}
	// update ref in results
	// Note: this is safe because the refs are engine specific
	dataP.Ref = ref
	dataS.Ref = ref
	// check results match
	if dataP != dataS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return dataP, nil
}

// LookupAllResources implements trackerdb.AccountsReader
func (ar *accountsReader) LookupAllResources(addr basics.Address) (data []trackerdb.PersistedResourcesData, rnd basics.Round, err error) {
	dataP, rndP, errP := ar.primary.LookupAllResources(addr)
	dataS, rndS, errS := ar.secondary.LookupAllResources(addr)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// coalesce refs
	if len(dataP) != len(dataS) {
		err = ErrInconsistentResult
		return
	}
	var ref trackerdb.AccountRef
	for i := range dataP {
		ref, err = coalesceAccountRefs(dataP[i].AcctRef, dataS[i].AcctRef)
		if err != nil {
			return data, rnd, err
		}
		// update ref in results
		dataP[i].AcctRef = ref
		dataS[i].AcctRef = ref
	}
	// check results match
	if !cmp.Equal(dataP, dataS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	if rndP != rndS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return dataP, rndP, nil
}

// LookupCreator implements trackerdb.AccountsReader
func (ar *accountsReader) LookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, ok bool, dbRound basics.Round, err error) {
	addrP, okP, dbRoundP, errP := ar.primary.LookupCreator(cidx, ctype)
	addrS, okS, dbRoundS, errS := ar.secondary.LookupCreator(cidx, ctype)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if addrP != addrS {
		err = ErrInconsistentResult
		return
	}
	if okP != okS {
		err = ErrInconsistentResult
		return
	}
	if dbRoundP != dbRoundS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return addrP, okP, dbRoundP, nil
}

// LookupKeyValue implements trackerdb.AccountsReader
func (ar *accountsReader) LookupKeyValue(key string) (pv trackerdb.PersistedKVData, err error) {
	pvP, errP := ar.primary.LookupKeyValue(key)
	pvS, errS := ar.secondary.LookupKeyValue(key)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(pvP, pvS) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return pvP, nil
}

// LookupKeysByPrefix implements trackerdb.AccountsReader
func (ar *accountsReader) LookupKeysByPrefix(prefix string, maxKeyNum uint64, results map[string]bool, resultCount uint64) (round basics.Round, err error) {
	roundP, errP := ar.primary.LookupKeysByPrefix(prefix, maxKeyNum, results, resultCount)
	roundS, errS := ar.secondary.LookupKeysByPrefix(prefix, maxKeyNum, results, resultCount)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if roundP != roundS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return roundP, nil
}

// LookupResources implements trackerdb.AccountsReader
func (ar *accountsReader) LookupResources(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (data trackerdb.PersistedResourcesData, err error) {
	dataP, errP := ar.primary.LookupResources(addr, aidx, ctype)
	dataS, errS := ar.secondary.LookupResources(addr, aidx, ctype)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// coalesce refs
	ref, err := coalesceAccountRefs(dataP.AcctRef, dataS.AcctRef)
	if err != nil {
		return
	}
	// update ref in results
	// Note: this is safe because the refs are engine specific
	dataP.AcctRef = ref
	dataS.AcctRef = ref
	// check results match
	if !cmp.Equal(dataP, dataS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return dataP, nil
}

func (ar *accountsReader) LookupLimitedResources(addr basics.Address, minIdx basics.CreatableIndex, maxCreatables uint64, ctype basics.CreatableType) (data []trackerdb.PersistedResourcesDataWithCreator, rnd basics.Round, err error) {
	dataP, rndP, errP := ar.primary.LookupLimitedResources(addr, minIdx, maxCreatables, ctype)
	dataS, rndS, errS := ar.secondary.LookupLimitedResources(addr, minIdx, maxCreatables, ctype)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// coalesce refs
	if len(dataP) != len(dataS) {
		err = ErrInconsistentResult
		return
	}
	var ref trackerdb.AccountRef
	for i := range dataP {
		ref, err = coalesceAccountRefs(dataP[i].AcctRef, dataS[i].AcctRef)
		if err != nil {
			return data, rnd, err
		}
		// update ref in results
		dataP[i].AcctRef = ref
		dataS[i].AcctRef = ref
	}
	// check results match
	if !cmp.Equal(dataP, dataS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	if rndP != rndS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return dataP, rndP, nil
}
