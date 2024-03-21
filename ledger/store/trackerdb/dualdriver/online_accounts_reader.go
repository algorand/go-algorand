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

package dualdriver

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/google/go-cmp/cmp"
)

type onlineAccountsReader struct {
	primary   trackerdb.OnlineAccountsReader
	secondary trackerdb.OnlineAccountsReader
}

// Close implements trackerdb.OnlineAccountsReader
func (oar *onlineAccountsReader) Close() {
	oar.primary.Close()
	oar.secondary.Close()
}

// LookupOnline implements trackerdb.OnlineAccountsReader
func (oar *onlineAccountsReader) LookupOnline(addr basics.Address, rnd basics.Round) (data trackerdb.PersistedOnlineAccountData, err error) {
	dataP, errP := oar.primary.LookupOnline(addr, rnd)
	dataS, errS := oar.secondary.LookupOnline(addr, rnd)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// coalesce refs
	ref, err := coalesceOnlineAccountRefs(dataP.Ref, dataS.Ref)
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

// LookupOnlineHistory implements trackerdb.OnlineAccountsReader
func (oar *onlineAccountsReader) LookupOnlineHistory(addr basics.Address) (result []trackerdb.PersistedOnlineAccountData, rnd basics.Round, err error) {
	resultP, rndP, errP := oar.primary.LookupOnlineHistory(addr)
	resultS, rndS, errS := oar.secondary.LookupOnlineHistory(addr)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// coalesce refs
	if len(resultP) != len(resultS) {
		err = ErrInconsistentResult
		return
	}
	var ref trackerdb.OnlineAccountRef
	for i := range resultP {
		ref, err = coalesceOnlineAccountRefs(resultP[i].Ref, resultS[i].Ref)
		if err != nil {
			return result, rnd, err
		}
		// update ref in results
		resultP[i].Ref = ref
		resultS[i].Ref = ref
	}
	// check results match
	if !cmp.Equal(resultP, resultS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	if rndP != rndS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return resultP, rndP, nil
}

// LookupOnlineRoundParams implements trackerdb.OnlineAccountsReader
func (oar *onlineAccountsReader) LookupOnlineRoundParams(rnd basics.Round) (onlineRoundParamsData ledgercore.OnlineRoundParamsData, err error) {
	resultP, errP := oar.primary.LookupOnlineRoundParams(rnd)
	resultS, errS := oar.secondary.LookupOnlineRoundParams(rnd)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(resultP, resultS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return resultP, nil
}
