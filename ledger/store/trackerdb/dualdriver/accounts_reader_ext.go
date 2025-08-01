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
	"context"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/google/go-cmp/cmp"
)

type accountsReaderExt struct {
	primary   trackerdb.AccountsReaderExt
	secondary trackerdb.AccountsReaderExt
}

// AccountsHashRound implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) AccountsHashRound(ctx context.Context) (hashrnd basics.Round, err error) {
	hashrndP, errP := ar.primary.AccountsHashRound(ctx)
	hashrndS, errS := ar.secondary.AccountsHashRound(ctx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if hashrndP != hashrndS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return hashrndP, nil
}

// AccountsOnlineRoundParams implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) AccountsOnlineRoundParams() (onlineRoundParamsData []ledgercore.OnlineRoundParamsData, endRound basics.Round, err error) {
	onlineRoundParamsDataP, endRoundP, errP := ar.primary.AccountsOnlineRoundParams()
	onlineRoundParamsDataS, endRoundS, errS := ar.secondary.AccountsOnlineRoundParams()
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(onlineRoundParamsDataP, onlineRoundParamsDataS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	if endRoundP != endRoundS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return onlineRoundParamsDataP, endRoundP, nil
}

// AccountsOnlineTop implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) AccountsOnlineTop(rnd basics.Round, offset uint64, n uint64, rewardUnit uint64) (onlineAccounts map[basics.Address]*ledgercore.OnlineAccount, err error) {
	onlineAccountsP, errP := ar.primary.AccountsOnlineTop(rnd, offset, n, rewardUnit)
	onlineAccountsS, errS := ar.secondary.AccountsOnlineTop(rnd, offset, n, rewardUnit)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(onlineAccountsP, onlineAccountsS) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return onlineAccountsP, nil
}

// AccountsRound implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) AccountsRound() (rnd basics.Round, err error) {
	rndP, errP := ar.primary.AccountsRound()
	rndS, errS := ar.secondary.AccountsRound()
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if rndP != rndS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return rndP, nil
}

// AccountsTotals implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) AccountsTotals(ctx context.Context, catchpointStaging bool) (totals ledgercore.AccountTotals, err error) {
	totalsP, errP := ar.primary.AccountsTotals(ctx, catchpointStaging)
	totalsS, errS := ar.secondary.AccountsTotals(ctx, catchpointStaging)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if totalsP != totalsS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return totalsP, nil
}

// LoadAllFullAccounts implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) LoadAllFullAccounts(ctx context.Context, balancesTable string, resourcesTable string, acctCb func(basics.Address, basics.AccountData)) (count int, err error) {
	countP, errP := ar.primary.LoadAllFullAccounts(ctx, balancesTable, resourcesTable, acctCb)
	countS, errS := ar.secondary.LoadAllFullAccounts(ctx, balancesTable, resourcesTable, acctCb)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if countP != countS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return countP, nil
}

// LoadTxTail implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) LoadTxTail(ctx context.Context, dbRound basics.Round) (roundData []*trackerdb.TxTailRound, roundHash []crypto.Digest, baseRound basics.Round, err error) {
	roundDataP, roundHashP, baseRoundP, errP := ar.primary.LoadTxTail(ctx, dbRound)
	roundDataS, roundHashS, baseRoundS, errS := ar.secondary.LoadTxTail(ctx, dbRound)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(roundDataP, roundDataS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	if !cmp.Equal(roundHashP, roundHashS) {
		err = ErrInconsistentResult
		return
	}
	if baseRoundP != baseRoundS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return roundDataP, roundHashP, baseRoundP, nil
}

// LookupAccountAddressFromAddressID implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) LookupAccountAddressFromAddressID(ctx context.Context, ref trackerdb.AccountRef) (address basics.Address, err error) {
	if ref == nil {
		return address, trackerdb.ErrNotFound
	}
	// parse ref
	xRef := ref.(accountRef)

	addressP, errP := ar.primary.LookupAccountAddressFromAddressID(ctx, xRef.primary)
	addressS, errS := ar.secondary.LookupAccountAddressFromAddressID(ctx, xRef.secondary)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if addressP != addressS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return addressP, nil
}

// LookupAccountRowID implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) LookupAccountRowID(addr basics.Address) (ref trackerdb.AccountRef, err error) {
	// Note: we do not check the refs since they are internal to the engines and wont match
	refP, errP := ar.primary.LookupAccountRowID(addr)
	refS, errS := ar.secondary.LookupAccountRowID(addr)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	return accountRef{refP, refS}, nil
}

// LookupOnlineAccountDataByAddress implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) LookupOnlineAccountDataByAddress(addr basics.Address) (ref trackerdb.OnlineAccountRef, data []byte, err error) {
	// Note: we do not check the refs since they are internal to the engines and wont match
	refP, dataP, errP := ar.primary.LookupOnlineAccountDataByAddress(addr)
	refS, dataS, errS := ar.secondary.LookupOnlineAccountDataByAddress(addr)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(dataP, dataS) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return onlineAccountRef{refP, refS}, dataP, nil
}

// LookupResourceDataByAddrID implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) LookupResourceDataByAddrID(accRef trackerdb.AccountRef, aidx basics.CreatableIndex) (data []byte, err error) {
	if accRef == nil {
		return data, trackerdb.ErrNotFound
	}
	// parse ref
	xRef := accRef.(accountRef)
	// lookup
	dataP, errP := ar.primary.LookupResourceDataByAddrID(xRef.primary, aidx)
	dataS, errS := ar.secondary.LookupResourceDataByAddrID(xRef.secondary, aidx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(dataP, dataS) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return dataP, nil
}

// OnlineAccountsAll implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) OnlineAccountsAll(maxAccounts uint64) (accounts []trackerdb.PersistedOnlineAccountData, err error) {
	accountsP, errP := ar.primary.OnlineAccountsAll(maxAccounts)
	accountsS, errS := ar.secondary.OnlineAccountsAll(maxAccounts)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// coalesce refs
	if len(accountsP) != len(accountsS) {
		err = ErrInconsistentResult
		return
	}
	var ref trackerdb.OnlineAccountRef
	for i := range accountsP {
		ref, err = coalesceOnlineAccountRefs(accountsP[i].Ref, accountsS[i].Ref)
		if err != nil {
			return accounts, err
		}
		// update ref in results
		accountsP[i].Ref = ref
		accountsS[i].Ref = ref
	}
	// check results match
	if !cmp.Equal(accountsP, accountsS, allowAllUnexported) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return accountsP, nil
}

// ExpiredOnlineAccountsForRound implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) ExpiredOnlineAccountsForRound(rnd basics.Round, voteRnd basics.Round, rewardUnit uint64, rewardsLevel uint64) (expAccounts map[basics.Address]*basics.OnlineAccountData, err error) {
	expAccountsP, errP := ar.primary.ExpiredOnlineAccountsForRound(rnd, voteRnd, rewardUnit, rewardsLevel)
	expAccountsS, errS := ar.secondary.ExpiredOnlineAccountsForRound(rnd, voteRnd, rewardUnit, rewardsLevel)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if !cmp.Equal(expAccountsP, expAccountsS) {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return expAccountsP, nil
}

// Testing implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) Testing() trackerdb.AccountsReaderTestExt {
	// TODO
	return nil
}

// TotalAccounts implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) TotalAccounts(ctx context.Context) (total uint64, err error) {
	totalP, errP := ar.primary.TotalAccounts(ctx)
	totalS, errS := ar.secondary.TotalAccounts(ctx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if totalP != totalS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return totalP, nil
}

// TotalKVs implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) TotalKVs(ctx context.Context) (total uint64, err error) {
	totalP, errP := ar.primary.TotalKVs(ctx)
	totalS, errS := ar.secondary.TotalKVs(ctx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if totalP != totalS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return totalP, nil
}

// TotalResources implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) TotalResources(ctx context.Context) (total uint64, err error) {
	totalP, errP := ar.primary.TotalResources(ctx)
	totalS, errS := ar.secondary.TotalResources(ctx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if totalP != totalS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return totalP, nil
}

// TotalOnlineAccountRows implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) TotalOnlineAccountRows(ctx context.Context) (total uint64, err error) {
	totalP, errP := ar.primary.TotalOnlineAccountRows(ctx)
	totalS, errS := ar.secondary.TotalOnlineAccountRows(ctx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if totalP != totalS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return totalP, nil
}

// TotalOnlineRoundParams implements trackerdb.AccountsReaderExt
func (ar *accountsReaderExt) TotalOnlineRoundParams(ctx context.Context) (total uint64, err error) {
	totalP, errP := ar.primary.TotalOnlineRoundParams(ctx)
	totalS, errS := ar.secondary.TotalOnlineRoundParams(ctx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if totalP != totalS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return totalP, nil
}
