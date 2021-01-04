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

package main

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"

	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
)

// ddrFromParams converts serialized DryrunRequest to v2.DryrunRequest
func ddrFromParams(dp *DebugParams) (ddr v2.DryrunRequest, err error) {
	if len(dp.DdrBlob) == 0 {
		return
	}

	var gdr generatedV2.DryrunRequest
	err = protocol.DecodeJSON(dp.DdrBlob, &gdr)
	if err == nil {
		ddr, err = v2.DryrunRequestFromGenerated(&gdr)
	} else {
		err = protocol.DecodeReflect(dp.DdrBlob, &ddr)
	}

	return
}

func convertAccounts(accounts []generatedV2.Account) (records []basics.BalanceRecord, err error) {
	for _, a := range accounts {
		var addr basics.Address
		addr, err = basics.UnmarshalChecksumAddress(a.Address)
		if err != nil {
			return
		}
		var ad basics.AccountData
		ad, err = v2.AccountToAccountData(&a)
		if err != nil {
			return
		}
		records = append(records, basics.BalanceRecord{Addr: addr, AccountData: ad})
	}
	return
}

func balanceRecordsFromDdr(ddr *v2.DryrunRequest) (records []basics.BalanceRecord, err error) {
	accounts := make(map[basics.Address]basics.AccountData)
	for _, a := range ddr.Accounts {
		var addr basics.Address
		addr, err = basics.UnmarshalChecksumAddress(a.Address)
		if err != nil {
			return
		}
		var ad basics.AccountData
		ad, err = v2.AccountToAccountData(&a)
		if err != nil {
			return
		}
		accounts[addr] = ad
	}
	for _, a := range ddr.Apps {
		var addr basics.Address
		addr, err = basics.UnmarshalChecksumAddress(a.Params.Creator)
		if err != nil {
			return
		}
		// deserialize app params and update account data
		var params basics.AppParams
		params, err = v2.ApplicationParamsToAppParams(&a.Params)
		if err != nil {
			return
		}
		appIdx := basics.AppIndex(a.Id)
		ad := accounts[addr]
		if ad.AppParams == nil {
			ad.AppParams = make(map[basics.AppIndex]basics.AppParams, 1)
			ad.AppParams[appIdx] = params
		} else {
			ap, ok := ad.AppParams[appIdx]
			if ok {
				v2.MergeAppParams(&ap, &params)
				ad.AppParams[appIdx] = ap
			} else {
				ad.AppParams[appIdx] = params
			}
		}
		accounts[addr] = ad
	}

	for addr, ad := range accounts {
		records = append(records, basics.BalanceRecord{Addr: addr, AccountData: ad})
	}
	return
}
