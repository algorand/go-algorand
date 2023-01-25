// Copyright (C) 2019-2023 Algorand, Inc.
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

package v2

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// convertAppResourceRecordToGenerated takes ledgercore.AppResourceRecord and converts it to v2.model.AppResourceRecord
func convertAppResourceRecordToGenerated(app ledgercore.AppResourceRecord) model.AppResourceRecord {
	var appLocalState *model.ApplicationLocalState = nil
	if app.State.LocalState != nil {
		s := AppLocalState(*app.State.LocalState, app.Aidx)
		appLocalState = &s
	}
	var appParams *model.ApplicationParams = nil
	if app.Params.Params != nil {
		p := AppParamsToApplication(app.Addr.String(), app.Aidx, app.Params.Params).Params
		appParams = &p
	}
	return model.AppResourceRecord{
		Address:              app.Addr.String(),
		AppIndex:             uint64(app.Aidx),
		AppDeleted:           app.Params.Deleted,
		AppParams:            appParams,
		AppLocalStateDeleted: app.State.Deleted,
		AppLocalState:        appLocalState,
	}
}

// convertAssetResourceRecordToGenerated takes ledgercore.AppResourceRecord and converts it to v2.model.AppResourceRecord
func convertAssetResourceRecordToGenerated(asset ledgercore.AssetResourceRecord) model.AssetResourceRecord {
	var assetHolding *model.AssetHolding = nil
	if asset.Holding.Holding != nil {
		a := AssetHolding(*asset.Holding.Holding, asset.Aidx)
		assetHolding = &a
	}
	var assetParams *model.AssetParams = nil
	if asset.Params.Params != nil {
		a := AssetParamsToAsset(asset.Addr.String(), asset.Aidx, asset.Params.Params)
		assetParams = &a.Params
	}
	return model.AssetResourceRecord{
		Address:             asset.Addr.String(),
		AssetIndex:          uint64(asset.Aidx),
		AssetHoldingDeleted: asset.Holding.Deleted,
		AssetHolding:        assetHolding,
		AssetParams:         assetParams,
		AssetDeleted:        asset.Params.Deleted,
	}
}

// stateDeltaToLedgerDelta converts ledgercore.StateDelta to v2.model.LedgerStateDelta
func stateDeltaToLedgerDelta(sDelta ledgercore.StateDelta, consensus config.ConsensusParams, rewardsLevel uint64, round uint64) (response model.LedgerStateDelta, err error) {
	var accts []model.AccountBalanceRecord
	var apps []model.AppResourceRecord
	var assets []model.AssetResourceRecord
	var keyValues []model.KvDelta
	var modifiedApps []model.ModifiedApp
	var modifiedAssets []model.ModifiedAsset
	var txLeases []model.TxLease

	for key, kvDelta := range sDelta.KvMods {
		var keyBytes = []byte(key)
		keyValues = append(keyValues, model.KvDelta{
			Key:   &keyBytes,
			Value: &kvDelta.Data,
		})
	}

	for _, record := range sDelta.Accts.Accts {
		var ot basics.OverflowTracker
		pendingRewards := basics.PendingRewards(&ot, consensus, record.MicroAlgos, record.RewardsBase, rewardsLevel)

		amountWithoutPendingRewards, overflowed := basics.OSubA(record.MicroAlgos, pendingRewards)
		if overflowed {
			return response, errors.New("overflow on pending reward calculation")
		}

		ad := basics.AccountData{}
		ledgercore.AssignAccountData(&ad, record.AccountData)
		a, err := AccountDataToAccount(record.Addr.String(), &ad, basics.Round(round), &consensus, amountWithoutPendingRewards)
		if err != nil {
			return response, err
		}

		accts = append(accts, model.AccountBalanceRecord{
			AccountData: a,
			Address:     record.Addr.String(),
		})
	}

	for _, app := range sDelta.Accts.GetAllAppResources() {
		apps = append(apps, convertAppResourceRecordToGenerated(app))
	}

	for _, asset := range sDelta.Accts.GetAllAssetResources() {
		assets = append(assets, convertAssetResourceRecordToGenerated(asset))
	}

	for createIdx, mod := range sDelta.Creatables {
		switch mod.Ctype {
		case basics.AppCreatable:
			modifiedApps = append(modifiedApps, model.ModifiedApp{
				Created: mod.Created,
				Creator: mod.Creator.String(),
				Id:      uint64(createIdx),
			})
		case basics.AssetCreatable:
			modifiedAssets = append(modifiedAssets, model.ModifiedAsset{
				Created: mod.Created,
				Creator: mod.Creator.String(),
				Id:      uint64(createIdx),
			})
		default:
			return response, fmt.Errorf("unable to determine type of creatable for modified creatable with index %d", createIdx)
		}
	}

	for lease, expRnd := range sDelta.Txleases {
		txLeases = append(txLeases, model.TxLease{
			Expiration: uint64(expRnd),
			Lease:      lease.Lease[:],
			Sender:     lease.Sender.String(),
		})
	}

	response = model.LedgerStateDeltaResponse{
		Accts: &model.AccountDeltas{
			Accounts: &accts,
			Apps:     &apps,
			Assets:   &assets,
		},
		ModifiedApps:   &modifiedApps,
		ModifiedAssets: &modifiedAssets,
		KvMods:         &keyValues,
		PrevTimestamp:  numOrNil(uint64(sDelta.PrevTimestamp)),
		StateProofNext: numOrNil(uint64(sDelta.StateProofNext)),
		Totals: &model.AccountTotals{
			NotParticipating: sDelta.Totals.NotParticipating.Money.Raw,
			Offline:          sDelta.Totals.Offline.Money.Raw,
			Online:           sDelta.Totals.Online.Money.Raw,
			RewardsLevel:     sDelta.Totals.RewardsLevel,
		},
		TxLeases: &txLeases,
	}
	return
}
