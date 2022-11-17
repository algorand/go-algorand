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

package v2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/crypto"
	dprivate "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/data/private"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/node"
)

// DataHandlers is an implementation to the V2 route handler interface defined by the generated code.
// Corresponding methods in the oapi spec are tagged as `data`
type DataHandlers struct {
	NonParticipatingHandlers
	Node node.DataNodeInterface
}

// Register implements route registration for the HandlerInterface
func (v2 *DataHandlers) Register(e *echo.Echo, publicAuth echo.MiddlewareFunc, privateAuth echo.MiddlewareFunc) {
	v2.NonParticipatingHandlers.Register(e, publicAuth, privateAuth)
	dprivate.RegisterHandlers(e, v2, privateAuth)
	registerCommon(e, v2.Node)
}

// GetNode implements node retrieval for the HandlerInterface
func (v2 *DataHandlers) GetNode() node.BaseNodeInterface {
	return v2.Node
}

// UnsetSyncRound removes the sync round restriction from the ledger.
// (DELETE /v2/ledger/sync)
func (v2 *DataHandlers) UnsetSyncRound(ctx echo.Context) error {
	err := v2.Node.UnsetSyncRound()
	if err != nil {
		return internalError(ctx, err, errFailedSettingSyncRound, v2.Log)
	}
	return ctx.NoContent(http.StatusOK)
}

// SetSyncRound sets the sync round on the ledger.
// (POST /v2/ledger/sync/{round})
func (v2 *DataHandlers) SetSyncRound(ctx echo.Context, round uint64) error {
	err := v2.Node.SetSyncRound(round)
	if err != nil {
		switch err {
		case catchup.ErrSyncRoundInvalid:
			return badRequest(ctx, err, errFailedSettingSyncRound, v2.Log)
		default:
			return internalError(ctx, err, errFailedSettingSyncRound, v2.Log)
		}
	}
	return ctx.NoContent(http.StatusOK)
}

// GetSyncRound gets the sync round from the ledger.
// (GET /v2/ledger/sync)
func (v2 *DataHandlers) GetSyncRound(ctx echo.Context) error {
	rnd, err := v2.Node.GetSyncRound()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingSyncRound, v2.Log)
	}
	if rnd == 0 {
		return notFound(ctx, fmt.Errorf("sync round is not set"), errFailedRetrievingSyncRound, v2.Log)
	}
	return ctx.JSON(http.StatusOK, model.GetSyncRoundResponse{Round: rnd})
}

// GetRoundStateDelta returns the deltas for a given round.
// This should be a ledgercore.StateDelta object.
// (GET /v2/deltas/{round})
func (v2 *DataHandlers) GetRoundStateDelta(ctx echo.Context, round uint64) error {
	sDelta, err := v2.Node.LedgerForAPI().GetStateDeltaForRound(basics.Round(round))
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingStateDelta, v2.Log)
	}

	var accts []model.AccountBalanceRecord
	var apps []model.AppResourceRecord
	var assets []model.AssetResourceRecord
	var keyValues []model.KvDelta
	var modifiedCreatables []model.ModifiedCreatable
	var txLeases []model.TxLease
	var inclTxns []model.IncludedTransaction

	consensusParams, err := v2.Node.LedgerForAPI().ConsensusParams(basics.Round(round))
	if err != nil {
		return internalError(ctx, fmt.Errorf("unable to retrieve consensus params for round %d", round), errInternalFailure, v2.Log)
	}
	hdr, err := v2.Node.LedgerForAPI().BlockHdr(basics.Round(round))
	if err != nil {
		return internalError(ctx, fmt.Errorf("unable to retrieve block header for round %d", round), errInternalFailure, v2.Log)
	}

	for key, kvDelta := range sDelta.KvMods {
		var keyBytes = []byte(key)
		keyValues = append(keyValues, model.KvDelta{
			Key:       &keyBytes,
			PrevValue: &kvDelta.OldData,
			Value:     &kvDelta.Data,
		})
	}

	for _, record := range sDelta.Accts.GetAllAccounts() {
		var apiParticipation *model.AccountParticipation
		if record.VoteID != (crypto.OneTimeSignatureVerifier{}) {
			apiParticipation = &model.AccountParticipation{
				VoteParticipationKey:      record.VoteID[:],
				SelectionParticipationKey: record.SelectionID[:],
				VoteFirstValid:            uint64(record.VoteFirstValid),
				VoteLastValid:             uint64(record.VoteLastValid),
				VoteKeyDilution:           uint64(record.VoteKeyDilution),
			}
			if !record.StateProofID.IsEmpty() {
				tmp := record.StateProofID[:]
				apiParticipation.StateProofKey = &tmp
			}
		}
		var ot basics.OverflowTracker
		pendingRewards := basics.PendingRewards(&ot, consensusParams, record.MicroAlgos, record.RewardsBase, hdr.RewardsLevel)

		amountWithoutPendingRewards, overflowed := basics.OSubA(record.MicroAlgos, pendingRewards)
		if overflowed {
			return internalError(ctx, errors.New("overflow on pending reward calculation"), errInternalFailure, v2.Log)
		}
		accts = append(accts, model.AccountBalanceRecord{
			AccountData: model.Account{
				SigType:                     nil,
				Round:                       round,
				Address:                     record.Addr.String(),
				Amount:                      record.MicroAlgos.Raw,
				PendingRewards:              pendingRewards.Raw,
				AmountWithoutPendingRewards: amountWithoutPendingRewards.Raw,
				Rewards:                     record.RewardedMicroAlgos.Raw,
				Status:                      record.Status.String(),
				RewardBase:                  &record.RewardsBase,
				Participation:               apiParticipation,
				TotalCreatedAssets:          record.TotalAssetParams,
				TotalCreatedApps:            record.TotalAppParams,
				TotalAssetsOptedIn:          record.TotalAssets,
				AuthAddr:                    addrOrNil(record.AuthAddr),
				TotalAppsOptedIn:            record.TotalAppLocalStates,
				AppsTotalSchema: &model.ApplicationStateSchema{
					NumByteSlice: record.TotalAppSchema.NumByteSlice,
					NumUint:      record.TotalAppSchema.NumUint,
				},
				AppsTotalExtraPages: numOrNil(uint64(record.TotalExtraAppPages)),
				MinBalance:          record.MinBalance(&consensusParams).Raw,
			},
			Address: record.Addr.String(),
		})
	}

	for _, app := range sDelta.Accts.GetAllAppResources() {
		var appLocalState *model.ApplicationLocalState = nil
		if app.State.LocalState != nil {
			localState := convertTKVToGenerated(&app.State.LocalState.KeyValue)
			appLocalState = &model.ApplicationLocalState{
				Id:       uint64(app.Aidx),
				KeyValue: localState,
				Schema: model.ApplicationStateSchema{
					NumByteSlice: app.State.LocalState.Schema.NumByteSlice,
					NumUint:      app.State.LocalState.Schema.NumUint,
				},
			}
		}
		var appParams *model.ApplicationParams = nil
		if app.Params.Params != nil {
			globalState := convertTKVToGenerated(&app.Params.Params.GlobalState)
			appParams = &model.ApplicationParams{
				ApprovalProgram:   app.Params.Params.ApprovalProgram,
				ClearStateProgram: app.Params.Params.ClearStateProgram,
				Creator:           app.Addr.String(),
				ExtraProgramPages: numOrNil(uint64(app.Params.Params.ExtraProgramPages)),
				GlobalState:       globalState,
				GlobalStateSchema: &model.ApplicationStateSchema{
					NumByteSlice: app.Params.Params.GlobalStateSchema.NumByteSlice,
					NumUint:      app.Params.Params.GlobalStateSchema.NumUint,
				},
				LocalStateSchema: &model.ApplicationStateSchema{
					NumByteSlice: app.Params.Params.LocalStateSchema.NumByteSlice,
					NumUint:      app.Params.Params.LocalStateSchema.NumUint,
				},
			}
		}
		apps = append(apps, model.AppResourceRecord{
			Address:              app.Addr.String(),
			AppIndex:             uint64(app.Aidx),
			AppParamsDeleted:     app.Params.Deleted,
			AppParams:            appParams,
			AppLocalStateDeleted: app.State.Deleted,
			AppLocalState:        appLocalState,
		})
	}

	for _, asset := range sDelta.Accts.GetAllAssetResources() {
		var assetHolding *model.AssetHolding = nil
		if asset.Holding.Holding != nil {
			assetHolding = &model.AssetHolding{
				Amount:   asset.Holding.Holding.Amount,
				AssetID:  uint64(asset.Aidx),
				IsFrozen: asset.Holding.Holding.Frozen,
			}
		}
		var assetParams *model.AssetParams = nil
		if asset.Params.Params != nil {
			assetParams = &model.AssetParams{
				Clawback:      strOrNil(asset.Params.Params.Clawback.String()),
				Creator:       asset.Addr.String(),
				Decimals:      uint64(asset.Params.Params.Decimals),
				DefaultFrozen: &asset.Params.Params.DefaultFrozen,
				Freeze:        strOrNil(asset.Params.Params.Freeze.String()),
				Manager:       strOrNil(asset.Params.Params.Manager.String()),
				MetadataHash:  byteOrNil(asset.Params.Params.MetadataHash[:]),
				Name:          strOrNil(asset.Params.Params.AssetName),
				NameB64:       byteOrNil([]byte(base64.StdEncoding.EncodeToString([]byte(asset.Params.Params.AssetName)))),
				Reserve:       strOrNil(asset.Params.Params.Reserve.String()),
				Total:         asset.Params.Params.Total,
				UnitName:      strOrNil(asset.Params.Params.UnitName),
				UnitNameB64:   byteOrNil([]byte(base64.StdEncoding.EncodeToString([]byte(asset.Params.Params.UnitName)))),
				Url:           strOrNil(asset.Params.Params.URL),
				UrlB64:        byteOrNil([]byte(base64.StdEncoding.EncodeToString([]byte(asset.Params.Params.URL)))),
			}
		}
		assets = append(assets, model.AssetResourceRecord{
			Address:             asset.Addr.String(),
			AssetIndex:          uint64(asset.Aidx),
			AssetHoldingDeleted: asset.Holding.Deleted,
			AssetHolding:        assetHolding,
			AssetParams:         assetParams,
			AssetParamsDeleted:  asset.Params.Deleted,
		})
	}

	for createIdx, mod := range sDelta.Creatables {
		var creatableType model.ModifiedCreatableCreatableType
		switch mod.Ctype {
		case basics.AppCreatable:
			creatableType = model.ModifiedCreatableCreatableTypeApp
		case basics.AssetCreatable:
			creatableType = model.ModifiedCreatableCreatableTypeAsset
		default:
			return internalError(ctx, fmt.Errorf("unable to determine type of creatable for modified creatable with index %d", createIdx), errInternalFailure, v2.Log)
		}
		modifiedCreatables = append(modifiedCreatables, model.ModifiedCreatable{
			CreatableType: creatableType,
			Created:       mod.Created,
			Creator:       mod.Creator.String(),
			Index:         uint64(createIdx),
		})
	}

	for lease, expRnd := range sDelta.Txleases {
		txLeases = append(txLeases, model.TxLease{
			Expiration: uint64(expRnd),
			Lease:      lease.Lease[:],
			Sender:     lease.Sender.String(),
		})
	}

	for txid, inclTxn := range sDelta.Txids {
		inclTxns = append(inclTxns, model.IncludedTransaction{
			Intra:     inclTxn.Intra,
			LastValid: uint64(inclTxn.LastValid),
			TxId:      txid.String(),
		})
	}

	response := model.RoundStateDeltaResponse{
		Accts: &model.AccountDeltas{
			Accounts: &accts,
			Apps:     &apps,
			Assets:   &assets,
		},
		Creatables:     &modifiedCreatables,
		KvMods:         &keyValues,
		PrevTimestamp:  numOrNil(uint64(sDelta.PrevTimestamp)),
		StateProofNext: numOrNil(uint64(sDelta.StateProofNext)),
		Totals: &model.AccountTotals{
			NotParticipating: sDelta.Totals.NotParticipating.Money.Raw,
			Offline:          sDelta.Totals.Offline.Money.Raw,
			Online:           sDelta.Totals.Online.Money.Raw,
			RewardsLevel:     sDelta.Totals.RewardsLevel,
		},
		TxIds:    &inclTxns,
		TxLeases: &txLeases,
	}

	return ctx.JSON(http.StatusOK, response)
}
