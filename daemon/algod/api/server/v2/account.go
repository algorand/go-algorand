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

package v2

import (
	"encoding/base64"
	"errors"
	"math"
	"slices"
	"sort"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
)

// AssetHolding converts between basics.AssetHolding and model.AssetHolding
func AssetHolding(ah basics.AssetHolding, ai basics.AssetIndex) model.AssetHolding {
	return model.AssetHolding{
		Amount:   ah.Amount,
		AssetID:  ai,
		IsFrozen: ah.Frozen,
	}
}

// AccountDataToAccount converts basics.AccountData to v2.model.Account
func AccountDataToAccount(
	address string, record *basics.AccountData,
	lastRound basics.Round, consensus *config.ConsensusParams,
	amountWithoutPendingRewards basics.MicroAlgos,
) (model.Account, error) {

	assets := make([]model.AssetHolding, 0, len(record.Assets))
	for curid, holding := range record.Assets {
		// Empty is ok, asset may have been deleted, so we can no
		// longer fetch the creator
		holding := AssetHolding(holding, curid)

		assets = append(assets, holding)
	}
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].AssetID < assets[j].AssetID
	})

	createdAssets := make([]model.Asset, 0, len(record.AssetParams))
	for idx, params := range record.AssetParams {
		asset := AssetParamsToAsset(address, idx, &params)
		createdAssets = append(createdAssets, asset)
	}
	sort.Slice(createdAssets, func(i, j int) bool {
		return createdAssets[i].Index < createdAssets[j].Index
	})

	var apiParticipation *model.AccountParticipation
	if !record.VoteID.IsEmpty() {
		apiParticipation = &model.AccountParticipation{
			VoteParticipationKey:      record.VoteID[:],
			SelectionParticipationKey: record.SelectionID[:],
			VoteFirstValid:            record.VoteFirstValid,
			VoteLastValid:             record.VoteLastValid,
			VoteKeyDilution:           record.VoteKeyDilution,
		}
		if !record.StateProofID.IsEmpty() {
			tmp := record.StateProofID[:]
			apiParticipation.StateProofKey = &tmp
		}
	}

	createdApps := make([]model.Application, 0, len(record.AppParams))
	for appIdx, appParams := range record.AppParams {
		app := AppParamsToApplication(address, appIdx, &appParams)
		createdApps = append(createdApps, app)
	}
	sort.Slice(createdApps, func(i, j int) bool {
		return createdApps[i].Id < createdApps[j].Id
	})

	appsLocalState := make([]model.ApplicationLocalState, 0, len(record.AppLocalStates))
	for appIdx, state := range record.AppLocalStates {
		appsLocalState = append(appsLocalState, AppLocalState(state, appIdx))
	}
	sort.Slice(appsLocalState, func(i, j int) bool {
		return appsLocalState[i].Id < appsLocalState[j].Id
	})

	totalAppSchema := model.ApplicationStateSchema{
		NumByteSlice: record.TotalAppSchema.NumByteSlice,
		NumUint:      record.TotalAppSchema.NumUint,
	}
	totalExtraPages := uint64(record.TotalExtraAppPages)

	amount := record.MicroAlgos
	pendingRewards, overflowed := basics.OSubA(amount, amountWithoutPendingRewards)
	if overflowed {
		return model.Account{}, errors.New("overflow on pending reward calculation")
	}

	minBalance := record.MinBalance(consensus.BalanceRequirements())

	return model.Account{
		SigType:                     nil,
		Round:                       lastRound,
		Address:                     address,
		Amount:                      amount.Raw,
		PendingRewards:              pendingRewards.Raw,
		AmountWithoutPendingRewards: amountWithoutPendingRewards.Raw,
		Rewards:                     record.RewardedMicroAlgos.Raw,
		Status:                      record.Status.String(),
		RewardBase:                  &record.RewardsBase,
		Participation:               apiParticipation,
		IncentiveEligible:           omitEmpty(record.IncentiveEligible),
		CreatedAssets:               &createdAssets,
		TotalCreatedAssets:          uint64(len(createdAssets)),
		CreatedApps:                 &createdApps,
		TotalCreatedApps:            uint64(len(createdApps)),
		Assets:                      &assets,
		TotalAssetsOptedIn:          uint64(len(assets)),
		AuthAddr:                    addrOrNil(record.AuthAddr),
		AppsLocalState:              &appsLocalState,
		TotalAppsOptedIn:            uint64(len(appsLocalState)),
		AppsTotalSchema:             &totalAppSchema,
		AppsTotalExtraPages:         omitEmpty(totalExtraPages),
		TotalBoxes:                  omitEmpty(record.TotalBoxes),
		TotalBoxBytes:               omitEmpty(record.TotalBoxBytes),
		MinBalance:                  minBalance.Raw,
		LastProposed:                omitEmpty(record.LastProposed),
		LastHeartbeat:               omitEmpty(record.LastHeartbeat),
	}, nil
}

func convertTKVToGenerated(tkv *basics.TealKeyValue) *model.TealKeyValueStore {
	if tkv == nil || len(*tkv) == 0 {
		return nil
	}

	converted := make(model.TealKeyValueStore, 0, len(*tkv))
	rawKeyBytes := make([]string, 0, len(*tkv))
	for k, v := range *tkv {
		converted = append(converted, model.TealKeyValue{
			Key: base64.StdEncoding.EncodeToString([]byte(k)),
			Value: model.TealValue{
				Type:  uint64(v.Type),
				Bytes: base64.StdEncoding.EncodeToString([]byte(v.Bytes)),
				Uint:  v.Uint,
			},
		})
		rawKeyBytes = append(rawKeyBytes, k)
	}
	sort.Slice(converted, func(i, j int) bool {
		return rawKeyBytes[i] < rawKeyBytes[j]
	})
	return &converted
}

func convertGeneratedTKV(akvs *model.TealKeyValueStore) (basics.TealKeyValue, error) {
	if akvs == nil || len(*akvs) == 0 {
		return nil, nil
	}

	tkv := make(basics.TealKeyValue)
	for _, kv := range *akvs {
		// Decode base-64 encoded map key
		decodedKey, err := base64.StdEncoding.DecodeString(kv.Key)
		if err != nil {
			return nil, err
		}

		// Decode base-64 encoded map value (OK even if empty string)
		decodedBytes, err := base64.StdEncoding.DecodeString(kv.Value.Bytes)
		if err != nil {
			return nil, err
		}

		tkv[string(decodedKey)] = basics.TealValue{
			Type:  basics.TealType(kv.Value.Type),
			Uint:  kv.Value.Uint,
			Bytes: string(decodedBytes),
		}
	}
	return tkv, nil
}

// AccountToAccountData converts v2.model.Account to basics.AccountData
func AccountToAccountData(a *model.Account) (basics.AccountData, error) {
	var voteID crypto.OneTimeSignatureVerifier
	var selID crypto.VRFVerifier
	var voteFirstValid basics.Round
	var voteLastValid basics.Round
	var voteKeyDilution uint64
	var stateProofID merklesignature.Commitment
	if a.Participation != nil {
		copy(voteID[:], a.Participation.VoteParticipationKey)
		copy(selID[:], a.Participation.SelectionParticipationKey)
		voteFirstValid = a.Participation.VoteFirstValid
		voteLastValid = a.Participation.VoteLastValid
		voteKeyDilution = a.Participation.VoteKeyDilution
		if a.Participation.StateProofKey != nil {
			copy(stateProofID[:], *a.Participation.StateProofKey)
		}
	}

	var rewardsBase uint64
	if a.RewardBase != nil {
		rewardsBase = *a.RewardBase
	}

	var assetParams map[basics.AssetIndex]basics.AssetParams
	if a.CreatedAssets != nil && len(*a.CreatedAssets) > 0 {
		assetParams = make(map[basics.AssetIndex]basics.AssetParams, len(*a.CreatedAssets))
		for _, ca := range *a.CreatedAssets {
			var metadataHash [32]byte
			if ca.Params.MetadataHash != nil {
				copy(metadataHash[:], *ca.Params.MetadataHash)
			}
			manager, err := nilToZeroAddr(ca.Params.Manager)
			if err != nil {
				return basics.AccountData{}, err
			}
			reserve, err := nilToZeroAddr(ca.Params.Reserve)
			if err != nil {
				return basics.AccountData{}, err
			}
			freeze, err := nilToZeroAddr(ca.Params.Freeze)
			if err != nil {
				return basics.AccountData{}, err
			}
			clawback, err := nilToZeroAddr(ca.Params.Clawback)
			if err != nil {
				return basics.AccountData{}, err
			}

			assetParams[ca.Index] = basics.AssetParams{
				Total:         ca.Params.Total,
				Decimals:      uint32(ca.Params.Decimals),
				DefaultFrozen: nilToZero(ca.Params.DefaultFrozen),
				UnitName:      nilToZero(ca.Params.UnitName),
				AssetName:     nilToZero(ca.Params.Name),
				URL:           nilToZero(ca.Params.Url),
				MetadataHash:  metadataHash,
				Manager:       manager,
				Reserve:       reserve,
				Freeze:        freeze,
				Clawback:      clawback,
			}
		}
	}
	var assets map[basics.AssetIndex]basics.AssetHolding
	if a.Assets != nil && len(*a.Assets) > 0 {
		assets = make(map[basics.AssetIndex]basics.AssetHolding, len(*a.Assets))
		for _, h := range *a.Assets {
			assets[h.AssetID] = basics.AssetHolding{
				Amount: h.Amount,
				Frozen: h.IsFrozen,
			}
		}
	}

	var appLocalStates map[basics.AppIndex]basics.AppLocalState
	if a.AppsLocalState != nil && len(*a.AppsLocalState) > 0 {
		appLocalStates = make(map[basics.AppIndex]basics.AppLocalState, len(*a.AppsLocalState))
		for _, ls := range *a.AppsLocalState {
			kv, err := convertGeneratedTKV(ls.KeyValue)
			if err != nil {
				return basics.AccountData{}, err
			}
			appLocalStates[ls.Id] = basics.AppLocalState{
				Schema: basics.StateSchema{
					NumUint:      ls.Schema.NumUint,
					NumByteSlice: ls.Schema.NumByteSlice,
				},
				KeyValue: kv,
			}
		}
	}

	var appParams map[basics.AppIndex]basics.AppParams
	if a.CreatedApps != nil && len(*a.CreatedApps) > 0 {
		appParams = make(map[basics.AppIndex]basics.AppParams, len(*a.CreatedApps))
		for _, params := range *a.CreatedApps {
			ap, err := ApplicationParamsToAppParams(&params.Params)
			if err != nil {
				return basics.AccountData{}, err
			}
			appParams[params.Id] = ap
		}
	}

	totalSchema := basics.StateSchema{}
	if a.AppsTotalSchema != nil {
		totalSchema.NumUint = a.AppsTotalSchema.NumUint
		totalSchema.NumByteSlice = a.AppsTotalSchema.NumByteSlice
	}

	var totalExtraPages uint32
	if a.AppsTotalExtraPages != nil {
		if *a.AppsTotalExtraPages > math.MaxUint32 {
			return basics.AccountData{}, errors.New("AppsTotalExtraPages exceeds maximum decodable value")
		}
		totalExtraPages = uint32(*a.AppsTotalExtraPages)
	}

	status, err := basics.UnmarshalStatus(a.Status)
	if err != nil {
		return basics.AccountData{}, err
	}

	ad := basics.AccountData{
		Status:             status,
		MicroAlgos:         basics.MicroAlgos{Raw: a.Amount},
		RewardsBase:        rewardsBase,
		RewardedMicroAlgos: basics.MicroAlgos{Raw: a.Rewards},
		IncentiveEligible:  nilToZero(a.IncentiveEligible),
		VoteID:             voteID,
		SelectionID:        selID,
		VoteFirstValid:     voteFirstValid,
		VoteLastValid:      voteLastValid,
		VoteKeyDilution:    voteKeyDilution,
		StateProofID:       stateProofID,
		Assets:             assets,
		AppLocalStates:     appLocalStates,
		AppParams:          appParams,
		TotalAppSchema:     totalSchema,
		TotalExtraAppPages: totalExtraPages,
		TotalBoxes:         nilToZero(a.TotalBoxes),
		TotalBoxBytes:      nilToZero(a.TotalBoxBytes),
		LastProposed:       nilToZero(a.LastProposed),
		LastHeartbeat:      nilToZero(a.LastHeartbeat),
	}

	ad.AuthAddr, err = nilToZeroAddr(a.AuthAddr)
	if err != nil {
		return basics.AccountData{}, err
	}
	if len(assetParams) > 0 {
		ad.AssetParams = assetParams
	}
	if len(assets) > 0 {
		ad.Assets = assets
	}
	if len(appLocalStates) > 0 {
		ad.AppLocalStates = appLocalStates
	}
	if len(appParams) > 0 {
		ad.AppParams = appParams
	}

	return ad, nil
}

// ApplicationParamsToAppParams converts model.ApplicationParams to basics.AppParams
func ApplicationParamsToAppParams(gap *model.ApplicationParams) (basics.AppParams, error) {
	ap := basics.AppParams{
		ApprovalProgram:   gap.ApprovalProgram,
		ClearStateProgram: gap.ClearStateProgram,
	}
	if gap.ExtraProgramPages != nil {
		if *gap.ExtraProgramPages > math.MaxUint32 {
			return basics.AppParams{}, errors.New("ExtraProgramPages exceeds maximum decodable value")
		}
		ap.ExtraProgramPages = uint32(*gap.ExtraProgramPages)
	}
	ap.Version = nilToZero(gap.Version)

	if gap.LocalStateSchema != nil {
		ap.LocalStateSchema = basics.StateSchema{
			NumUint:      gap.LocalStateSchema.NumUint,
			NumByteSlice: gap.LocalStateSchema.NumByteSlice,
		}
	}
	if gap.GlobalStateSchema != nil {
		ap.GlobalStateSchema = basics.StateSchema{
			NumUint:      gap.GlobalStateSchema.NumUint,
			NumByteSlice: gap.GlobalStateSchema.NumByteSlice,
		}
	}
	kv, err := convertGeneratedTKV(gap.GlobalState)
	if err != nil {
		return basics.AppParams{}, err
	}
	ap.GlobalState = kv

	ap.SizeSponsor, err = nilToZeroAddr(gap.SizeSponsor)
	if err != nil {
		return basics.AppParams{}, err
	}
	return ap, nil
}

// AppParamsToApplication converts basics.AppParams to model.Application
func AppParamsToApplication(creator string, appIdx basics.AppIndex, appParams *basics.AppParams) model.Application {
	globalState := convertTKVToGenerated(&appParams.GlobalState)
	extraProgramPages := uint64(appParams.ExtraProgramPages)
	app := model.Application{
		Id: appIdx,
		Params: model.ApplicationParams{
			Creator:           creator,
			ApprovalProgram:   appParams.ApprovalProgram,
			ClearStateProgram: appParams.ClearStateProgram,
			ExtraProgramPages: omitEmpty(extraProgramPages),
			GlobalState:       globalState,
			LocalStateSchema: &model.ApplicationStateSchema{
				NumByteSlice: appParams.LocalStateSchema.NumByteSlice,
				NumUint:      appParams.LocalStateSchema.NumUint,
			},
			GlobalStateSchema: &model.ApplicationStateSchema{
				NumByteSlice: appParams.GlobalStateSchema.NumByteSlice,
				NumUint:      appParams.GlobalStateSchema.NumUint,
			},
			Version:     omitEmpty(appParams.Version),
			SizeSponsor: addrOrNil(appParams.SizeSponsor),
		},
	}
	return app
}

// AppLocalState converts between basics.AppLocalState and model.ApplicationLocalState
func AppLocalState(state basics.AppLocalState, appIdx basics.AppIndex) model.ApplicationLocalState {
	localState := convertTKVToGenerated(&state.KeyValue)
	return model.ApplicationLocalState{
		Id:       appIdx,
		KeyValue: localState,
		Schema: model.ApplicationStateSchema{
			NumByteSlice: state.Schema.NumByteSlice,
			NumUint:      state.Schema.NumUint,
		},
	}
}

// AssetParamsToAsset converts basics.AssetParams to model.Asset
func AssetParamsToAsset(creator string, idx basics.AssetIndex, params *basics.AssetParams) model.Asset {
	frozen := params.DefaultFrozen
	assetParams := model.AssetParams{
		Creator:       creator,
		Total:         params.Total,
		Decimals:      uint64(params.Decimals),
		DefaultFrozen: &frozen,
		Name:          omitEmpty(printableUTF8OrEmpty(params.AssetName)),
		NameB64:       sliceOrNil([]byte(params.AssetName)),
		UnitName:      omitEmpty(printableUTF8OrEmpty(params.UnitName)),
		UnitNameB64:   sliceOrNil([]byte(params.UnitName)),
		Url:           omitEmpty(printableUTF8OrEmpty(params.URL)),
		UrlB64:        sliceOrNil([]byte(params.URL)),
		Clawback:      addrOrNil(params.Clawback),
		Freeze:        addrOrNil(params.Freeze),
		Manager:       addrOrNil(params.Manager),
		Reserve:       addrOrNil(params.Reserve),
	}
	if params.MetadataHash != ([32]byte{}) {
		metadataHash := slices.Clone(params.MetadataHash[:])
		assetParams.MetadataHash = &metadataHash
	}

	return model.Asset{
		Index:  idx,
		Params: assetParams,
	}
}
