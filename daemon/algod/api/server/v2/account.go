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

package v2

import (
	"errors"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
)

// AccountDataToAccount converts basics.AccountData to v2.generated.Account
func AccountDataToAccount(
	address string, record *basics.AccountData, assetsCreators map[basics.AssetIndex]string,
	lastRound basics.Round, amountWithoutPendingRewards basics.MicroAlgos,
) (generated.Account, error) {

	assets := make([]generated.AssetHolding, 0)
	if len(record.Assets) > 0 {
		//assets = make(map[uint64]v1.AssetHolding)
		for curid, holding := range record.Assets {
			// Empty is ok, asset may have been deleted, so we can no
			// longer fetch the creator
			creator := assetsCreators[curid]
			holding := generated.AssetHolding{
				Amount:   holding.Amount,
				AssetId:  uint64(curid),
				Creator:  creator,
				IsFrozen: holding.Frozen,
			}

			assets = append(assets, holding)
		}
	}

	createdAssets := make([]generated.Asset, 0)
	if len(record.AssetParams) > 0 {
		for idx, params := range record.AssetParams {
			assetParams := generated.AssetParams{
				Creator:       address,
				Total:         params.Total,
				Decimals:      uint64(params.Decimals),
				DefaultFrozen: &params.DefaultFrozen,
				MetadataHash:  byteOrNil(params.MetadataHash[:]),
				Name:          strOrNil(params.AssetName),
				UnitName:      strOrNil(params.UnitName),
				Url:           strOrNil(params.URL),
				Clawback:      addrOrNil(params.Clawback),
				Freeze:        addrOrNil(params.Freeze),
				Manager:       addrOrNil(params.Manager),
				Reserve:       addrOrNil(params.Reserve),
			}
			asset := generated.Asset{
				Index:  uint64(idx),
				Params: assetParams,
			}
			createdAssets = append(createdAssets, asset)
		}
	}

	var apiParticipation *generated.AccountParticipation
	if record.VoteID != (crypto.OneTimeSignatureVerifier{}) {
		apiParticipation = &generated.AccountParticipation{
			VoteParticipationKey:      record.VoteID[:],
			SelectionParticipationKey: record.SelectionID[:],
			VoteFirstValid:            uint64(record.VoteFirstValid),
			VoteLastValid:             uint64(record.VoteLastValid),
			VoteKeyDilution:           uint64(record.VoteKeyDilution),
		}
	}

	convertTKV := func(tkv *basics.TealKeyValue) (converted generated.TealKeyValueStore) {
		for k, v := range *tkv {
			converted = append(converted, generated.TealKeyValue{
				Key: k,
				Value: generated.TealValue{
					Type:  uint64(v.Type),
					Bytes: v.Bytes,
					Uint:  v.Uint,
				},
			})
		}
		return
	}

	createdApps := make([]generated.Application, 0, len(record.AppParams))
	if len(record.AppParams) > 0 {
		for appIdx, appParams := range record.AppParams {
			globalState := convertTKV(&appParams.GlobalState)
			createdApps = append(createdApps, generated.Application{
				AppIndex: uint64(appIdx),
				AppParams: generated.ApplicationParams{
					ApprovalProgram:   appParams.ApprovalProgram,
					ClearStateProgram: appParams.ClearStateProgram,
					GlobalState:       &globalState,
					LocalStateSchema: &generated.ApplicationStateSchema{
						NumByteSlice: appParams.LocalStateSchema.NumByteSlice,
						NumUint:      appParams.LocalStateSchema.NumUint,
					},
					GlobalStateSchema: &generated.ApplicationStateSchema{
						NumByteSlice: appParams.GlobalStateSchema.NumByteSlice,
						NumUint:      appParams.GlobalStateSchema.NumUint,
					},
				},
			})
		}
	}

	appsLocalState := make([]generated.ApplicationLocalStates, 0, len(record.AppLocalStates))
	if len(record.AppLocalStates) > 0 {
		for appIdx, state := range record.AppLocalStates {
			localState := convertTKV(&state.KeyValue)
			appsLocalState = append(appsLocalState, generated.ApplicationLocalStates{
				AppIndex: uint64(appIdx),
				State: generated.ApplicationLocalState{
					KeyValue: localState,
					Schema: generated.ApplicationStateSchema{
						NumByteSlice: state.Schema.NumByteSlice,
						NumUint:      state.Schema.NumUint,
					},
				},
			})
		}
	}

	totalAppSchema := generated.ApplicationStateSchema{
		NumByteSlice: record.TotalAppSchema.NumByteSlice,
		NumUint:      record.TotalAppSchema.NumUint,
	}

	amount := record.MicroAlgos
	pendingRewards, overflowed := basics.OSubA(amount, amountWithoutPendingRewards)
	if overflowed {
		return generated.Account{}, errors.New("overflow on pending reward calcuation")
	}

	return generated.Account{
		SigType:                     nil,
		Round:                       uint64(lastRound),
		Address:                     address,
		Amount:                      amount.Raw,
		PendingRewards:              pendingRewards.Raw,
		AmountWithoutPendingRewards: amountWithoutPendingRewards.Raw,
		Rewards:                     record.RewardedMicroAlgos.Raw,
		Status:                      record.Status.String(),
		RewardBase:                  &record.RewardsBase,
		Participation:               apiParticipation,
		CreatedAssets:               &createdAssets,
		Assets:                      &assets,
		SpendingKey:                 addrOrNil(record.SpendingKey),
		CreatedApps:                 &createdApps,
		AppsLocalState:              &appsLocalState,
		AppsTotalSchema:             &totalAppSchema,
	}, nil
}

// AccountToAccountData converts v2.generated.Account to basics.AccountData
func AccountToAccountData(a *generated.Account) (basics.AccountData, error) {
	var voteID crypto.OneTimeSignatureVerifier
	var selID crypto.VRFVerifier
	var voteFirstValid basics.Round
	var voteLastValid basics.Round
	var voteKeyDilution uint64
	if a.Participation != nil {
		copy(voteID[:], a.Participation.VoteParticipationKey)
		copy(selID[:], a.Participation.SelectionParticipationKey)
		voteFirstValid = basics.Round(a.Participation.VoteFirstValid)
		voteLastValid = basics.Round(a.Participation.VoteLastValid)
		voteKeyDilution = a.Participation.VoteKeyDilution
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
			copy(metadataHash[:], *ca.Params.MetadataHash)
			manager, err := basics.UnmarshalChecksumAddress(*ca.Params.Manager)
			if err != nil {
				return basics.AccountData{}, err
			}
			reserve, err := basics.UnmarshalChecksumAddress(*ca.Params.Reserve)
			if err != nil {
				return basics.AccountData{}, err
			}
			freeze, err := basics.UnmarshalChecksumAddress(*ca.Params.Freeze)
			if err != nil {
				return basics.AccountData{}, err
			}
			clawback, err := basics.UnmarshalChecksumAddress(*ca.Params.Clawback)
			if err != nil {
				return basics.AccountData{}, err
			}

			assetParams[basics.AssetIndex(ca.Index)] = basics.AssetParams{
				Total:         ca.Params.Total,
				Decimals:      uint32(ca.Params.Decimals),
				DefaultFrozen: *ca.Params.DefaultFrozen,
				UnitName:      *ca.Params.UnitName,
				AssetName:     *ca.Params.Name,
				URL:           *ca.Params.Url,
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
			assets[basics.AssetIndex(h.AssetId)] = basics.AssetHolding{
				Amount: h.Amount,
				Frozen: h.IsFrozen,
			}
		}
	}

	convertTKV := func(akvs *generated.TealKeyValueStore) basics.TealKeyValue {
		if len(*akvs) == 0 {
			return nil
		}

		tkv := make(basics.TealKeyValue)
		for _, kv := range *akvs {
			tkv[kv.Key] = basics.TealValue{
				Type:  basics.TealType(kv.Value.Type),
				Uint:  kv.Value.Uint,
				Bytes: kv.Value.Bytes,
			}
		}
		return tkv
	}

	var appLocalStates map[basics.AppIndex]basics.AppLocalState
	if a.AppsLocalState != nil && len(*a.AppsLocalState) > 0 {
		appLocalStates = make(map[basics.AppIndex]basics.AppLocalState, len(*a.AppsLocalState))
		for _, ls := range *a.AppsLocalState {
			appLocalStates[basics.AppIndex(ls.AppIndex)] = basics.AppLocalState{
				Schema: basics.StateSchema{
					NumUint:      ls.State.Schema.NumUint,
					NumByteSlice: ls.State.Schema.NumByteSlice,
				},
				KeyValue: convertTKV(&ls.State.KeyValue),
			}
		}
	}

	var appParams map[basics.AppIndex]basics.AppParams
	if a.CreatedApps != nil && len(*a.CreatedApps) > 0 {
		appParams = make(map[basics.AppIndex]basics.AppParams, len(*a.CreatedApps))
		for _, params := range *a.CreatedApps {
			appParams[basics.AppIndex(params.AppIndex)] = basics.AppParams{
				ApprovalProgram:   params.AppParams.ApprovalProgram,
				ClearStateProgram: params.AppParams.ClearStateProgram,
				LocalStateSchema: basics.StateSchema{
					NumUint:      params.AppParams.LocalStateSchema.NumUint,
					NumByteSlice: params.AppParams.LocalStateSchema.NumByteSlice,
				},
				GlobalStateSchema: basics.StateSchema{
					NumUint:      params.AppParams.GlobalStateSchema.NumUint,
					NumByteSlice: params.AppParams.GlobalStateSchema.NumByteSlice,
				},
				GlobalState: convertTKV(params.AppParams.GlobalState),
			}
		}
	}

	totalSchema := basics.StateSchema{}
	if a.AppsTotalSchema != nil {
		totalSchema.NumUint = a.AppsTotalSchema.NumUint
		totalSchema.NumByteSlice = a.AppsTotalSchema.NumByteSlice
	}

	ad := basics.AccountData{
		Status:             basics.UnmarshalStatus(a.Status),
		MicroAlgos:         basics.MicroAlgos{Raw: a.Amount},
		RewardsBase:        rewardsBase,
		RewardedMicroAlgos: basics.MicroAlgos{Raw: a.Rewards},
		VoteID:             voteID,
		SelectionID:        selID,
		VoteFirstValid:     voteFirstValid,
		VoteLastValid:      voteLastValid,
		VoteKeyDilution:    voteKeyDilution,
		Assets:             assets,
		AppLocalStates:     appLocalStates,
		AppParams:          appParams,
		TotalAppSchema:     totalSchema,
	}

	if a.SpendingKey != nil {
		spendingKey, err := basics.UnmarshalChecksumAddress(*a.SpendingKey)
		if err != nil {
			return basics.AccountData{}, err
		}
		ad.SpendingKey = spendingKey
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
