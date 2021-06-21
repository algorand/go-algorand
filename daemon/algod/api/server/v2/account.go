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

package v2

import (
	"encoding/base64"
	"errors"
	"math"
	"sort"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
)

// AccountDataToAccount converts basics.AccountData to v2.generated.Account
func AccountDataToAccount(
	address string, record *basics.AccountData, assetsCreators map[basics.AssetIndex]string,
	lastRound basics.Round, amountWithoutPendingRewards basics.MicroAlgos,
) (generated.Account, error) {

	assets := make([]generated.AssetHolding, 0, len(record.Assets))
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
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].AssetId < assets[j].AssetId
	})

	createdAssets := make([]generated.Asset, 0, len(record.AssetParams))
	for idx, params := range record.AssetParams {
		asset := AssetParamsToAsset(address, idx, &params)
		createdAssets = append(createdAssets, asset)
	}
	sort.Slice(createdAssets, func(i, j int) bool {
		return createdAssets[i].Index < createdAssets[j].Index
	})

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

	createdApps := make([]generated.Application, 0, len(record.AppParams))
	for appIdx, appParams := range record.AppParams {
		app := AppParamsToApplication(address, appIdx, &appParams)
		createdApps = append(createdApps, app)
	}
	sort.Slice(createdApps, func(i, j int) bool {
		return createdApps[i].Id < createdApps[j].Id
	})

	appsLocalState := make([]generated.ApplicationLocalState, 0, len(record.AppLocalStates))
	for appIdx, state := range record.AppLocalStates {
		localState := convertTKVToGenerated(&state.KeyValue)
		appsLocalState = append(appsLocalState, generated.ApplicationLocalState{
			Id:       uint64(appIdx),
			KeyValue: localState,
			Schema: generated.ApplicationStateSchema{
				NumByteSlice: state.Schema.NumByteSlice,
				NumUint:      state.Schema.NumUint,
			},
		})
	}
	sort.Slice(appsLocalState, func(i, j int) bool {
		return appsLocalState[i].Id < appsLocalState[j].Id
	})

	totalAppSchema := generated.ApplicationStateSchema{
		NumByteSlice: record.TotalAppSchema.NumByteSlice,
		NumUint:      record.TotalAppSchema.NumUint,
	}
	totalExtraPages := uint64(record.TotalExtraAppPages)

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
		CreatedApps:                 &createdApps,
		Assets:                      &assets,
		AuthAddr:                    addrOrNil(record.AuthAddr),
		AppsLocalState:              &appsLocalState,
		AppsTotalSchema:             &totalAppSchema,
		AppsTotalExtraPages:         &totalExtraPages,
	}, nil
}

func convertTKVToGenerated(tkv *basics.TealKeyValue) *generated.TealKeyValueStore {
	if tkv == nil || len(*tkv) == 0 {
		return nil
	}

	converted := make(generated.TealKeyValueStore, 0, len(*tkv))
	rawKeyBytes := make([]string, 0, len(*tkv))
	for k, v := range *tkv {
		converted = append(converted, generated.TealKeyValue{
			Key: base64.StdEncoding.EncodeToString([]byte(k)),
			Value: generated.TealValue{
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

func convertGeneratedTKV(akvs *generated.TealKeyValueStore) (basics.TealKeyValue, error) {
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
		var err error
		for _, ca := range *a.CreatedAssets {
			var metadataHash [32]byte
			if ca.Params.MetadataHash != nil {
				copy(metadataHash[:], *ca.Params.MetadataHash)
			}
			var manager, reserve, freeze, clawback basics.Address
			if ca.Params.Manager != nil {
				if manager, err = basics.UnmarshalChecksumAddress(*ca.Params.Manager); err != nil {
					return basics.AccountData{}, err
				}
			}
			if ca.Params.Reserve != nil {
				if reserve, err = basics.UnmarshalChecksumAddress(*ca.Params.Reserve); err != nil {
					return basics.AccountData{}, err
				}
			}
			if ca.Params.Freeze != nil {
				if freeze, err = basics.UnmarshalChecksumAddress(*ca.Params.Freeze); err != nil {
					return basics.AccountData{}, err
				}
			}
			if ca.Params.Clawback != nil {
				if clawback, err = basics.UnmarshalChecksumAddress(*ca.Params.Clawback); err != nil {
					return basics.AccountData{}, err
				}
			}

			var defaultFrozen bool
			if ca.Params.DefaultFrozen != nil {
				defaultFrozen = *ca.Params.DefaultFrozen
			}
			var url string
			if ca.Params.Url != nil {
				url = *ca.Params.Url
			}
			var unitName string
			if ca.Params.UnitName != nil {
				unitName = *ca.Params.UnitName
			}
			var name string
			if ca.Params.Name != nil {
				name = *ca.Params.Name
			}

			assetParams[basics.AssetIndex(ca.Index)] = basics.AssetParams{
				Total:         ca.Params.Total,
				Decimals:      uint32(ca.Params.Decimals),
				DefaultFrozen: defaultFrozen,
				UnitName:      unitName,
				AssetName:     name,
				URL:           url,
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

	var appLocalStates map[basics.AppIndex]basics.AppLocalState
	if a.AppsLocalState != nil && len(*a.AppsLocalState) > 0 {
		appLocalStates = make(map[basics.AppIndex]basics.AppLocalState, len(*a.AppsLocalState))
		for _, ls := range *a.AppsLocalState {
			kv, err := convertGeneratedTKV(ls.KeyValue)
			if err != nil {
				return basics.AccountData{}, err
			}
			appLocalStates[basics.AppIndex(ls.Id)] = basics.AppLocalState{
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
			appParams[basics.AppIndex(params.Id)] = ap
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
		VoteID:             voteID,
		SelectionID:        selID,
		VoteFirstValid:     voteFirstValid,
		VoteLastValid:      voteLastValid,
		VoteKeyDilution:    voteKeyDilution,
		Assets:             assets,
		AppLocalStates:     appLocalStates,
		AppParams:          appParams,
		TotalAppSchema:     totalSchema,
		TotalExtraAppPages: totalExtraPages,
	}

	if a.AuthAddr != nil {
		authAddr, err := basics.UnmarshalChecksumAddress(*a.AuthAddr)
		if err != nil {
			return basics.AccountData{}, err
		}
		ad.AuthAddr = authAddr
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

// ApplicationParamsToAppParams converts generated.ApplicationParams to basics.AppParams
func ApplicationParamsToAppParams(gap *generated.ApplicationParams) (basics.AppParams, error) {
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

	return ap, nil
}

// AppParamsToApplication converts basics.AppParams to generated.Application
func AppParamsToApplication(creator string, appIdx basics.AppIndex, appParams *basics.AppParams) generated.Application {
	globalState := convertTKVToGenerated(&appParams.GlobalState)
	extraProgramPages := uint64(appParams.ExtraProgramPages)
	return generated.Application{
		Id: uint64(appIdx),
		Params: generated.ApplicationParams{
			Creator:           creator,
			ApprovalProgram:   appParams.ApprovalProgram,
			ClearStateProgram: appParams.ClearStateProgram,
			ExtraProgramPages: &extraProgramPages,
			GlobalState:       globalState,
			LocalStateSchema: &generated.ApplicationStateSchema{
				NumByteSlice: appParams.LocalStateSchema.NumByteSlice,
				NumUint:      appParams.LocalStateSchema.NumUint,
			},
			GlobalStateSchema: &generated.ApplicationStateSchema{
				NumByteSlice: appParams.GlobalStateSchema.NumByteSlice,
				NumUint:      appParams.GlobalStateSchema.NumUint,
			},
		},
	}
}

// AssetParamsToAsset converts basics.AssetParams to generated.Asset
func AssetParamsToAsset(creator string, idx basics.AssetIndex, params *basics.AssetParams) generated.Asset {
	frozen := params.DefaultFrozen
	assetParams := generated.AssetParams{
		Creator:       creator,
		Total:         params.Total,
		Decimals:      uint64(params.Decimals),
		DefaultFrozen: &frozen,
		Name:          strOrNil(params.AssetName),
		UnitName:      strOrNil(params.UnitName),
		Url:           strOrNil(params.URL),
		Clawback:      addrOrNil(params.Clawback),
		Freeze:        addrOrNil(params.Freeze),
		Manager:       addrOrNil(params.Manager),
		Reserve:       addrOrNil(params.Reserve),
	}
	if params.MetadataHash != ([32]byte{}) {
		metadataHash := make([]byte, len(params.MetadataHash))
		copy(metadataHash, params.MetadataHash[:])
		assetParams.MetadataHash = &metadataHash
	}

	return generated.Asset{
		Index:  uint64(idx),
		Params: assetParams,
	}
}
