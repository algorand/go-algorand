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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/sync/semaphore"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	specv2 "github.com/algorand/go-algorand/daemon/algod/api/spec/v2"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/libgoal/participation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/stateproof"
	"github.com/algorand/go-algorand/util"
)

// MaxTealSourceBytes sets a size limit for TEAL source programs for requests
// Max TEAL program size is currently 8k
// but we allow for comments, spacing, and repeated consts
// in the source TEAL. We have some indication that real TEAL programs with comments are about 20 times bigger than the bytecode they produce, and we may soon allow 16,000 byte logicsigs, implying a maximum of 320kb. Let's call it half a meg for a little room to spare.
const MaxTealSourceBytes = 512 * 1024

// MaxTealDryrunBytes sets a size limit for dryrun requests
// With the ability to hold unlimited assets DryrunRequests can
// become quite large, so we allow up to 1MB
const MaxTealDryrunBytes = 1_000_000

// MaxAssetResults sets a size limit for the number of assets returned in a single request to the
// /v2/accounts/{address}/assets endpoint
const MaxAssetResults = 1000

// DefaultAssetResults sets a default size limit for the number of assets returned in a single request to the
// /v2/accounts/{address}/assets endpoint
const DefaultAssetResults = uint64(1000)

const (
	errInvalidLimit      = "limit parameter must be a positive integer"
	errUnableToParseNext = "unable to parse next token"
)

// WaitForBlockTimeout is the timeout for the WaitForBlock endpoint.
var WaitForBlockTimeout = 1 * time.Minute

// Handlers is an implementation to the V2 route handler interface defined by the generated code.
type Handlers struct {
	Node     NodeInterface
	Log      logging.Logger
	Shutdown <-chan struct{}

	// KeygenLimiter is used to limit the number of concurrent key generation requests.
	KeygenLimiter *semaphore.Weighted
}

// LedgerForAPI describes the Ledger methods used by the v2 API.
type LedgerForAPI interface {
	LookupAccount(round basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, basics.MicroAlgos, error)
	LookupLatest(addr basics.Address) (basics.AccountData, basics.Round, basics.MicroAlgos, error)
	LookupKv(round basics.Round, key string) ([]byte, error)
	LookupKeysByPrefix(round basics.Round, keyPrefix string, maxKeyNum uint64) ([]string, error)
	ConsensusParams(r basics.Round) (config.ConsensusParams, error)
	Latest() basics.Round
	LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error)
	LookupAssets(addr basics.Address, assetIDGT basics.AssetIndex, limit uint64) ([]ledgercore.AssetResourceWithIDs, basics.Round, error)
	LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error)
	BlockCert(rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error)
	LatestTotals() (basics.Round, ledgercore.AccountTotals, error)
	BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error)
	Wait(r basics.Round) chan struct{}
	WaitWithCancel(r basics.Round) (chan struct{}, func())
	GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)
	EncodedBlockCert(rnd basics.Round) (blk []byte, cert []byte, err error)
	Block(rnd basics.Round) (blk bookkeeping.Block, err error)
	TxnsFrom(id basics.Address, r basics.Round) ([]transactions.Transaction, error)
	GetStateDeltaForRound(rnd basics.Round) (ledgercore.StateDelta, error)
	GetTracer() logic.EvalTracer
}

// NodeInterface represents node fns used by the handlers.
type NodeInterface interface {
	LedgerForAPI() LedgerForAPI
	Status() (s node.StatusReport, err error)
	GenesisID() string
	GenesisHash() crypto.Digest
	BroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error
	AsyncBroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error
	Simulate(request simulation.Request) (result simulation.Result, err error)
	GetPeers() (inboundPeers []network.Peer, outboundPeers []network.Peer, err error)
	GetPendingTransaction(txID transactions.Txid) (res node.TxnWithStatus, found bool)
	GetPendingTxnsFromPool() ([]transactions.SignedTxn, error)
	SuggestedFee() basics.MicroAlgos
	StartCatchup(catchpoint string) error
	AbortCatchup(catchpoint string) error
	Config() config.Local
	InstallParticipationKey(partKeyBinary []byte) (account.ParticipationID, error)
	ListParticipationKeys() ([]account.ParticipationRecord, error)
	GetParticipationKey(account.ParticipationID) (account.ParticipationRecord, error)
	RemoveParticipationKey(account.ParticipationID) error
	AppendParticipationKeys(id account.ParticipationID, keys account.StateProofKeys) error
	SetSyncRound(rnd basics.Round) error
	GetSyncRound() basics.Round
	UnsetSyncRound()
	GetBlockTimeStampOffset() (*int64, error)
	SetBlockTimeStampOffset(int64) error
}

func convertParticipationRecord(record account.ParticipationRecord) model.ParticipationKey {
	participationKey := model.ParticipationKey{
		Id:      record.ParticipationID.String(),
		Address: record.Account.String(),
		Key: model.AccountParticipation{
			VoteFirstValid:  record.FirstValid,
			VoteLastValid:   record.LastValid,
			VoteKeyDilution: record.KeyDilution,
		},
	}

	if record.StateProof != nil {
		tmp := record.StateProof.Commitment[:]
		participationKey.Key.StateProofKey = &tmp
	}

	// These are pointers but should always be present.
	if record.Voting != nil {
		participationKey.Key.VoteParticipationKey = record.Voting.OneTimeSignatureVerifier[:]
	}
	if record.VRF != nil {
		participationKey.Key.SelectionParticipationKey = record.VRF.PK[:]
	}

	// Optional fields.
	if record.EffectiveLast != 0 && record.EffectiveFirst == 0 {
		// Special case for first valid on round 0
		zero := basics.Round(0)
		participationKey.EffectiveFirstValid = &zero
	} else {
		participationKey.EffectiveFirstValid = omitEmpty(record.EffectiveFirst)
	}
	participationKey.EffectiveLastValid = omitEmpty(record.EffectiveLast)
	participationKey.LastVote = omitEmpty(record.LastVote)
	participationKey.LastBlockProposal = omitEmpty(record.LastBlockProposal)
	participationKey.LastVote = omitEmpty(record.LastVote)
	participationKey.LastStateProof = omitEmpty(record.LastStateProof)

	return participationKey
}

// ErrNoStateProofForRound returned when a state proof transaction could not be found
var ErrNoStateProofForRound = errors.New("no state proof can be found for that round")

// ErrTimeout indicates a task took too long, and the server canceled it.
var ErrTimeout = errors.New("timed out on request")

// ErrShutdown represents the error for the string errServiceShuttingDown
var ErrShutdown = errors.New(errServiceShuttingDown)

// GetStateProofTransactionForRound searches for a state proof transaction that can be used to prove on the given round (i.e the round is within the
// attestation period). the latestRound should be provided as an upper bound for the search
func GetStateProofTransactionForRound(ctx context.Context, txnFetcher LedgerForAPI, round, latestRound basics.Round, stop <-chan struct{}) (transactions.Transaction, error) {
	hdr, err := txnFetcher.BlockHdr(round)
	if err != nil {
		return transactions.Transaction{}, err
	}

	if config.Consensus[hdr.CurrentProtocol].StateProofInterval == 0 {
		return transactions.Transaction{}, ErrNoStateProofForRound
	}

	for i := round + 1; i <= latestRound; i++ {
		select {
		case <-stop:
			return transactions.Transaction{}, ErrShutdown
		case <-ctx.Done():
			return transactions.Transaction{}, ErrTimeout
		default:
		}

		txns, err := txnFetcher.TxnsFrom(transactions.StateProofSender, i)
		if err != nil {
			return transactions.Transaction{}, err
		}
		for _, txn := range txns {
			if txn.Type != protocol.StateProofTx {
				continue
			}

			if txn.StateProofTxnFields.Message.FirstAttestedRound <= round &&
				round <= txn.StateProofTxnFields.Message.LastAttestedRound {
				return txn, nil
			}
		}
	}
	return transactions.Transaction{}, ErrNoStateProofForRound
}

// GetParticipationKeys Return a list of participation keys
// (GET /v2/participation)
func (v2 *Handlers) GetParticipationKeys(ctx echo.Context) error {
	partKeys, err := v2.Node.ListParticipationKeys()

	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	var response []model.ParticipationKey

	for _, participationRecord := range partKeys {
		response = append(response, convertParticipationRecord(participationRecord))
	}

	return ctx.JSON(http.StatusOK, response)
}

func (v2 *Handlers) generateKeyHandler(address basics.Address, params model.GenerateParticipationKeysParams) error {
	installFunc := func(path string) error {
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		partKeyBinary := bytes

		if len(partKeyBinary) == 0 {
			return fmt.Errorf("cannot install partkey '%s' is empty", partKeyBinary)
		}

		partID, err := v2.Node.InstallParticipationKey(partKeyBinary)
		v2.Log.Infof("Installed participation key %s", partID)
		return err
	}
	_, _, err := participation.GenParticipationKeysTo(address.String(), params.First, params.Last, nilToZero(params.Dilution), "", installFunc)
	return err
}

// GenerateParticipationKeys generates and installs participation keys to the node.
// (POST /v2/participation/generate/{address})
func (v2 *Handlers) GenerateParticipationKeys(ctx echo.Context, address basics.Address, params model.GenerateParticipationKeysParams) error {
	if !v2.KeygenLimiter.TryAcquire(1) {
		err := fmt.Errorf("participation key generation already in progress")
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	// Semaphore was acquired, generate the key.
	go func() {
		defer v2.KeygenLimiter.Release(1)
		err := v2.generateKeyHandler(address, params)
		if err != nil {
			v2.Log.Warnf("Error generating participation keys: %v", err)
		}
	}()

	// Empty object. In the future we may want to add a field for the participation ID.
	return ctx.String(http.StatusOK, "{}")
}

// AddParticipationKey Add a participation key to the node
// (POST /v2/participation)
func (v2 *Handlers) AddParticipationKey(ctx echo.Context) error {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(ctx.Request().Body)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	partKeyBinary := buf.Bytes()

	if len(partKeyBinary) == 0 {
		lenErr := errors.New(errRESTPayloadZeroLength)
		return badRequest(ctx, lenErr, lenErr.Error(), v2.Log)
	}

	partID, err := v2.Node.InstallParticipationKey(partKeyBinary)

	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	response := model.PostParticipationResponse{PartId: partID.String()}
	return ctx.JSON(http.StatusOK, response)

}

// DeleteParticipationKeyByID Delete a given participation key by id
// (DELETE /v2/participation/{participation-id})
func (v2 *Handlers) DeleteParticipationKeyByID(ctx echo.Context, participationID string) error {

	decodedParticipationID, err := account.ParseParticipationID(participationID)

	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	err = v2.Node.RemoveParticipationKey(decodedParticipationID)

	if err != nil {
		if errors.Is(err, account.ErrParticipationIDNotFound) {
			return notFound(ctx, account.ErrParticipationIDNotFound, "participation id not found", v2.Log)
		}

		return internalError(ctx, err, err.Error(), v2.Log)
	}

	return ctx.NoContent(http.StatusOK)
}

// GetParticipationKeyByID Get participation key info by id
// (GET /v2/participation/{participation-id})
func (v2 *Handlers) GetParticipationKeyByID(ctx echo.Context, participationID string) error {

	decodedParticipationID, err := account.ParseParticipationID(participationID)

	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	participationRecord, err := v2.Node.GetParticipationKey(decodedParticipationID)

	if err != nil {
		return internalError(ctx, err, err.Error(), v2.Log)
	}

	if participationRecord.IsZero() {
		return notFound(ctx, account.ErrParticipationIDNotFound, account.ErrParticipationIDNotFound.Error(), v2.Log)
	}

	response := convertParticipationRecord(participationRecord)

	return ctx.JSON(http.StatusOK, response)
}

// AppendKeys Append state proof keys to a participation key
// (POST /v2/participation/{participation-id})
func (v2 *Handlers) AppendKeys(ctx echo.Context, participationID string) error {
	decodedParticipationID, err := account.ParseParticipationID(participationID)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	var keys account.StateProofKeys
	dec := protocol.NewDecoder(ctx.Request().Body)
	err = dec.Decode(&keys)
	if err != nil {
		err = fmt.Errorf("unable to parse keys from body: %w", err)
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	if len(keys) == 0 {
		err = errors.New("empty request, please attach keys to request body")
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	err = v2.Node.AppendParticipationKeys(decodedParticipationID, keys)
	if err != nil {
		return internalError(ctx, err, err.Error(), v2.Log)
	}
	return nil
}

// ShutdownNode shuts down the node.
// (POST /v2/shutdown)
// Deprecated: use ShutdownNode2 instead.
func (v2 *Handlers) ShutdownNode(ctx echo.Context, params model.ShutdownNodeParams) error {
	return v2.ShutdownNode2(ctx, (model.ShutdownNode2Params)(params))
}

// ShutdownNode2 shuts down the node.
// (POST /v2/node/shutdown)
func (v2 *Handlers) ShutdownNode2(ctx echo.Context, params model.ShutdownNode2Params) error {
	// TODO: shutdown endpoint
	return ctx.String(http.StatusNotImplemented, "Endpoint not implemented.")
}

// AccountInformation gets account information for a given account.
// (GET /v2/accounts/{address})
func (v2 *Handlers) AccountInformation(ctx echo.Context, address basics.Address, params model.AccountInformationParams) error {
	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	// should we skip fetching apps and assets?
	if params.Exclude != nil {
		switch *params.Exclude {
		case "all":
			return v2.basicAccountInformation(ctx, address, handle, contentType)
		case "none", "":
		default:
			return badRequest(ctx, err, errFailedToParseExclude, v2.Log)
		}
	}

	myLedger := v2.Node.LedgerForAPI()

	// count total # of resources, if max limit is set
	if maxResults := v2.Node.Config().MaxAPIResourcesPerAccount; maxResults != 0 {
		record, _, _, lookupErr := myLedger.LookupAccount(myLedger.Latest(), address)
		if lookupErr != nil {
			return internalError(ctx, lookupErr, errFailedLookingUpLedger, v2.Log)
		}
		totalResults := record.TotalAssets + record.TotalAssetParams + record.TotalAppLocalStates + record.TotalAppParams
		if totalResults > maxResults {
			v2.Log.Infof("MaxAccountAPIResults limit %d exceeded, total results %d", maxResults, totalResults)
			extraData := map[string]any{
				"max-results":           maxResults,
				"total-assets-opted-in": record.TotalAssets,
				"total-created-assets":  record.TotalAssetParams,
				"total-apps-opted-in":   record.TotalAppLocalStates,
				"total-created-apps":    record.TotalAppParams,
			}
			return ctx.JSON(http.StatusBadRequest, model.ErrorResponse{
				Message: "Result limit exceeded",
				Data:    &extraData,
			})
		}
	}

	record, lastRound, amountWithoutPendingRewards, err := myLedger.LookupLatest(address)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	// check against configured total limit on assets/apps
	if handle == protocol.CodecHandle {
		data, err1 := encode(handle, record)
		if err1 != nil {
			return internalError(ctx, err1, errFailedToEncodeResponse, v2.Log)
		}
		return ctx.Blob(http.StatusOK, contentType, data)
	}

	consensus, err := myLedger.ConsensusParams(lastRound)
	if err != nil {
		return internalError(ctx, err, fmt.Sprintf("could not retrieve consensus information for last round (%d)", lastRound), v2.Log)
	}

	account, err := AccountDataToAccount(address.String(), &record, lastRound, &consensus, amountWithoutPendingRewards)
	if err != nil {
		return internalError(ctx, err, errInternalFailure, v2.Log)
	}

	response := model.AccountResponse(account)
	return ctx.JSON(http.StatusOK, response)
}

// basicAccountInformation handles the case when no resources (assets or apps) are requested.
func (v2 *Handlers) basicAccountInformation(ctx echo.Context, addr basics.Address, handle codec.Handle, contentType string) error {
	myLedger := v2.Node.LedgerForAPI()
	record, lastRound, amountWithoutPendingRewards, err := myLedger.LookupAccount(myLedger.Latest(), addr)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if handle == protocol.CodecHandle {
		data, encErr := encode(handle, record)
		if encErr != nil {
			return internalError(ctx, encErr, errFailedToEncodeResponse, v2.Log)
		}
		return ctx.Blob(http.StatusOK, contentType, data)
	}

	consensus, err := myLedger.ConsensusParams(lastRound)
	if err != nil {
		return internalError(ctx, err, fmt.Sprintf("could not retrieve consensus information for last round (%d)", lastRound), v2.Log)
	}

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

	pendingRewards, overflowed := basics.OSubA(record.MicroAlgos, amountWithoutPendingRewards)
	if overflowed {
		return internalError(ctx, errors.New("overflow on pending reward calculation"), errInternalFailure, v2.Log)
	}

	account := model.Account{
		SigType:                     nil,
		Round:                       lastRound,
		Address:                     addr.String(),
		Amount:                      record.MicroAlgos.Raw,
		PendingRewards:              pendingRewards.Raw,
		AmountWithoutPendingRewards: amountWithoutPendingRewards.Raw,
		Rewards:                     record.RewardedMicroAlgos.Raw,
		Status:                      record.Status.String(),
		RewardBase:                  &record.RewardsBase,
		Participation:               apiParticipation,
		IncentiveEligible:           omitEmpty(record.IncentiveEligible),
		TotalCreatedAssets:          record.TotalAssetParams,
		TotalCreatedApps:            record.TotalAppParams,
		TotalAssetsOptedIn:          record.TotalAssets,
		AuthAddr:                    addrOrNil(record.AuthAddr),
		TotalAppsOptedIn:            record.TotalAppLocalStates,
		AppsTotalSchema: &model.ApplicationStateSchema{
			NumByteSlice: record.TotalAppSchema.NumByteSlice,
			NumUint:      record.TotalAppSchema.NumUint,
		},
		AppsTotalExtraPages: omitEmpty(uint64(record.TotalExtraAppPages)),
		TotalBoxes:          omitEmpty(record.TotalBoxes),
		TotalBoxBytes:       omitEmpty(record.TotalBoxBytes),
		MinBalance:          record.MinBalance(&consensus).Raw,
		LastProposed:        omitEmpty(record.LastProposed),
		LastHeartbeat:       omitEmpty(record.LastHeartbeat),
	}
	response := model.AccountResponse(account)
	return ctx.JSON(http.StatusOK, response)
}

// AccountAssetInformation gets account information about a given asset.
// (GET /v2/accounts/{address}/assets/{asset-id})
func (v2 *Handlers) AccountAssetInformation(ctx echo.Context, address basics.Address, assetID basics.AssetIndex, params model.AccountAssetInformationParams) error {
	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	ledger := v2.Node.LedgerForAPI()

	lastRound := ledger.Latest()
	record, err := ledger.LookupAsset(lastRound, address, assetID)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if record.AssetParams == nil && record.AssetHolding == nil {
		return notFound(ctx, errors.New(errAccountAssetDoesNotExist), errAccountAssetDoesNotExist, v2.Log)
	}

	// return msgpack response
	if handle == protocol.CodecHandle {
		data, err := encode(handle, specv2.AssetResourceToAccountAssetModel(record))
		if err != nil {
			return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
		}
		return ctx.Blob(http.StatusOK, contentType, data)
	}

	// prepare JSON response
	response := model.AccountAssetResponse{Round: lastRound}

	if record.AssetParams != nil {
		asset := AssetParamsToAsset(address.String(), assetID, record.AssetParams)
		response.CreatedAsset = &asset.Params
	}

	if record.AssetHolding != nil {
		response.AssetHolding = &model.AssetHolding{
			Amount:   record.AssetHolding.Amount,
			AssetID:  assetID,
			IsFrozen: record.AssetHolding.Frozen,
		}
	}

	return ctx.JSON(http.StatusOK, response)
}

// AccountApplicationInformation gets account information about a given app.
// (GET /v2/accounts/{address}/applications/{application-id})
func (v2 *Handlers) AccountApplicationInformation(ctx echo.Context, address basics.Address, applicationID basics.AppIndex, params model.AccountApplicationInformationParams) error {
	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	ledger := v2.Node.LedgerForAPI()

	lastRound := ledger.Latest()
	record, err := ledger.LookupApplication(lastRound, address, applicationID)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if record.AppParams == nil && record.AppLocalState == nil {
		return notFound(ctx, errors.New(errAccountAppDoesNotExist), errAccountAppDoesNotExist, v2.Log)
	}

	// return msgpack response
	if handle == protocol.CodecHandle {
		data, err := encode(handle, specv2.AppResourceToAccountApplicationModel(record))
		if err != nil {
			return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
		}
		return ctx.Blob(http.StatusOK, contentType, data)
	}

	// prepare JSON response
	response := model.AccountApplicationResponse{Round: lastRound}

	if record.AppParams != nil {
		app := AppParamsToApplication(address.String(), applicationID, record.AppParams)
		response.CreatedApp = &app.Params
	}

	if record.AppLocalState != nil {
		localState := convertTKVToGenerated(&record.AppLocalState.KeyValue)
		response.AppLocalState = &model.ApplicationLocalState{
			Id:       applicationID,
			KeyValue: localState,
			Schema: model.ApplicationStateSchema{
				NumByteSlice: record.AppLocalState.Schema.NumByteSlice,
				NumUint:      record.AppLocalState.Schema.NumUint,
			},
		}
	}

	return ctx.JSON(http.StatusOK, response)
}

// BlockResponseJSON is used to embed the block in JSON responses.
type BlockResponseJSON struct {
	Block bookkeeping.Block `codec:"block"`
}

// GetBlock gets the block for the given round.
// (GET /v2/blocks/{round})
func (v2 *Handlers) GetBlock(ctx echo.Context, round basics.Round, params model.GetBlockParams) error {
	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	// For a future iteration/V3, we should make the available data for this endpoint consistent between messagepack and JSON.
	// Currently, the certificate is only returned in messagepack format requests for a complete block.
	// The 'getBlockHeader' function is used to get the block header only; this is currently consistent between messagepack and JSON.

	// If the client requests block header only, process that
	if params.HeaderOnly != nil && *params.HeaderOnly {
		return v2.getBlockHeader(ctx, round, handle, contentType)
	}

	// msgpack format uses 'RawBlockBytes' and attaches a custom header.
	if handle == protocol.CodecHandle {
		blockbytes, blockErr := rpcs.RawBlockBytes(v2.Node.LedgerForAPI(), round)
		if blockErr != nil {
			switch blockErr.(type) {
			case ledgercore.ErrNoEntry:
				return notFound(ctx, blockErr, errFailedLookingUpLedger, v2.Log)
			default:
				return internalError(ctx, blockErr, blockErr.Error(), v2.Log)
			}
		}

		ctx.Response().Writer.Header().Add("X-Algorand-Struct", "block-v1")
		return ctx.Blob(http.StatusOK, contentType, blockbytes)
	}

	ledger := v2.Node.LedgerForAPI()
	block, err := ledger.Block(round)
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			return notFound(ctx, err, errFailedLookingUpLedger, v2.Log)
		default:
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
	}

	// Encoding wasn't working well without embedding "real" objects.
	response := BlockResponseJSON{
		Block: block,
	}

	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, data)
}

func (v2 *Handlers) getBlockHeader(ctx echo.Context, round basics.Round, handle codec.Handle, contentType string) error {
	ledger := v2.Node.LedgerForAPI()
	block, err := ledger.BlockHdr(round)
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			return notFound(ctx, err, errFailedLookingUpLedger, v2.Log)
		default:
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
	}

	response := struct {
		Block bookkeeping.BlockHeader `codec:"block"`
	}{
		Block: block,
	}

	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, data)
}

// GetBlockTxids gets all top level TxIDs in a block for the given round.
// (GET /v2/blocks/{round}/txids)
func (v2 *Handlers) GetBlockTxids(ctx echo.Context, round basics.Round) error {
	ledger := v2.Node.LedgerForAPI()
	block, err := ledger.Block(round)
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			return notFound(ctx, err, errFailedLookingUpLedger, v2.Log)
		default:
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
	}

	txns, err := block.DecodePaysetFlat()
	if err != nil {
		return internalError(ctx, err, "decoding transactions", v2.Log)
	}

	txids := make([]string, 0, len(txns))
	for ids := range txns {
		txids = append(txids, txns[ids].ID().String())
	}

	response := model.BlockTxidsResponse{BlockTxids: txids}

	return ctx.JSON(http.StatusOK, response)
}

// NewAppCallLogs generates a new model.AppCallLogs struct.
func NewAppCallLogs(txid string, logs []string, appIndex basics.AppIndex) model.AppCallLogs {
	return model.AppCallLogs{
		TxId:             txid,
		Logs:             util.Map(logs, func(s string) []byte { return []byte(s) }),
		ApplicationIndex: appIndex,
	}
}

func getAppIndexFromTxn(txn transactions.SignedTxnWithAD) basics.AppIndex {
	appIndex := txn.SignedTxn.Txn.ApplicationID
	if appIndex == 0 {
		appIndex = txn.ApplyData.ApplicationID
	}

	return appIndex
}

func appendLogsFromTxns(blockLogs []model.AppCallLogs, txns []transactions.SignedTxnWithAD, outerTxnID string) []model.AppCallLogs {

	for _, txn := range txns {
		if len(txn.EvalDelta.Logs) > 0 {
			blockLogs = append(
				blockLogs,
				NewAppCallLogs(outerTxnID, txn.EvalDelta.Logs, getAppIndexFromTxn(txn)),
			)
		}

		blockLogs = appendLogsFromTxns(blockLogs, txn.EvalDelta.InnerTxns, outerTxnID)
	}

	return blockLogs
}

// GetBlockLogs gets all of the logs (inner and outer app calls) for a given block
// (GET /v2/blocks/{round}/logs)
func (v2 *Handlers) GetBlockLogs(ctx echo.Context, round basics.Round) error {
	ledger := v2.Node.LedgerForAPI()
	block, err := ledger.Block(round)
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			return notFound(ctx, err, errFailedLookingUpLedger, v2.Log)
		default:
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
	}

	txns, err := block.DecodePaysetFlat()
	if err != nil {
		return internalError(ctx, err, "decoding transactions", v2.Log)
	}

	blockLogs := []model.AppCallLogs{}

	for _, txn := range txns {
		blockLogs = appendLogsFromTxns(blockLogs, []transactions.SignedTxnWithAD{txn}, txn.ID().String())
	}

	response := model.BlockLogsResponse{Logs: blockLogs}

	return ctx.JSON(http.StatusOK, response)
}

// GetBlockHash gets the block hash for the given round.
// (GET /v2/blocks/{round}/hash)
func (v2 *Handlers) GetBlockHash(ctx echo.Context, round basics.Round) error {
	ledger := v2.Node.LedgerForAPI()
	block, err := ledger.Block(round)
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			return notFound(ctx, err, errFailedLookingUpLedger, v2.Log)
		default:
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
	}

	response := model.BlockHashResponse{BlockHash: crypto.Digest(block.Hash()).String()}

	return ctx.JSON(http.StatusOK, response)
}

// GetTransactionProof generates a Merkle proof for a transaction in a block.
// (GET /v2/blocks/{round}/transactions/{txid}/proof)
func (v2 *Handlers) GetTransactionProof(ctx echo.Context, round basics.Round, txid string, params model.GetTransactionProofParams) error {
	var txID transactions.Txid
	err := txID.FromString(txid)
	if err != nil {
		return badRequest(ctx, err, errNoValidTxnSpecified, v2.Log)
	}

	if params.Hashtype != nil && *params.Hashtype != "sha512_256" && *params.Hashtype != "sha256" {
		return badRequest(ctx, nil, errInvalidHashType, v2.Log)
	}

	ledger := v2.Node.LedgerForAPI()
	block, err := ledger.Block(round)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	proto := config.Consensus[block.CurrentProtocol]
	if proto.PaysetCommit != config.PaysetCommitMerkle {
		return notFound(ctx, err, "protocol does not support Merkle proofs", v2.Log)
	}

	hashtype := "sha512_256" // default hash type for proof
	if params.Hashtype != nil {
		hashtype = string(*params.Hashtype)
	}
	if hashtype == "sha256" && !proto.EnableSHA256TxnCommitmentHeader {
		return badRequest(ctx, err, "protocol does not support sha256 vector commitment proofs", v2.Log)
	}

	txns, err := block.DecodePaysetFlat()
	if err != nil {
		return internalError(ctx, err, "decoding transactions", v2.Log)
	}

	for idx := range txns {
		if txns[idx].ID() != txID {
			continue // skip
		}

		var tree *merklearray.Tree
		var stibhash crypto.Digest

		switch hashtype {
		case "sha256":
			tree, err = block.TxnMerkleTreeSHA256()
			if err != nil {
				return internalError(ctx, err, "building Vector Commitment (SHA256)", v2.Log)
			}
			stibhash = block.Payset[idx].HashSHA256()
		case "sha512_256":
			tree, err = block.TxnMerkleTree()
			if err != nil {
				return internalError(ctx, err, "building Merkle tree", v2.Log)
			}
			stibhash = block.Payset[idx].Hash()
		default:
			return badRequest(ctx, err, "unsupported hash type", v2.Log)
		}

		proof, proofErr := tree.ProveSingleLeaf(uint64(idx))
		if proofErr != nil {
			return internalError(ctx, proofErr, "generating proof", v2.Log)
		}

		response := model.TransactionProofResponse{
			Proof:     proof.GetConcatenatedProof(),
			Stibhash:  stibhash[:],
			Idx:       uint64(idx),
			Treedepth: uint64(proof.TreeDepth),
			Hashtype:  model.TransactionProofHashtype(hashtype),
		}

		return ctx.JSON(http.StatusOK, response)
	}

	err = errors.New(errTransactionNotFound)
	return notFound(ctx, err, err.Error(), v2.Log)
}

// GetSupply gets the current supply reported by the ledger.
// (GET /v2/ledger/supply)
func (v2 *Handlers) GetSupply(ctx echo.Context) error {
	latest, totals, err := v2.Node.LedgerForAPI().LatestTotals()
	if err != nil {
		err = fmt.Errorf("GetSupply(): round %d, failed: %v", latest, err)
		return internalError(ctx, err, errInternalFailure, v2.Log)
	}

	supply := model.SupplyResponse{
		CurrentRound: latest,
		TotalMoney:   totals.Participating().Raw,
		OnlineMoney:  totals.Online.Money.Raw,
	}

	return ctx.JSON(http.StatusOK, supply)
}

// GetPeers returns the list of connected peers.
// (GET /v2/node/peers)
func (v2 *Handlers) GetPeers(ctx echo.Context) error {

	// Get list of connected peers from the node
	inboundPeers, outboundPeers, err := v2.Node.GetPeers()
	if err != nil {
		return internalError(ctx, err, errFailedToGetPeers, v2.Log)
	}

	// Populate the response struct
	response := model.GetPeersResponse{
		Peers: make([]model.PeerStatus, 0, len(inboundPeers)+len(outboundPeers)),
	}
	response.Peers = filterPeers(inboundPeers, model.PeerStatusConnectionTypeInbound)
	response.Peers = append(response.Peers, filterPeers(outboundPeers, model.PeerStatusConnectionTypeOutbound)...)
	return ctx.JSON(http.StatusOK, response)
}

type PeerMap map[string]string

func (pm PeerMap) addPeer(addr string, network string) {
	if _, found := pm[addr]; !found {
		pm[addr] = network
		return
	}
	pm[addr] += "," + network
}

func filterPeers(peers []network.Peer, connType model.PeerStatusConnectionType) []model.PeerStatus {
	peerMap := make(PeerMap)

	for _, p := range peers {
		switch peer := p.(type) {
		case network.HTTPPeer:
			peerMap.addPeer(peer.GetAddress(), string(model.PeerStatusNetworkTypeWs))
		case network.UnicastPeer:
			peerMap.addPeer(peer.GetAddress(), string(model.PeerStatusNetworkTypeWs))
		case network.LibP2PPeer:
			peerMap.addPeer(peer.GetAddress(), string(model.PeerStatusNetworkTypeP2p))
		}
	}
	peerStatuses := make([]model.PeerStatus, len(peerMap))
	var i int = 0
	for addr := range peerMap {
		peerStatuses[i] = model.PeerStatus{
			ConnectionType: connType,
			NetworkAddress: addr,
			NetworkType:    model.PeerStatusNetworkType(peerMap[addr]),
		}
		i++
	}
	return peerStatuses
}

// GetStatus gets the current node status.
// (GET /v2/status)
func (v2 *Handlers) GetStatus(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}

	response := model.NodeStatusResponse{
		LastRound:                   stat.LastRound,
		LastVersion:                 string(stat.LastVersion),
		NextVersion:                 string(stat.NextVersion),
		NextVersionRound:            stat.NextVersionRound,
		NextVersionSupported:        stat.NextVersionSupported,
		TimeSinceLastRound:          stat.TimeSinceLastRound().Nanoseconds(),
		CatchupTime:                 stat.CatchupTime.Nanoseconds(),
		StoppedAtUnsupportedRound:   stat.StoppedAtUnsupportedRound,
		LastCatchpoint:              &stat.LastCatchpoint,
		Catchpoint:                  &stat.Catchpoint,
		CatchpointTotalAccounts:     &stat.CatchpointCatchupTotalAccounts,
		CatchpointProcessedAccounts: &stat.CatchpointCatchupProcessedAccounts,
		CatchpointVerifiedAccounts:  &stat.CatchpointCatchupVerifiedAccounts,
		CatchpointTotalKvs:          &stat.CatchpointCatchupTotalKVs,
		CatchpointProcessedKvs:      &stat.CatchpointCatchupProcessedKVs,
		CatchpointVerifiedKvs:       &stat.CatchpointCatchupVerifiedKVs,
		CatchpointTotalBlocks:       &stat.CatchpointCatchupTotalBlocks,
		CatchpointAcquiredBlocks:    &stat.CatchpointCatchupAcquiredBlocks,
	}

	// Make sure a vote is happening
	if stat.NextProtocolVoteBefore > 0 {
		votesToGo := basics.Round(0)
		// Check if the vote window is still open.
		if stat.NextProtocolVoteBefore > stat.LastRound {
			// subtract 1 because the variables are referring to "Last" round and "VoteBefore"
			votesToGo = stat.NextProtocolVoteBefore - stat.LastRound - 1
		}

		consensus := config.Consensus[protocol.ConsensusCurrentVersion]
		upgradeVoteRounds := basics.Round(consensus.UpgradeVoteRounds)
		upgradeThreshold := basics.Round(consensus.UpgradeThreshold)
		votes := basics.Round(consensus.UpgradeVoteRounds) - votesToGo
		votesYes := stat.NextProtocolApprovals
		votesNo := votes - votesYes
		upgradeDelay := stat.UpgradeDelay
		response.UpgradeVotesRequired = &upgradeThreshold
		response.UpgradeNodeVote = &stat.UpgradeApprove
		response.UpgradeDelay = &upgradeDelay
		response.UpgradeVotes = &votes
		response.UpgradeYesVotes = &votesYes
		response.UpgradeNoVotes = &votesNo
		response.UpgradeNextProtocolVoteBefore = omitEmpty(stat.NextProtocolVoteBefore)
		response.UpgradeVoteRounds = &upgradeVoteRounds
	}

	return ctx.JSON(http.StatusOK, response)
}

// WaitForBlock returns the node status after waiting for the given round.
// (GET /v2/status/wait-for-block-after/{round}/)
func (v2 *Handlers) WaitForBlock(ctx echo.Context, round basics.Round) error {
	ledger := v2.Node.LedgerForAPI()

	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.StoppedAtUnsupportedRound {
		return badRequest(ctx, err, errRequestedRoundInUnsupportedRound, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("WaitForBlock failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}

	latestBlkHdr, err := ledger.BlockHdr(ledger.Latest())
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingLatestBlockHeaderStatus, v2.Log)
	}
	if latestBlkHdr.NextProtocol != "" {
		if _, nextProtocolSupported := config.Consensus[latestBlkHdr.NextProtocol]; !nextProtocolSupported {
			// see if the desired protocol switch is expect to happen before or after the above point.
			if latestBlkHdr.NextProtocolSwitchOn <= round+1 {
				// we would never reach to this round, since this round would happen after the (unsupported) protocol upgrade.
				return badRequest(ctx, err, errRequestedRoundInUnsupportedRound, v2.Log)
			}
		}
	}

	// Wait
	ledgerWaitCh, cancelLedgerWait := ledger.WaitWithCancel(round + 1)
	defer cancelLedgerWait()
	select {
	case <-v2.Shutdown:
		return internalError(ctx, err, errServiceShuttingDown, v2.Log)
	case <-ctx.Request().Context().Done():
		return ctx.NoContent(http.StatusRequestTimeout)
	case <-time.After(WaitForBlockTimeout):
	case <-ledgerWaitCh:
	}

	// Return status after the wait
	return v2.GetStatus(ctx)
}

// decodeTxGroup attempts to decode a request body containing a transaction group.
func decodeTxGroup(body io.Reader, maxTxGroupSize int) ([]transactions.SignedTxn, error) {
	var txgroup []transactions.SignedTxn
	dec := protocol.NewDecoder(body)
	for {
		var st transactions.SignedTxn
		err := dec.Decode(&st)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		txgroup = append(txgroup, st)

		if len(txgroup) > maxTxGroupSize {
			err := fmt.Errorf("max group size is %d", maxTxGroupSize)
			return nil, err
		}
	}

	if len(txgroup) == 0 {
		return nil, errors.New("empty txgroup")
	}

	return txgroup, nil
}

// RawTransaction broadcasts a raw transaction to the network.
// (POST /v2/transactions)
func (v2 *Handlers) RawTransaction(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("RawTransaction failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}
	proto := config.Consensus[stat.LastVersion]

	txgroup, err := decodeTxGroup(ctx.Request().Body, proto.MaxTxGroupSize)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	err = v2.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	return ctx.JSON(http.StatusOK, model.PostTransactionsResponse{TxId: txid.String()})
}

// RawTransactionAsync broadcasts a raw transaction to the network without ensuring it is accepted by transaction pool.
// (POST /v2/transactions/async)
func (v2 *Handlers) RawTransactionAsync(ctx echo.Context) error {
	if !v2.Node.Config().EnableExperimentalAPI {
		return ctx.String(http.StatusNotFound, "/transactions/async was not enabled in the configuration file by setting the EnableExperimentalAPI to true")
	}
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/transactions/async was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	txgroup, err := decodeTxGroup(ctx.Request().Body, bounds.MaxTxGroupSize)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	err = v2.Node.AsyncBroadcastSignedTxGroup(txgroup)
	if err != nil {
		return serviceUnavailable(ctx, err, err.Error(), v2.Log)
	}
	return ctx.NoContent(http.StatusOK)
}

// AccountAssetsInformation looks up an account's asset holdings.
// (GET /v2/accounts/{address}/assets)
func (v2 *Handlers) AccountAssetsInformation(ctx echo.Context, address basics.Address, params model.AccountAssetsInformationParams) error {
	if !v2.Node.Config().EnableExperimentalAPI {
		return ctx.String(http.StatusNotFound, "/v2/accounts/{address}/assets was not enabled in the configuration file by setting the EnableExperimentalAPI to true")
	}

	var assetGreaterThan uint64 = 0
	if params.Next != nil {
		agt, err0 := strconv.ParseUint(*params.Next, 10, 64)
		if err0 != nil {
			return badRequest(ctx, err0, fmt.Sprintf("%s: %v", errUnableToParseNext, err0), v2.Log)
		}
		assetGreaterThan = agt
	}

	if params.Limit != nil {
		if *params.Limit <= 0 {
			return badRequest(ctx, errors.New(errInvalidLimit), errInvalidLimit, v2.Log)
		}

		if *params.Limit > MaxAssetResults {
			limitErrMsg := fmt.Sprintf("limit %d exceeds max assets single batch limit %d", *params.Limit, MaxAssetResults)
			return badRequest(ctx, errors.New(limitErrMsg), limitErrMsg, v2.Log)
		}
	} else {
		// default limit
		l := DefaultAssetResults
		params.Limit = &l
	}

	ledger := v2.Node.LedgerForAPI()

	// Logic
	// 1. Get the account's asset holdings subject to limits
	// 2. Handle empty response
	// 3. Prepare JSON response

	// We intentionally request one more than the limit to determine if there are more assets.
	records, lookupRound, err := ledger.LookupAssets(address, basics.AssetIndex(assetGreaterThan), *params.Limit+1)

	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	// prepare JSON response
	response := model.AccountAssetsInformationResponse{Round: lookupRound}

	// If the total count is greater than the limit, we set the next token to the last asset ID being returned
	if uint64(len(records)) > *params.Limit {
		// we do not include the last record in the response
		records = records[:*params.Limit]
		nextTk := strconv.FormatUint(uint64(records[len(records)-1].AssetID), 10)
		response.NextToken = &nextTk
	}

	assetHoldings := make([]model.AccountAssetHolding, 0, len(records))

	for _, record := range records {
		if record.AssetHolding == nil {
			v2.Log.Warnf("AccountAssetsInformation: asset %d has no holding - should not be possible", record.AssetID)
			continue
		}

		aah := model.AccountAssetHolding{
			AssetHolding: model.AssetHolding{
				Amount:   record.AssetHolding.Amount,
				AssetID:  record.AssetID,
				IsFrozen: record.AssetHolding.Frozen,
			},
		}

		if !record.Creator.IsZero() {
			asset := AssetParamsToAsset(record.Creator.String(), record.AssetID, record.AssetParams)
			aah.AssetParams = &asset.Params
		}

		assetHoldings = append(assetHoldings, aah)
	}

	response.AssetHoldings = &assetHoldings

	return ctx.JSON(http.StatusOK, response)
}

// PreEncodedSimulateTxnResult mirrors model.SimulateTransactionResult
type PreEncodedSimulateTxnResult struct {
	Txn                      PreEncodedTxInfo                        `codec:"txn-result"`
	AppBudgetConsumed        *int                                    `codec:"app-budget-consumed,omitempty"`
	LogicSigBudgetConsumed   *int                                    `codec:"logic-sig-budget-consumed,omitempty"`
	TransactionTrace         *model.SimulationTransactionExecTrace   `codec:"exec-trace,omitempty"`
	UnnamedResourcesAccessed *model.SimulateUnnamedResourcesAccessed `codec:"unnamed-resources-accessed,omitempty"`
	FixedSigner              *string                                 `codec:"fixed-signer,omitempty"`
}

// PreEncodedSimulateTxnGroupResult mirrors model.SimulateTransactionGroupResult
type PreEncodedSimulateTxnGroupResult struct {
	AppBudgetAdded           *int                                    `codec:"app-budget-added,omitempty"`
	AppBudgetConsumed        *int                                    `codec:"app-budget-consumed,omitempty"`
	FailedAt                 *[]int                                  `codec:"failed-at,omitempty"`
	FailureMessage           *string                                 `codec:"failure-message,omitempty"`
	UnnamedResourcesAccessed *model.SimulateUnnamedResourcesAccessed `codec:"unnamed-resources-accessed,omitempty"`
	Txns                     []PreEncodedSimulateTxnResult           `codec:"txn-results"`
}

// PreEncodedSimulateResponse mirrors model.SimulateResponse
type PreEncodedSimulateResponse struct {
	Version         uint64                             `codec:"version"`
	LastRound       basics.Round                       `codec:"last-round"`
	TxnGroups       []PreEncodedSimulateTxnGroupResult `codec:"txn-groups"`
	EvalOverrides   *model.SimulationEvalOverrides     `codec:"eval-overrides,omitempty"`
	ExecTraceConfig simulation.ExecTraceConfig         `codec:"exec-trace-config,omitempty"`
	InitialStates   *model.SimulateInitialStates       `codec:"initial-states,omitempty"`
}

// PreEncodedSimulateRequestTransactionGroup mirrors model.SimulateRequestTransactionGroup
type PreEncodedSimulateRequestTransactionGroup struct {
	Txns []transactions.SignedTxn `codec:"txns"`
}

// PreEncodedSimulateRequest mirrors model.SimulateRequest
type PreEncodedSimulateRequest struct {
	TxnGroups             []PreEncodedSimulateRequestTransactionGroup `codec:"txn-groups"`
	Round                 basics.Round                                `codec:"round,omitempty"`
	AllowEmptySignatures  bool                                        `codec:"allow-empty-signatures,omitempty"`
	AllowMoreLogging      bool                                        `codec:"allow-more-logging,omitempty"`
	AllowUnnamedResources bool                                        `codec:"allow-unnamed-resources,omitempty"`
	ExtraOpcodeBudget     int                                         `codec:"extra-opcode-budget,omitempty"`
	ExecTraceConfig       simulation.ExecTraceConfig                  `codec:"exec-trace-config,omitempty"`
	FixSigners            bool                                        `codec:"fix-signers,omitempty"`
}

// SimulateTransaction simulates broadcasting a raw transaction to the network, returning relevant simulation results.
// (POST /v2/transactions/simulate)
func (v2 *Handlers) SimulateTransaction(ctx echo.Context, params model.SimulateTransactionParams) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("SimulateTransaction failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}
	proto := config.Consensus[stat.LastVersion]

	requestBuffer := new(bytes.Buffer)
	requestBodyReader := http.MaxBytesReader(nil, ctx.Request().Body, MaxTealDryrunBytes)
	_, err = requestBuffer.ReadFrom(requestBodyReader)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	requestData := requestBuffer.Bytes()

	var simulateRequest PreEncodedSimulateRequest
	err = decode(protocol.CodecHandle, requestData, &simulateRequest)
	if err != nil {
		err = decode(protocol.JSONStrictHandle, requestData, &simulateRequest)
		if err != nil {
			return badRequest(ctx, err, err.Error(), v2.Log)
		}
	}

	for _, txgroup := range simulateRequest.TxnGroups {
		if len(txgroup.Txns) == 0 {
			err = errors.New("empty txgroup")
			return badRequest(ctx, err, err.Error(), v2.Log)
		}
		if len(txgroup.Txns) > proto.MaxTxGroupSize {
			err = fmt.Errorf("transaction group size %d exceeds protocol max %d", len(txgroup.Txns), proto.MaxTxGroupSize)
			return badRequest(ctx, err, err.Error(), v2.Log)
		}
	}

	// Simulate transaction
	simulationResult, err := v2.Node.Simulate(convertSimulationRequest(simulateRequest))
	if err != nil {
		var invalidTxErr simulation.InvalidRequestError
		switch {
		case errors.As(err, &invalidTxErr):
			return badRequest(ctx, invalidTxErr, invalidTxErr.Error(), v2.Log)
		default:
			return internalError(ctx, err, err.Error(), v2.Log)
		}
	}

	response := convertSimulationResult(simulationResult)

	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}
	responseData, err := encode(handle, &response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, responseData)
}

// TealDryrun takes transactions and additional simulated ledger state and returns debugging information.
// (POST /v2/teal/dryrun)
func (v2 *Handlers) TealDryrun(ctx echo.Context) error {
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/teal/dryrun was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	req := ctx.Request()
	buf := new(bytes.Buffer)
	req.Body = http.MaxBytesReader(nil, req.Body, MaxTealDryrunBytes)
	_, err := buf.ReadFrom(ctx.Request().Body)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	data := buf.Bytes()

	var dr DryrunRequest
	var gdr model.DryrunRequest
	err = decode(protocol.JSONStrictHandle, data, &gdr)
	if err == nil {
		dr, err = DryrunRequestFromGenerated(&gdr)
		if err != nil {
			return badRequest(ctx, err, err.Error(), v2.Log)
		}
	} else {
		err = decode(protocol.CodecHandle, data, &dr)
		if err != nil {
			return badRequest(ctx, err, err.Error(), v2.Log)
		}
	}

	// fetch previous block header just once to prevent racing with network
	var hdr bookkeeping.BlockHeader
	if dr.ProtocolVersion == "" || dr.Round == 0 || dr.LatestTimestamp == 0 {
		actualLedger := v2.Node.LedgerForAPI()
		hdr, err = actualLedger.BlockHdr(actualLedger.Latest())
		if err != nil {
			return internalError(ctx, err, "current block error", v2.Log)
		}
	}

	var response model.DryrunResponse

	var protocolVersion protocol.ConsensusVersion
	if dr.ProtocolVersion != "" {
		var ok bool
		_, ok = config.Consensus[protocol.ConsensusVersion(dr.ProtocolVersion)]
		if !ok {
			return badRequest(ctx, nil, "unsupported protocol version", v2.Log)
		}
		protocolVersion = protocol.ConsensusVersion(dr.ProtocolVersion)
	} else {
		protocolVersion = hdr.CurrentProtocol
	}
	dr.ProtocolVersion = string(protocolVersion)

	if dr.Round == 0 {
		dr.Round = hdr.Round + 1
	}

	if dr.LatestTimestamp == 0 {
		dr.LatestTimestamp = hdr.TimeStamp
	}

	doDryrunRequest(&dr, &response)
	response.ProtocolVersion = string(protocolVersion)
	return ctx.JSON(http.StatusOK, response)
}

// UnsetSyncRound removes the sync round restriction from the ledger.
// (DELETE /v2/ledger/sync)
func (v2 *Handlers) UnsetSyncRound(ctx echo.Context) error {
	v2.Node.UnsetSyncRound()
	return ctx.NoContent(http.StatusOK)
}

// SetSyncRound sets the sync round on the ledger.
// (POST /v2/ledger/sync/{round})
func (v2 *Handlers) SetSyncRound(ctx echo.Context, round basics.Round) error {
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
func (v2 *Handlers) GetSyncRound(ctx echo.Context) error {
	rnd := v2.Node.GetSyncRound()
	if rnd == 0 {
		return notFound(ctx, fmt.Errorf("sync round is not set"), errFailedRetrievingSyncRound, v2.Log)
	}
	return ctx.JSON(http.StatusOK, model.GetSyncRoundResponse{Round: rnd})
}

// GetLedgerStateDelta returns the deltas for a given round.
// This should be a representation of the ledgercore.StateDelta object.
// (GET /v2/deltas/{round})
func (v2 *Handlers) GetLedgerStateDelta(ctx echo.Context, round basics.Round, params model.GetLedgerStateDeltaParams) error {
	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}
	sDelta, err := v2.Node.LedgerForAPI().GetStateDeltaForRound(round)
	if err != nil {
		return notFound(ctx, err, fmt.Sprintf(errFailedRetrievingStateDelta, err), v2.Log)
	}
	if handle == protocol.JSONStrictHandle {
		// Zero out the Txleases map since it cannot be represented in JSON, as it is a map with an
		// object key.
		sDelta.Txleases = nil
	}
	data, err := encode(handle, sDelta)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}
	return ctx.Blob(http.StatusOK, contentType, data)
}

// TransactionParams returns the suggested parameters for constructing a new transaction.
// (GET /v2/transactions/params)
func (v2 *Handlers) TransactionParams(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("TransactionParams failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}

	gh := v2.Node.GenesisHash()
	proto := config.Consensus[stat.LastVersion]

	response := model.TransactionParametersResponse{
		ConsensusVersion: string(stat.LastVersion),
		Fee:              v2.Node.SuggestedFee().Raw,
		GenesisHash:      gh[:],
		GenesisId:        v2.Node.GenesisID(),
		LastRound:        stat.LastRound,
		MinFee:           proto.MinTxnFee,
	}

	return ctx.JSON(http.StatusOK, response)
}

// PreEncodedTxInfo represents the PendingTransaction response before it is
// encoded to a format.
type PreEncodedTxInfo struct {
	AssetIndex         *basics.AssetIndex         `codec:"asset-index,omitempty"`
	AssetClosingAmount *uint64                    `codec:"asset-closing-amount,omitempty"`
	ApplicationIndex   *basics.AppIndex           `codec:"application-index,omitempty"`
	CloseRewards       *uint64                    `codec:"close-rewards,omitempty"`
	ClosingAmount      *uint64                    `codec:"closing-amount,omitempty"`
	ConfirmedRound     *basics.Round              `codec:"confirmed-round,omitempty"`
	GlobalStateDelta   *model.StateDelta          `codec:"global-state-delta,omitempty"`
	LocalStateDelta    *[]model.AccountStateDelta `codec:"local-state-delta,omitempty"`
	PoolError          string                     `codec:"pool-error"`
	ReceiverRewards    *uint64                    `codec:"receiver-rewards,omitempty"`
	SenderRewards      *uint64                    `codec:"sender-rewards,omitempty"`
	Txn                transactions.SignedTxn     `codec:"txn"`
	Logs               *[][]byte                  `codec:"logs,omitempty"`
	Inners             *[]PreEncodedTxInfo        `codec:"inner-txns,omitempty"`
}

// PendingTransactionInformation returns a transaction with the specified txID
// from the transaction pool. If not found looks for the transaction in the
// last proto.MaxTxnLife rounds
// (GET /v2/transactions/pending/{txid})
func (v2 *Handlers) PendingTransactionInformation(ctx echo.Context, txid string, params model.PendingTransactionInformationParams) error {

	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("PendingTransactionInformation failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}

	txID := transactions.Txid{}
	if err0 := txID.FromString(txid); err0 != nil {
		return badRequest(ctx, err0, errNoValidTxnSpecified, v2.Log)
	}

	txn, ok := v2.Node.GetPendingTransaction(txID)

	// We didn't find it, return a failure
	if !ok {
		err1 := errors.New(errTransactionNotFound)
		return notFound(ctx, err1, err1.Error(), v2.Log)
	}

	// Encoding wasn't working well without embedding "real" objects.
	response := PreEncodedTxInfo{
		Txn:       txn.Txn,
		PoolError: txn.PoolError,
	}

	if txn.ConfirmedRound != 0 {
		response.ConfirmedRound = &txn.ConfirmedRound

		response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
		response.AssetClosingAmount = &txn.ApplyData.AssetClosingAmount
		response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
		response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
		response.CloseRewards = &txn.ApplyData.CloseRewards.Raw
		response.AssetIndex = computeAssetIndexFromTxn(txn, v2.Node.LedgerForAPI())
		response.ApplicationIndex = computeAppIndexFromTxn(txn, v2.Node.LedgerForAPI())
		response.LocalStateDelta = sliceOrNil(localDeltasToLocalDeltas(txn.ApplyData.EvalDelta, &txn.Txn.Txn))
		response.GlobalStateDelta = sliceOrNil(globalDeltaToStateDelta(txn.ApplyData.EvalDelta.GlobalDelta))
		response.Logs = convertLogs(txn)
		response.Inners = convertInners(&txn)
	}

	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}
	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, data)
}

// getPendingTransactions returns to the provided context a list of uncomfirmed transactions currently in the transaction pool with optional Max/Address filters.
func (v2 *Handlers) getPendingTransactions(ctx echo.Context, max *uint64, format *string, addrFilter *basics.Address) error {

	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("PendingTransactionInformation failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}

	handle, contentType, err := getCodecHandle(format)
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	txnPool, err := v2.Node.GetPendingTxnsFromPool()
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpTransactionPool, v2.Log)
	}

	txnLimit := uint64(math.MaxUint64)
	if max != nil && *max != 0 {
		txnLimit = *max
	}

	// Convert transactions to msgp / json strings
	topTxns := make([]transactions.SignedTxn, 0)
	for _, txn := range txnPool {
		// break out if we've reached the max number of transactions
		if uint64(len(topTxns)) >= txnLimit {
			break
		}

		// continue if we have an address filter and the address doesn't match the transaction.
		if addrFilter != nil && !txn.Txn.MatchAddress(*addrFilter) {
			continue
		}

		topTxns = append(topTxns, txn)
	}

	// Encoding wasn't working well without embedding "real" objects.
	response := struct {
		TopTransactions   []transactions.SignedTxn `json:"top-transactions"`
		TotalTransactions uint64                   `json:"total-transactions"`
	}{
		TopTransactions:   topTxns,
		TotalTransactions: uint64(len(txnPool)),
	}

	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, data)
}

// startCatchup Given a catchpoint, it starts catching up to this catchpoint
func (v2 *Handlers) startCatchup(ctx echo.Context, catchpoint string, minRounds basics.Round) error {
	catchpointRound, _, err := ledgercore.ParseCatchpointLabel(catchpoint)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseCatchpoint, v2.Log)
	}

	if minRounds > 0 {
		ledgerRound := v2.Node.LedgerForAPI().Latest()
		if catchpointRound < (ledgerRound + basics.Round(minRounds)) {
			v2.Log.Infof("Skipping catchup. Catchpoint round %d is not %d rounds ahead of the current round %d.", catchpointRound, minRounds, ledgerRound)
			return ctx.JSON(http.StatusOK, model.CatchpointStartResponse{
				CatchupMessage: errCatchpointWouldNotInitialize,
			})
		}
	}

	// Select 200/201, or return an error
	var code int
	err = v2.Node.StartCatchup(catchpoint)
	switch err.(type) {
	case nil:
		code = http.StatusCreated
	case *node.CatchpointAlreadyInProgressError:
		code = http.StatusOK
	case *node.CatchpointUnableToStartError:
		return badRequest(ctx, err, err.Error(), v2.Log)
	case *node.StartCatchpointError:
		return timeout(ctx, err, err.Error(), v2.Log)
	default:
		return internalError(ctx, err, fmt.Sprintf(errFailedToStartCatchup, err), v2.Log)
	}

	return ctx.JSON(code, model.CatchpointStartResponse{
		CatchupMessage: catchpoint,
	})
}

// abortCatchup Given a catchpoint, it aborts catching up to this catchpoint
func (v2 *Handlers) abortCatchup(ctx echo.Context, catchpoint string) error {
	_, _, err := ledgercore.ParseCatchpointLabel(catchpoint)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseCatchpoint, v2.Log)
	}

	err = v2.Node.AbortCatchup(catchpoint)
	if err != nil {
		return internalError(ctx, err, fmt.Sprintf(errFailedToAbortCatchup, err), v2.Log)
	}

	return ctx.JSON(http.StatusOK, model.CatchpointAbortResponse{
		CatchupMessage: catchpoint,
	})
}

// GetPendingTransactions returns the list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/transactions/pending)
func (v2 *Handlers) GetPendingTransactions(ctx echo.Context, params model.GetPendingTransactionsParams) error {
	return v2.getPendingTransactions(ctx, params.Max, (*string)(params.Format), nil)
}

// GetApplicationByID returns application information by app idx.
// (GET /v2/applications/{application-id})
func (v2 *Handlers) GetApplicationByID(ctx echo.Context, applicationID basics.AppIndex) error {
	ledger := v2.Node.LedgerForAPI()
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(applicationID), basics.AppCreatable)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if !ok {
		return notFound(ctx, errors.New(errAppDoesNotExist), errAppDoesNotExist, v2.Log)
	}

	lastRound := ledger.Latest()

	record, err := ledger.LookupApplication(lastRound, creator, applicationID)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if record.AppParams == nil {
		return notFound(ctx, errors.New(errAppDoesNotExist), errAppDoesNotExist, v2.Log)
	}
	appParams := *record.AppParams
	app := AppParamsToApplication(creator.String(), applicationID, &appParams)
	response := model.ApplicationResponse(app)
	return ctx.JSON(http.StatusOK, response)
}

func applicationBoxesMaxKeys(requestedMax uint64, algodMax uint64) uint64 {
	if requestedMax == 0 {
		if algodMax == 0 {
			return math.MaxUint64 // unlimited results when both requested and algod max are 0
		}
		return algodMax + 1 // API limit dominates.  Increments by 1 to test if more than max supported results exist.
	}

	if requestedMax <= algodMax || algodMax == 0 {
		return requestedMax // requested limit dominates
	}

	return algodMax + 1 // API limit dominates.  Increments by 1 to test if more than max supported results exist.
}

// GetApplicationBoxes returns the boxes of an application
// (GET /v2/applications/{application-id}/boxes)
func (v2 *Handlers) GetApplicationBoxes(ctx echo.Context, applicationID basics.AppIndex, params model.GetApplicationBoxesParams) error {
	ledger := v2.Node.LedgerForAPI()
	lastRound := ledger.Latest()
	keyPrefix := apps.MakeBoxKey(uint64(applicationID), "")

	requestedMax, algodMax := nilToZero(params.Max), v2.Node.Config().MaxAPIBoxPerApplication
	max := applicationBoxesMaxKeys(requestedMax, algodMax)

	if max != math.MaxUint64 {
		record, _, _, err := ledger.LookupAccount(ledger.Latest(), applicationID.Address())
		if err != nil {
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
		if record.TotalBoxes > max {
			return ctx.JSON(http.StatusBadRequest, model.ErrorResponse{
				Message: "Result limit exceeded",
				Data: &map[string]any{
					"max-api-box-per-application": algodMax,
					"max":                         requestedMax,
					"total-boxes":                 record.TotalBoxes,
				},
			})
		}
	}

	boxKeys, err := ledger.LookupKeysByPrefix(lastRound, keyPrefix, math.MaxUint64)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	prefixLen := len(keyPrefix)
	responseBoxes := make([]model.BoxDescriptor, len(boxKeys))
	for i, boxKey := range boxKeys {
		responseBoxes[i] = model.BoxDescriptor{
			Name: []byte(boxKey[prefixLen:]),
		}
	}
	response := model.BoxesResponse{Boxes: responseBoxes}
	return ctx.JSON(http.StatusOK, response)
}

// GetApplicationBoxByName returns the value of an application's box
// (GET /v2/applications/{application-id}/box)
func (v2 *Handlers) GetApplicationBoxByName(ctx echo.Context, applicationID basics.AppIndex, params model.GetApplicationBoxByNameParams) error {
	ledger := v2.Node.LedgerForAPI()
	lastRound := ledger.Latest()

	encodedBoxName := params.Name
	boxNameBytes, err := apps.NewAppCallBytes(encodedBoxName)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	boxName, err := boxNameBytes.Raw()
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	value, err := ledger.LookupKv(lastRound, apps.MakeBoxKey(uint64(applicationID), string(boxName)))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if value == nil {
		return notFound(ctx, errors.New(errBoxDoesNotExist), errBoxDoesNotExist, v2.Log)
	}

	response := model.BoxResponse{
		Round: lastRound,
		Name:  boxName,
		Value: value,
	}
	return ctx.JSON(http.StatusOK, response)
}

// GetAssetByID returns application information by app idx.
// (GET /v2/assets/{asset-id})
func (v2 *Handlers) GetAssetByID(ctx echo.Context, assetID basics.AssetIndex) error {
	ledger := v2.Node.LedgerForAPI()
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(assetID), basics.AssetCreatable)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if !ok {
		return notFound(ctx, errors.New(errAssetDoesNotExist), errAssetDoesNotExist, v2.Log)
	}

	lastRound := ledger.Latest()
	record, err := ledger.LookupAsset(lastRound, creator, assetID)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if record.AssetParams == nil {
		return notFound(ctx, errors.New(errAssetDoesNotExist), errAssetDoesNotExist, v2.Log)
	}
	assetParams := *record.AssetParams
	asset := AssetParamsToAsset(creator.String(), assetID, &assetParams)
	response := model.AssetResponse(asset)
	return ctx.JSON(http.StatusOK, response)
}

// GetPendingTransactionsByAddress takes an Algorand address and returns its associated list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/accounts/{address}/transactions/pending)
func (v2 *Handlers) GetPendingTransactionsByAddress(ctx echo.Context, address basics.Address, params model.GetPendingTransactionsByAddressParams) error {
	return v2.getPendingTransactions(ctx, params.Max, (*string)(params.Format), &address)
}

// StartCatchup Given a catchpoint, it starts catching up to this catchpoint
// (POST /v2/catchup/{catchpoint})
func (v2 *Handlers) StartCatchup(ctx echo.Context, catchpoint string, params model.StartCatchupParams) error {
	min := nilToZero(params.Min)
	return v2.startCatchup(ctx, catchpoint, min)
}

// AbortCatchup Given a catchpoint, it aborts catching up to this catchpoint
// (DELETE /v2/catchup/{catchpoint})
func (v2 *Handlers) AbortCatchup(ctx echo.Context, catchpoint string) error {
	return v2.abortCatchup(ctx, catchpoint)
}

// CompileResponseWithSourceMap overrides the sourcemap field in
// the CompileResponse for JSON marshalling.
type CompileResponseWithSourceMap struct {
	model.CompileResponse
	Sourcemap *logic.SourceMap `json:"sourcemap,omitempty"`
}

// TealCompile compiles TEAL code to binary, return both binary and hash
// (POST /v2/teal/compile)
func (v2 *Handlers) TealCompile(ctx echo.Context, params model.TealCompileParams) (err error) {
	// Return early if teal compile is not allowed in node config.
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/teal/compile was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	if params.Sourcemap == nil {
		// Backwards compatibility: set sourcemap flag to default false value.
		defaultValue := false
		params.Sourcemap = &defaultValue
	}

	buf := new(bytes.Buffer)
	ctx.Request().Body = http.MaxBytesReader(nil, ctx.Request().Body, MaxTealSourceBytes)
	_, err = buf.ReadFrom(ctx.Request().Body)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	source := buf.String()
	ops, err := logic.AssembleString(source)
	if err != nil {
		sb := strings.Builder{}
		ops.ReportMultipleErrors("", &sb)
		return badRequest(ctx, err, sb.String(), v2.Log)
	}
	pd := logic.HashProgram(ops.Program)
	addr := basics.Address(pd)

	// If source map flag is enabled, then return the map.
	var sourcemap *logic.SourceMap
	if *params.Sourcemap {
		rawmap := logic.GetSourceMap([]string{"<body>"}, ops.OffsetToSource)
		sourcemap = &rawmap
	}

	response := CompileResponseWithSourceMap{
		model.CompileResponse{
			Hash:   addr.String(),
			Result: base64.StdEncoding.EncodeToString(ops.Program),
		},
		sourcemap,
	}
	return ctx.JSON(http.StatusOK, response)
}

// GetStateProof returns the state proof for a given round.
// (GET /v2/stateproofs/{round})
func (v2 *Handlers) GetStateProof(ctx echo.Context, round basics.Round) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx.Request().Context(), time.Minute)
	defer cancel()

	ledger := v2.Node.LedgerForAPI()
	if ledger.Latest() < round {
		return internalError(ctx, errors.New(errRoundGreaterThanTheLatest), errRoundGreaterThanTheLatest, v2.Log)
	}

	tx, err := GetStateProofTransactionForRound(ctxWithTimeout, ledger, round, ledger.Latest(), v2.Shutdown)
	if err != nil {
		return v2.wrapStateproofError(ctx, err)
	}

	response := model.StateProofResponse{
		StateProof: protocol.Encode(&tx.StateProof),
	}

	response.Message.BlockHeadersCommitment = tx.Message.BlockHeadersCommitment
	response.Message.VotersCommitment = tx.Message.VotersCommitment
	response.Message.LnProvenWeight = tx.Message.LnProvenWeight
	response.Message.FirstAttestedRound = tx.Message.FirstAttestedRound
	response.Message.LastAttestedRound = tx.Message.LastAttestedRound

	return ctx.JSON(http.StatusOK, response)
}

func (v2 *Handlers) wrapStateproofError(ctx echo.Context, err error) error {
	if errors.Is(err, ErrNoStateProofForRound) {
		return notFound(ctx, err, err.Error(), v2.Log)
	}
	if errors.Is(err, ErrTimeout) {
		return timeout(ctx, err, err.Error(), v2.Log)
	}
	return internalError(ctx, err, err.Error(), v2.Log)
}

// GetLightBlockHeaderProof Gets a proof of a light block header for a given round
// (GET /v2/blocks/{round}/lightheader/proof)
func (v2 *Handlers) GetLightBlockHeaderProof(ctx echo.Context, round basics.Round) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx.Request().Context(), time.Minute)
	defer cancel()
	ledger := v2.Node.LedgerForAPI()
	if ledger.Latest() < round {
		return internalError(ctx, errors.New(errRoundGreaterThanTheLatest), errRoundGreaterThanTheLatest, v2.Log)
	}

	stateProof, err := GetStateProofTransactionForRound(ctxWithTimeout, ledger, round, ledger.Latest(), v2.Shutdown)
	if err != nil {
		return v2.wrapStateproofError(ctx, err)
	}

	lastAttestedRound := stateProof.Message.LastAttestedRound
	firstAttestedRound := stateProof.Message.FirstAttestedRound
	stateProofInterval := uint64(lastAttestedRound - firstAttestedRound + 1)

	lightHeaders, err := stateproof.FetchLightHeaders(ledger, stateProofInterval, lastAttestedRound)
	if err != nil {
		return notFound(ctx, err, err.Error(), v2.Log)
	}

	blockIndex := round - firstAttestedRound
	leafproof, err := stateproof.GenerateProofOfLightBlockHeaders(stateProofInterval, lightHeaders, blockIndex)
	if err != nil {
		return internalError(ctx, err, err.Error(), v2.Log)
	}

	response := model.LightBlockHeaderProofResponse{
		Index:     uint64(blockIndex),
		Proof:     leafproof.GetConcatenatedProof(),
		Treedepth: int(leafproof.TreeDepth),
	}
	return ctx.JSON(http.StatusOK, response)
}

// TealDisassemble disassembles the program bytecode in base64 into TEAL code.
// (POST /v2/teal/disassemble)
func (v2 *Handlers) TealDisassemble(ctx echo.Context) error {
	// return early if teal compile is not allowed in node config
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/teal/disassemble was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	buf := new(bytes.Buffer)
	ctx.Request().Body = http.MaxBytesReader(nil, ctx.Request().Body, MaxTealSourceBytes)
	_, err := buf.ReadFrom(ctx.Request().Body)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	sourceProgram := buf.Bytes()
	program, err := logic.Disassemble(sourceProgram)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	response := model.DisassembleResponse{
		Result: program,
	}
	return ctx.JSON(http.StatusOK, response)
}

// GetLedgerStateDeltaForTransactionGroup retrieves the delta for a specified transaction group.
// (GET /v2/deltas/txn/group/{id})
func (v2 *Handlers) GetLedgerStateDeltaForTransactionGroup(ctx echo.Context, id string, params model.GetLedgerStateDeltaForTransactionGroupParams) error {
	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}
	idDigest, err := crypto.DigestFromString(id)
	if err != nil {
		return badRequest(ctx, err, errNoValidTxnSpecified, v2.Log)
	}
	tracer, ok := v2.Node.LedgerForAPI().GetTracer().(*eval.TxnGroupDeltaTracer)
	if !ok {
		return notImplemented(ctx, err, errFailedRetrievingTracer, v2.Log)
	}
	delta, err := tracer.GetDeltaForID(idDigest)
	if err != nil {
		return notFound(ctx, err, fmt.Sprintf(errFailedRetrievingStateDelta, err), v2.Log)
	}
	if handle == protocol.JSONStrictHandle {
		// Zero out the Txleases map since it cannot be represented in JSON, as it is a map with an
		// object key.
		delta.Txleases = nil
	}
	data, err := encode(handle, delta)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}
	return ctx.Blob(http.StatusOK, contentType, data)
}

// GetTransactionGroupLedgerStateDeltasForRound retrieves the deltas for transaction groups in a given round.
// (GET /v2/deltas/{round}/txn/group)
func (v2 *Handlers) GetTransactionGroupLedgerStateDeltasForRound(ctx echo.Context, round basics.Round, params model.GetTransactionGroupLedgerStateDeltasForRoundParams) error {
	handle, contentType, err := getCodecHandle((*string)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}
	tracer, ok := v2.Node.LedgerForAPI().GetTracer().(*eval.TxnGroupDeltaTracer)
	if !ok {
		return notImplemented(ctx, err, errFailedRetrievingTracer, v2.Log)
	}
	deltas, err := tracer.GetDeltasForRound(round)
	if err != nil {
		return notFound(ctx, err, fmt.Sprintf(errFailedRetrievingStateDelta, err), v2.Log)
	}
	if handle == protocol.JSONStrictHandle {
		// Zero out the Txleases map since it cannot be represented in JSON, as it is a map with an
		// object key.
		for i := range deltas {
			deltas[i].Delta.Txleases = nil
		}
	}
	response := struct {
		Deltas []eval.TxnGroupDeltaWithIds
	}{
		Deltas: deltas,
	}
	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}
	return ctx.Blob(http.StatusOK, contentType, data)
}

// ExperimentalCheck is only available when EnabledExperimentalAPI is true
func (v2 *Handlers) ExperimentalCheck(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, true)
}

// GetBlockTimeStampOffset gets the timestamp offset.
// This is only available in dev mode.
// (GET /v2/devmode/blocks/offset)
func (v2 *Handlers) GetBlockTimeStampOffset(ctx echo.Context) error {
	offset, err := v2.Node.GetBlockTimeStampOffset()
	if err != nil {
		err = fmt.Errorf("cannot get block timestamp offset because we are not in dev mode")
		return badRequest(ctx, err, fmt.Sprintf(errFailedRetrievingTimeStampOffset, err), v2.Log)
	} else if offset == nil {
		err = fmt.Errorf("block timestamp offset was never set, using real clock for timestamps")
		return notFound(ctx, err, fmt.Sprintf(errFailedRetrievingTimeStampOffset, err), v2.Log)
	}
	return ctx.JSON(http.StatusOK, model.GetBlockTimeStampOffsetResponse{Offset: uint64(*offset)})
}

// SetBlockTimeStampOffset sets the timestamp offset.
// This is only available in dev mode.
// (POST /v2/devmode/blocks/offset/{offset})
func (v2 *Handlers) SetBlockTimeStampOffset(ctx echo.Context, offset uint64) error {
	if offset > math.MaxInt64 {
		err := fmt.Errorf("block timestamp offset cannot be larger than max int64 value")
		return badRequest(ctx, err, fmt.Sprintf(errFailedSettingTimeStampOffset, err), v2.Log)
	}
	err := v2.Node.SetBlockTimeStampOffset(int64(offset))
	if err != nil {
		return badRequest(ctx, err, fmt.Sprintf(errFailedSettingTimeStampOffset, err), v2.Log)
	}
	return ctx.NoContent(http.StatusOK)
}

// savedBlockingRate is the current blocking rate
var savedBlockingRate atomic.Int32

// GetDebugSettingsProf returns the current mutex and blocking rates.
func (v2 *Handlers) GetDebugSettingsProf(ctx echo.Context) error {
	mutexRate := uint64(runtime.SetMutexProfileFraction(-1))
	blockingRate := uint64(savedBlockingRate.Load())

	response := model.DebugSettingsProf{
		MutexRate: &mutexRate,
		BlockRate: &blockingRate,
	}

	return ctx.JSON(http.StatusOK, response)
}

// GetConfig returns the merged (defaults + overrides) config file in json.
func (v2 *Handlers) GetConfig(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, v2.Node.Config())
}

// PutDebugSettingsProf sets the mutex and blocking rates and returns the old values.
func (v2 *Handlers) PutDebugSettingsProf(ctx echo.Context) error {
	req := ctx.Request()
	buf := new(bytes.Buffer)
	req.Body = http.MaxBytesReader(nil, req.Body, 128)
	_, err := buf.ReadFrom(ctx.Request().Body)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	data := buf.Bytes()

	var opts model.DebugSettingsProf
	err = decode(protocol.JSONStrictHandle, data, &opts)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	var response model.DebugSettingsProf

	// validate input fiest
	if opts.MutexRate != nil && *opts.MutexRate > math.MaxInt32 {
		err = errors.New("blocking rate cannot be larger than max int32 value")
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	if opts.BlockRate != nil && *opts.BlockRate > math.MaxInt32 {
		err = errors.New("blocking rate cannot be larger than max int32 value")
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	if opts.MutexRate != nil {
		newMutexRate := int(*opts.MutexRate)
		oldMutexRate := uint64(runtime.SetMutexProfileFraction(newMutexRate))
		response.MutexRate = &oldMutexRate
	}

	if opts.BlockRate != nil {
		newBlockingRate := int(*opts.BlockRate)
		runtime.SetBlockProfileRate(newBlockingRate)

		oldBlockingRate := uint64(savedBlockingRate.Load())
		response.BlockRate = &oldBlockingRate
		savedBlockingRate.Store(int32(newBlockingRate))
	}

	return ctx.JSON(http.StatusOK, response)
}
