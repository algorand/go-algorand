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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	npprivate "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/nonparticipating/private"
	nppublic "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/nonparticipating/public"
	specv2 "github.com/algorand/go-algorand/daemon/algod/api/spec/v2"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/stateproof"
)

// NonParticipatingHandlers is an implementation to the V2 route handler interface defined by the generated code.
// Corresponding methods in the oapi spec are tagged as `nonparticipating`
type NonParticipatingHandlers struct {
	Log      logging.Logger
	Shutdown <-chan struct{}
	Node     node.NonParticipatingNodeInterface
}

// Register implements route registration for the HandlerInterface
func (v2 *NonParticipatingHandlers) Register(e *echo.Echo, publicAuth echo.MiddlewareFunc, privateAuth echo.MiddlewareFunc) {
	nppublic.RegisterHandlers(e, v2, publicAuth)
	npprivate.RegisterHandlers(e, v2, privateAuth)
	registerCommon(e, v2.Node)
}

// GetNode implements the HandlerInterface
func (v2 *NonParticipatingHandlers) GetNode() node.BaseNodeInterface {
	return v2.Node
}

// ShutdownNode shuts down the node.
// (POST /v2/shutdown)
func (v2 *NonParticipatingHandlers) ShutdownNode(ctx echo.Context, params model.ShutdownNodeParams) error {
	// TODO: shutdown endpoint
	return ctx.String(http.StatusNotImplemented, "Endpoint not implemented.")
}

// AccountInformation gets account information for a given account.
// (GET /v2/accounts/{address})
func (v2 *NonParticipatingHandlers) AccountInformation(ctx echo.Context, address string, params model.AccountInformationParams) error {
	handle, contentType, err := getCodecHandle((*model.Format)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseAddress, v2.Log)
	}

	// should we skip fetching apps and assets?
	if params.Exclude != nil {
		switch *params.Exclude {
		case "all":
			return v2.basicAccountInformation(ctx, addr, handle, contentType)
		case "none", "":
		default:
			return badRequest(ctx, err, errFailedToParseExclude, v2.Log)
		}
	}

	myLedger := v2.Node.LedgerForAPI()

	// count total # of resources, if max limit is set
	if maxResults := v2.Node.Config().MaxAPIResourcesPerAccount; maxResults != 0 {
		record, _, _, err := myLedger.LookupAccount(myLedger.Latest(), addr)
		if err != nil {
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
		totalResults := record.TotalAssets + record.TotalAssetParams + record.TotalAppLocalStates + record.TotalAppParams
		if totalResults > maxResults {
			v2.Log.Infof("MaxAccountAPIResults limit %d exceeded, total results %d", maxResults, totalResults)
			extraData := map[string]interface{}{
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

	record, lastRound, amountWithoutPendingRewards, err := myLedger.LookupLatest(addr)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	// check against configured total limit on assets/apps
	if handle == protocol.CodecHandle {
		data, err := encode(handle, record)
		if err != nil {
			return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
		}
		return ctx.Blob(http.StatusOK, contentType, data)
	}

	consensus, err := myLedger.ConsensusParams(lastRound)
	if err != nil {
		return internalError(ctx, err, fmt.Sprintf("could not retrieve consensus information for last round (%d)", lastRound), v2.Log)
	}

	account, err := AccountDataToAccount(address, &record, lastRound, &consensus, amountWithoutPendingRewards)
	if err != nil {
		return internalError(ctx, err, errInternalFailure, v2.Log)
	}

	response := model.AccountResponse(account)
	return ctx.JSON(http.StatusOK, response)
}

// basicAccountInformation handles the case when no resources (assets or apps) are requested.
func (v2 *NonParticipatingHandlers) basicAccountInformation(ctx echo.Context, addr basics.Address, handle codec.Handle, contentType string) error {
	myLedger := v2.Node.LedgerForAPI()
	record, lastRound, amountWithoutPendingRewards, err := myLedger.LookupAccount(myLedger.Latest(), addr)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if handle == protocol.CodecHandle {
		data, err := encode(handle, record)
		if err != nil {
			return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
		}
		return ctx.Blob(http.StatusOK, contentType, data)
	}

	consensus, err := myLedger.ConsensusParams(lastRound)
	if err != nil {
		return internalError(ctx, err, fmt.Sprintf("could not retrieve consensus information for last round (%d)", lastRound), v2.Log)
	}

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

	pendingRewards, overflowed := basics.OSubA(record.MicroAlgos, amountWithoutPendingRewards)
	if overflowed {
		return internalError(ctx, errors.New("overflow on pending reward calculation"), errInternalFailure, v2.Log)
	}

	account := model.Account{
		SigType:                     nil,
		Round:                       uint64(lastRound),
		Address:                     addr.String(),
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
		TotalBoxes:          numOrNil(record.TotalBoxes),
		TotalBoxBytes:       numOrNil(record.TotalBoxBytes),
		MinBalance:          record.MinBalance(&consensus).Raw,
	}
	response := model.AccountResponse(account)
	return ctx.JSON(http.StatusOK, response)
}

// AccountAssetInformation gets account information about a given asset.
// (GET /v2/accounts/{address}/assets/{asset-id})
func (v2 *NonParticipatingHandlers) AccountAssetInformation(ctx echo.Context, address string, assetID uint64, params model.AccountAssetInformationParams) error {
	handle, contentType, err := getCodecHandle((*model.Format)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseAddress, v2.Log)
	}

	ledger := v2.Node.LedgerForAPI()

	lastRound := ledger.Latest()
	record, err := ledger.LookupAsset(lastRound, addr, basics.AssetIndex(assetID))
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
	response := model.AccountAssetResponse{Round: uint64(lastRound)}

	if record.AssetParams != nil {
		asset := AssetParamsToAsset(addr.String(), basics.AssetIndex(assetID), record.AssetParams)
		response.CreatedAsset = &asset.Params
	}

	if record.AssetHolding != nil {
		response.AssetHolding = &model.AssetHolding{
			Amount:   record.AssetHolding.Amount,
			AssetID:  uint64(assetID),
			IsFrozen: record.AssetHolding.Frozen,
		}
	}

	return ctx.JSON(http.StatusOK, response)
}

// AccountApplicationInformation gets account information about a given app.
// (GET /v2/accounts/{address}/applications/{application-id})
func (v2 *NonParticipatingHandlers) AccountApplicationInformation(ctx echo.Context, address string, applicationID uint64, params model.AccountApplicationInformationParams) error {
	handle, contentType, err := getCodecHandle((*model.Format)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseAddress, v2.Log)
	}

	ledger := v2.Node.LedgerForAPI()

	lastRound := ledger.Latest()
	record, err := ledger.LookupApplication(lastRound, addr, basics.AppIndex(applicationID))
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
	response := model.AccountApplicationResponse{Round: uint64(lastRound)}

	if record.AppParams != nil {
		app := AppParamsToApplication(addr.String(), basics.AppIndex(applicationID), record.AppParams)
		response.CreatedApp = &app.Params
	}

	if record.AppLocalState != nil {
		localState := convertTKVToGenerated(&record.AppLocalState.KeyValue)
		response.AppLocalState = &model.ApplicationLocalState{
			Id:       uint64(applicationID),
			KeyValue: localState,
			Schema: model.ApplicationStateSchema{
				NumByteSlice: record.AppLocalState.Schema.NumByteSlice,
				NumUint:      record.AppLocalState.Schema.NumUint,
			},
		}
	}

	return ctx.JSON(http.StatusOK, response)
}

// GetBlock gets the block for the given round.
// (GET /v2/blocks/{round})
func (v2 *NonParticipatingHandlers) GetBlock(ctx echo.Context, round uint64, params model.GetBlockParams) error {
	handle, contentType, err := getCodecHandle((*model.Format)(params.Format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	// msgpack format uses 'RawBlockBytes' and attaches a custom header.
	if handle == protocol.CodecHandle {
		blockbytes, err := rpcs.RawBlockBytes(v2.Node.LedgerForAPI(), basics.Round(round))
		if err != nil {
			switch err.(type) {
			case ledgercore.ErrNoEntry:
				return notFound(ctx, err, errFailedLookingUpLedger, v2.Log)
			default:
				return internalError(ctx, err, err.Error(), v2.Log)
			}
		}

		ctx.Response().Writer.Header().Add("X-Algorand-Struct", "block-v1")
		return ctx.Blob(http.StatusOK, contentType, blockbytes)
	}

	ledger := v2.Node.LedgerForAPI()
	block, _, err := ledger.BlockCert(basics.Round(round))
	if err != nil {
		switch err.(type) {
		case ledgercore.ErrNoEntry:
			return notFound(ctx, err, errFailedLookingUpLedger, v2.Log)
		default:
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
	}

	// Encoding wasn't working well without embedding "real" objects.
	response := struct {
		Block bookkeeping.Block `codec:"block"`
	}{
		Block: block,
	}

	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, data)
}

// GetBlockHash gets the block hash for the given round.
// (GET /v2/blocks/{round}/hash)
func (v2 *NonParticipatingHandlers) GetBlockHash(ctx echo.Context, round uint64) error {
	ledger := v2.Node.LedgerForAPI()
	block, _, err := ledger.BlockCert(basics.Round(round))
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
func (v2 *NonParticipatingHandlers) GetTransactionProof(ctx echo.Context, round uint64, txid string, params model.GetTransactionProofParams) error {
	var txID transactions.Txid
	err := txID.UnmarshalText([]byte(txid))
	if err != nil {
		return badRequest(ctx, err, errNoValidTxnSpecified, v2.Log)
	}

	if params.Hashtype != nil && *params.Hashtype != "sha512_256" && *params.Hashtype != "sha256" {
		return badRequest(ctx, nil, errInvalidHashType, v2.Log)
	}

	ledger := v2.Node.LedgerForAPI()
	block, _, err := ledger.BlockCert(basics.Round(round))
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

		proof, err := tree.ProveSingleLeaf(uint64(idx))
		if err != nil {
			return internalError(ctx, err, "generating proof", v2.Log)
		}

		response := model.TransactionProofResponse{
			Proof:     proof.GetConcatenatedProof(),
			Stibhash:  stibhash[:],
			Idx:       uint64(idx),
			Treedepth: uint64(proof.TreeDepth),
			Hashtype:  model.TransactionProofResponseHashtype(hashtype),
		}

		return ctx.JSON(http.StatusOK, response)
	}

	err = errors.New(errTransactionNotFound)
	return notFound(ctx, err, err.Error(), v2.Log)
}

// GetSupply gets the current supply reported by the ledger.
// (GET /v2/ledger/supply)
func (v2 *NonParticipatingHandlers) GetSupply(ctx echo.Context) error {
	latest, totals, err := v2.Node.LedgerForAPI().LatestTotals()
	if err != nil {
		err = fmt.Errorf("GetSupply(): round %d, failed: %v", latest, err)
		return internalError(ctx, err, errInternalFailure, v2.Log)
	}

	supply := model.SupplyResponse{
		CurrentRound: uint64(latest),
		TotalMoney:   totals.Participating().Raw,
		OnlineMoney:  totals.Online.Money.Raw,
	}

	return ctx.JSON(http.StatusOK, supply)
}

// GetStatus gets the current node status.
// (GET /v2/status)
func (v2 *NonParticipatingHandlers) GetStatus(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}

	response := model.NodeStatusResponse{
		LastRound:                   uint64(stat.LastRound),
		LastVersion:                 string(stat.LastVersion),
		NextVersion:                 string(stat.NextVersion),
		NextVersionRound:            uint64(stat.NextVersionRound),
		NextVersionSupported:        stat.NextVersionSupported,
		TimeSinceLastRound:          uint64(stat.TimeSinceLastRound().Nanoseconds()),
		CatchupTime:                 uint64(stat.CatchupTime.Nanoseconds()),
		StoppedAtUnsupportedRound:   stat.StoppedAtUnsupportedRound,
		LastCatchpoint:              &stat.LastCatchpoint,
		Catchpoint:                  &stat.Catchpoint,
		CatchpointTotalAccounts:     &stat.CatchpointCatchupTotalAccounts,
		CatchpointProcessedAccounts: &stat.CatchpointCatchupProcessedAccounts,
		CatchpointVerifiedAccounts:  &stat.CatchpointCatchupVerifiedAccounts,
		CatchpointTotalBlocks:       &stat.CatchpointCatchupTotalBlocks,
		CatchpointAcquiredBlocks:    &stat.CatchpointCatchupAcquiredBlocks,
	}

	return ctx.JSON(http.StatusOK, response)
}

// WaitForBlock returns the node status after waiting for the given round.
// (GET /v2/status/wait-for-block-after/{round}/)
func (v2 *NonParticipatingHandlers) WaitForBlock(ctx echo.Context, round uint64) error {
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
			if latestBlkHdr.NextProtocolSwitchOn <= basics.Round(round+1) {
				// we would never reach to this round, since this round would happen after the (unsupported) protocol upgrade.
				return badRequest(ctx, err, errRequestedRoundInUnsupportedRound, v2.Log)
			}
		}
	}

	// Wait
	select {
	case <-v2.Shutdown:
		return internalError(ctx, err, errServiceShuttingDown, v2.Log)
	case <-time.After(1 * time.Minute):
	case <-ledger.Wait(basics.Round(round + 1)):
	}

	// Return status after the wait
	return v2.GetStatus(ctx)
}

// TealDryrun takes transactions and additional simulated ledger state and returns debugging information.
// (POST /v2/teal/dryrun)
func (v2 *NonParticipatingHandlers) TealDryrun(ctx echo.Context) error {
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/teal/dryrun was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	req := ctx.Request()
	buf := new(bytes.Buffer)
	req.Body = http.MaxBytesReader(nil, req.Body, maxTealDryrunBytes)
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
		dr.Round = uint64(hdr.Round + 1)
	}

	if dr.LatestTimestamp == 0 {
		dr.LatestTimestamp = hdr.TimeStamp
	}

	doDryrunRequest(&dr, &response)
	response.ProtocolVersion = string(protocolVersion)
	return ctx.JSON(http.StatusOK, response)
}

// startCatchup Given a catchpoint, it starts catching up to this catchpoint
func (v2 *NonParticipatingHandlers) startCatchup(ctx echo.Context, catchpoint string) error {
	_, _, err := ledgercore.ParseCatchpointLabel(catchpoint)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseCatchpoint, v2.Log)
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
	default:
		return internalError(ctx, err, fmt.Sprintf(errFailedToStartCatchup, err), v2.Log)
	}

	return ctx.JSON(code, model.CatchpointStartResponse{
		CatchupMessage: catchpoint,
	})
}

// abortCatchup Given a catchpoint, it aborts catching up to this catchpoint
func (v2 *NonParticipatingHandlers) abortCatchup(ctx echo.Context, catchpoint string) error {
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

// GetApplicationByID returns application information by app idx.
// (GET /v2/applications/{application-id})
func (v2 *NonParticipatingHandlers) GetApplicationByID(ctx echo.Context, applicationID uint64) error {
	appIdx := basics.AppIndex(applicationID)
	ledger := v2.Node.LedgerForAPI()
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(appIdx), basics.AppCreatable)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if !ok {
		return notFound(ctx, errors.New(errAppDoesNotExist), errAppDoesNotExist, v2.Log)
	}

	lastRound := ledger.Latest()

	record, err := ledger.LookupApplication(lastRound, creator, basics.AppIndex(applicationID))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if record.AppParams == nil {
		return notFound(ctx, errors.New(errAppDoesNotExist), errAppDoesNotExist, v2.Log)
	}
	appParams := *record.AppParams
	app := AppParamsToApplication(creator.String(), appIdx, &appParams)
	response := model.ApplicationResponse(app)
	return ctx.JSON(http.StatusOK, response)
}

// GetApplicationBoxes returns the box names of an application
// (GET /v2/applications/{application-id}/boxes)
func (v2 *NonParticipatingHandlers) GetApplicationBoxes(ctx echo.Context, applicationID uint64, params model.GetApplicationBoxesParams) error {
	appIdx := basics.AppIndex(applicationID)
	ledger := v2.Node.LedgerForAPI()
	lastRound := ledger.Latest()
	keyPrefix := logic.MakeBoxKey(appIdx, "")

	requestedMax, algodMax := nilToZero(params.Max), v2.Node.Config().MaxAPIBoxPerApplication
	max := applicationBoxesMaxKeys(requestedMax, algodMax)

	if max != math.MaxUint64 {
		record, _, _, err := ledger.LookupAccount(ledger.Latest(), appIdx.Address())
		if err != nil {
			return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
		}
		if record.TotalBoxes > max {
			return ctx.JSON(http.StatusBadRequest, model.ErrorResponse{
				Message: "Result limit exceeded",
				Data: &map[string]interface{}{
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
func (v2 *NonParticipatingHandlers) GetApplicationBoxByName(ctx echo.Context, applicationID uint64, params model.GetApplicationBoxByNameParams) error {
	appIdx := basics.AppIndex(applicationID)
	ledger := v2.Node.LedgerForAPI()
	lastRound := ledger.Latest()

	encodedBoxName := params.Name
	boxNameBytes, err := logic.NewAppCallBytes(encodedBoxName)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	boxName, err := boxNameBytes.Raw()
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	value, err := ledger.LookupKv(lastRound, logic.MakeBoxKey(appIdx, string(boxName)))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if value == nil {
		return notFound(ctx, errors.New(errBoxDoesNotExist), errBoxDoesNotExist, v2.Log)
	}

	response := model.BoxResponse{
		Name:  boxName,
		Value: value,
	}
	return ctx.JSON(http.StatusOK, response)
}

// GetAssetByID returns application information by app idx.
// (GET /v2/assets/{asset-id})
func (v2 *NonParticipatingHandlers) GetAssetByID(ctx echo.Context, assetID uint64) error {
	assetIdx := basics.AssetIndex(assetID)
	ledger := v2.Node.LedgerForAPI()
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(assetIdx), basics.AssetCreatable)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if !ok {
		return notFound(ctx, errors.New(errAssetDoesNotExist), errAssetDoesNotExist, v2.Log)
	}

	lastRound := ledger.Latest()
	record, err := ledger.LookupAsset(lastRound, creator, basics.AssetIndex(assetID))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	if record.AssetParams == nil {
		return notFound(ctx, errors.New(errAssetDoesNotExist), errAssetDoesNotExist, v2.Log)
	}
	assetParams := *record.AssetParams
	asset := AssetParamsToAsset(creator.String(), assetIdx, &assetParams)
	response := model.AssetResponse(asset)
	return ctx.JSON(http.StatusOK, response)
}

// StartCatchup Given a catchpoint, it starts catching up to this catchpoint
// (POST /v2/catchup/{catchpoint})
func (v2 *NonParticipatingHandlers) StartCatchup(ctx echo.Context, catchpoint string) error {
	return v2.startCatchup(ctx, catchpoint)
}

// AbortCatchup Given a catchpoint, it aborts catching up to this catchpoint
// (DELETE /v2/catchup/{catchpoint})
func (v2 *NonParticipatingHandlers) AbortCatchup(ctx echo.Context, catchpoint string) error {
	return v2.abortCatchup(ctx, catchpoint)
}

// TealCompile compiles TEAL code to binary, return both binary and hash
// (POST /v2/teal/compile)
func (v2 *NonParticipatingHandlers) TealCompile(ctx echo.Context, params model.TealCompileParams) (err error) {
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
	ctx.Request().Body = http.MaxBytesReader(nil, ctx.Request().Body, maxTealSourceBytes)
	_, err = buf.ReadFrom(ctx.Request().Body)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	source := buf.String()
	ops, err := logic.AssembleString(source)
	if err != nil {
		sb := strings.Builder{}
		ops.ReportProblems("", &sb)
		return badRequest(ctx, err, sb.String(), v2.Log)
	}
	pd := logic.HashProgram(ops.Program)
	addr := basics.Address(pd)

	// If source map flag is enabled, then return the map.
	var sourcemap *logic.SourceMap
	if *params.Sourcemap {
		rawmap := logic.GetSourceMap([]string{}, ops.OffsetToLine)
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
func (v2 *NonParticipatingHandlers) GetStateProof(ctx echo.Context, round uint64) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx.Request().Context(), time.Minute)
	defer cancel()

	ledger := v2.Node.LedgerForAPI()
	if ledger.Latest() < basics.Round(round) {
		return internalError(ctx, errors.New(errRoundGreaterThanTheLatest), errRoundGreaterThanTheLatest, v2.Log)
	}

	tx, err := GetStateProofTransactionForRound(ctxWithTimeout, ledger, basics.Round(round), ledger.Latest(), v2.Shutdown)
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

func (v2 *NonParticipatingHandlers) wrapStateproofError(ctx echo.Context, err error) error {
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
func (v2 *NonParticipatingHandlers) GetLightBlockHeaderProof(ctx echo.Context, round uint64) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx.Request().Context(), time.Minute)
	defer cancel()
	ledger := v2.Node.LedgerForAPI()
	if ledger.Latest() < basics.Round(round) {
		return internalError(ctx, errors.New(errRoundGreaterThanTheLatest), errRoundGreaterThanTheLatest, v2.Log)
	}

	stateProof, err := GetStateProofTransactionForRound(ctxWithTimeout, ledger, basics.Round(round), ledger.Latest(), v2.Shutdown)
	if err != nil {
		return v2.wrapStateproofError(ctx, err)
	}

	lastAttestedRound := stateProof.Message.LastAttestedRound
	firstAttestedRound := stateProof.Message.FirstAttestedRound
	stateProofInterval := lastAttestedRound - firstAttestedRound + 1

	lightHeaders, err := stateproof.FetchLightHeaders(ledger, stateProofInterval, basics.Round(lastAttestedRound))
	if err != nil {
		return notFound(ctx, err, err.Error(), v2.Log)
	}

	blockIndex := round - firstAttestedRound
	leafproof, err := stateproof.GenerateProofOfLightBlockHeaders(stateProofInterval, lightHeaders, blockIndex)
	if err != nil {
		return internalError(ctx, err, err.Error(), v2.Log)
	}

	response := model.LightBlockHeaderProofResponse{
		Index:     blockIndex,
		Proof:     leafproof.GetConcatenatedProof(),
		Treedepth: uint64(leafproof.TreeDepth),
	}
	return ctx.JSON(http.StatusOK, response)
}

// TealDisassemble disassembles the program bytecode in base64 into TEAL code.
// (POST /v2/teal/disassemble)
func (v2 *NonParticipatingHandlers) TealDisassemble(ctx echo.Context) error {
	// return early if teal compile is not allowed in node config
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/teal/disassemble was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	buf := new(bytes.Buffer)
	ctx.Request().Body = http.MaxBytesReader(nil, ctx.Request().Body, maxTealSourceBytes)
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
