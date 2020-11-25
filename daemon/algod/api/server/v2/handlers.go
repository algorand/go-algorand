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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/private"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

const maxTealSourceBytes = 1e5
const maxTealDryrunBytes = 1e5

// Handlers is an implementation to the V2 route handler interface defined by the generated code.
type Handlers struct {
	Node     NodeInterface
	Log      logging.Logger
	Shutdown <-chan struct{}
}

// NodeInterface represents node fns used by the handlers.
type NodeInterface interface {
	Ledger() *data.Ledger
	Status() (s node.StatusReport, err error)
	GenesisID() string
	GenesisHash() crypto.Digest
	BroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error
	GetPendingTransaction(txID transactions.Txid) (res node.TxnWithStatus, found bool)
	GetPendingTxnsFromPool() ([]transactions.SignedTxn, error)
	SuggestedFee() basics.MicroAlgos
	StartCatchup(catchpoint string) error
	AbortCatchup(catchpoint string) error
	Config() config.Local
}

// RegisterParticipationKeys registers participation keys.
// (POST /v2/register-participation-keys/{address})
func (v2 *Handlers) RegisterParticipationKeys(ctx echo.Context, address string, params private.RegisterParticipationKeysParams) error {
	// TODO: register participation keys endpoint
	return ctx.String(http.StatusNotImplemented, "Endpoint not implemented.")
}

// ShutdownNode shuts down the node.
// (POST /v2/shutdown)
func (v2 *Handlers) ShutdownNode(ctx echo.Context, params private.ShutdownNodeParams) error {
	// TODO: shutdown endpoint
	return ctx.String(http.StatusNotImplemented, "Endpoint not implemented.")
}

// AccountInformation gets account information for a given account.
// (GET /v2/accounts/{address})
func (v2 *Handlers) AccountInformation(ctx echo.Context, address string, params generated.AccountInformationParams) error {
	handle, contentType, err := getCodecHandle(params.Format)
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseAddress, v2.Log)
	}

	myLedger := v2.Node.Ledger()
	lastRound := myLedger.Latest()
	record, err := myLedger.Lookup(lastRound, addr)
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

	recordWithoutPendingRewards, _, err := myLedger.LookupWithoutRewards(lastRound, addr)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	amountWithoutPendingRewards := recordWithoutPendingRewards.MicroAlgos

	assetsCreators := make(map[basics.AssetIndex]string, len(record.Assets))
	if len(record.Assets) > 0 {
		//assets = make(map[uint64]v1.AssetHolding)
		for curid := range record.Assets {
			var creator string
			creatorAddr, ok, err := myLedger.GetCreator(basics.CreatableIndex(curid), basics.AssetCreatable)
			if err == nil && ok {
				creator = creatorAddr.String()
			} else {
				// Asset may have been deleted, so we can no
				// longer fetch the creator
				creator = ""
			}
			assetsCreators[curid] = creator
		}
	}

	account, err := AccountDataToAccount(address, &record, assetsCreators, lastRound, amountWithoutPendingRewards)
	if err != nil {
		return internalError(ctx, err, errInternalFailure, v2.Log)
	}

	response := generated.AccountResponse(account)
	return ctx.JSON(http.StatusOK, response)
}

// GetBlock gets the block for the given round.
// (GET /v2/blocks/{round})
func (v2 *Handlers) GetBlock(ctx echo.Context, round uint64, params generated.GetBlockParams) error {
	handle, contentType, err := getCodecHandle(params.Format)
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	// msgpack format uses 'RawBlockBytes' and attaches a custom header.
	if handle == protocol.CodecHandle {
		blockbytes, err := rpcs.RawBlockBytes(v2.Node.Ledger(), basics.Round(round))
		if err != nil {
			return internalError(ctx, err, err.Error(), v2.Log)
		}

		ctx.Response().Writer.Header().Add("X-Algorand-Struct", "block-v1")
		return ctx.Blob(http.StatusOK, contentType, blockbytes)
	}

	ledger := v2.Node.Ledger()
	block, _, err := ledger.BlockCert(basics.Round(round))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
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

// GetSupply gets the current supply reported by the ledger.
// (GET /v2/ledger/supply)
func (v2 *Handlers) GetSupply(ctx echo.Context) error {
	latest := v2.Node.Ledger().Latest()
	totals, err := v2.Node.Ledger().Totals(latest)
	if err != nil {
		err = fmt.Errorf("GetSupply(): round %d, failed: %v", latest, err)
		return internalError(ctx, err, errInternalFailure, v2.Log)
	}

	supply := generated.SupplyResponse{
		CurrentRound: uint64(latest),
		TotalMoney:   totals.Participating().Raw,
		OnlineMoney:  totals.Online.Money.Raw,
	}

	return ctx.JSON(http.StatusOK, supply)
}

// GetStatus gets the current node status.
// (GET /v2/status)
func (v2 *Handlers) GetStatus(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}

	response := generated.NodeStatusResponse{
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
func (v2 *Handlers) WaitForBlock(ctx echo.Context, round uint64) error {
	ledger := v2.Node.Ledger()

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

	var txgroup []transactions.SignedTxn
	dec := protocol.NewDecoder(ctx.Request().Body)
	for {
		var st transactions.SignedTxn
		err := dec.Decode(&st)
		if err == io.EOF {
			break
		}
		if err != nil {
			return badRequest(ctx, err, err.Error(), v2.Log)
		}
		txgroup = append(txgroup, st)

		if len(txgroup) > proto.MaxTxGroupSize {
			err := fmt.Errorf("max group size is %d", proto.MaxTxGroupSize)
			return badRequest(ctx, err, err.Error(), v2.Log)
		}
	}

	if len(txgroup) == 0 {
		err := errors.New("empty txgroup")
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	err = v2.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	return ctx.JSON(http.StatusOK, generated.PostTransactionsResponse{TxId: txid.String()})
}

// TealDryrun takes transactions and additional simulated ledger state and returns debugging information.
// (POST /v2/teal/dryrun)
func (v2 *Handlers) TealDryrun(ctx echo.Context) error {
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/teal/dryrun was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	req := ctx.Request()
	buf := new(bytes.Buffer)
	req.Body = http.MaxBytesReader(nil, req.Body, maxTealDryrunBytes)
	buf.ReadFrom(req.Body)
	data := buf.Bytes()

	var dr DryrunRequest
	var gdr generated.DryrunRequest
	err := decode(protocol.JSONHandle, data, &gdr)
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
		actualLedger := v2.Node.Ledger()
		hdr, err = actualLedger.BlockHdr(actualLedger.Latest())
		if err != nil {
			return internalError(ctx, err, "current block error", v2.Log)
		}
	}

	var response generated.DryrunResponse

	var proto config.ConsensusParams
	var protocolVersion protocol.ConsensusVersion
	if dr.ProtocolVersion != "" {
		var ok bool
		proto, ok = config.Consensus[protocol.ConsensusVersion(dr.ProtocolVersion)]
		if !ok {
			return badRequest(ctx, nil, "unsupported protocol version", v2.Log)
		}
		protocolVersion = protocol.ConsensusVersion(dr.ProtocolVersion)
	} else {
		proto = config.Consensus[hdr.CurrentProtocol]
		protocolVersion = hdr.CurrentProtocol
	}

	if dr.Round == 0 {
		dr.Round = uint64(hdr.Round + 1)
	}

	if dr.LatestTimestamp == 0 {
		dr.LatestTimestamp = hdr.TimeStamp
	}

	doDryrunRequest(&dr, &proto, &response)
	response.ProtocolVersion = string(protocolVersion)
	return ctx.JSON(http.StatusOK, response)
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

	response := generated.TransactionParametersResponse{
		ConsensusVersion: string(stat.LastVersion),
		Fee:              v2.Node.SuggestedFee().Raw,
		GenesisHash:      gh[:],
		GenesisId:        v2.Node.GenesisID(),
		LastRound:        uint64(stat.LastRound),
		MinFee:           proto.MinTxnFee,
	}

	return ctx.JSON(http.StatusOK, response)
}

// PendingTransactionInformation returns a transaction with the specified txID
// from the transaction pool. If not found looks for the transaction in the
// last proto.MaxTxnLife rounds
// (GET /v2/transactions/pending/{txid})
func (v2 *Handlers) PendingTransactionInformation(ctx echo.Context, txid string, params generated.PendingTransactionInformationParams) error {

	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("PendingTransactionInformation failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}

	txID := transactions.Txid{}
	if err := txID.UnmarshalText([]byte(txid)); err != nil {
		return badRequest(ctx, err, errNoTxnSpecified, v2.Log)
	}

	txn, ok := v2.Node.GetPendingTransaction(txID)

	// We didn't find it, return a failure
	if !ok {
		err := errors.New(errTransactionNotFound)
		return notFound(ctx, err, err.Error(), v2.Log)
	}

	// Encoding wasn't working well without embedding "real" objects.
	response := struct {
		AssetIndex       *uint64                        `codec:"asset-index,omitempty"`
		ApplicationIndex *uint64                        `codec:"application-index,omitempty"`
		CloseRewards     *uint64                        `codec:"close-rewards,omitempty"`
		ClosingAmount    *uint64                        `codec:"closing-amount,omitempty"`
		ConfirmedRound   *uint64                        `codec:"confirmed-round,omitempty"`
		GlobalStateDelta *generated.StateDelta          `codec:"global-state-delta,omitempty"`
		LocalStateDelta  *[]generated.AccountStateDelta `codec:"local-state-delta,omitempty"`
		PoolError        string                         `codec:"pool-error"`
		ReceiverRewards  *uint64                        `codec:"receiver-rewards,omitempty"`
		SenderRewards    *uint64                        `codec:"sender-rewards,omitempty"`
		Txn              transactions.SignedTxn         `codec:"txn"`
	}{
		Txn: txn.Txn,
	}

	handle, contentType, err := getCodecHandle(params.Format)
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	if txn.ConfirmedRound != 0 {
		r := uint64(txn.ConfirmedRound)
		response.ConfirmedRound = &r

		response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
		response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
		response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
		response.CloseRewards = &txn.ApplyData.CloseRewards.Raw

		response.AssetIndex = computeAssetIndexFromTxn(txn, v2.Node.Ledger())
		response.ApplicationIndex = computeAppIndexFromTxn(txn, v2.Node.Ledger())

		response.LocalStateDelta, response.GlobalStateDelta = convertToDeltas(txn)
	}

	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, data)
}

// getPendingTransactions returns to the provided context a list of uncomfirmed transactions currently in the transaction pool with optional Max/Address filters.
func (v2 *Handlers) getPendingTransactions(ctx echo.Context, max *uint64, format *string, addrFilter *string) error {

	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		return serviceUnavailable(ctx, fmt.Errorf("PendingTransactionInformation failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, v2.Log)
	}

	var addrPtr *basics.Address

	if addrFilter != nil {
		addr, err := basics.UnmarshalChecksumAddress(*addrFilter)
		if err != nil {
			return badRequest(ctx, err, errFailedToParseAddress, v2.Log)
		}
		addrPtr = &addr
	}

	handle, contentType, err := getCodecHandle(format)
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	txns, err := v2.Node.GetPendingTxnsFromPool()
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpTransactionPool, v2.Log)
	}

	// MatchAddress uses this to check FeeSink, we don't care about that here.
	spec := transactions.SpecialAddresses{
		FeeSink:     basics.Address{},
		RewardsPool: basics.Address{},
	}

	// Convert transactions to msgp / json strings
	txnArray := make([]transactions.SignedTxn, 0)
	for _, txn := range txns {
		// break out if we've reached the max number of transactions
		if max != nil && uint64(len(txnArray)) >= *max {
			break
		}

		// continue if we have an address filter and the address doesn't match the transaction.
		if addrPtr != nil && !txn.Txn.MatchAddress(*addrPtr, spec) {
			continue
		}

		txnArray = append(txnArray, txn)
	}

	// Encoding wasn't working well without embedding "real" objects.
	response := struct {
		TopTransactions   []transactions.SignedTxn `json:"top-transactions"`
		TotalTransactions uint64                   `json:"total-transactions"`
	}{
		TopTransactions:   txnArray,
		TotalTransactions: uint64(len(txnArray)),
	}

	data, err := encode(handle, response)
	if err != nil {
		return internalError(ctx, err, errFailedToEncodeResponse, v2.Log)
	}

	return ctx.Blob(http.StatusOK, contentType, data)
}

// startCatchup Given a catchpoint, it starts catching up to this catchpoint
func (v2 *Handlers) startCatchup(ctx echo.Context, catchpoint string) error {
	_, _, err := ledger.ParseCatchpointLabel(catchpoint)
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

	return ctx.JSON(code, private.CatchpointStartResponse{
		CatchupMessage: catchpoint,
	})
}

// abortCatchup Given a catchpoint, it aborts catching up to this catchpoint
func (v2 *Handlers) abortCatchup(ctx echo.Context, catchpoint string) error {
	_, _, err := ledger.ParseCatchpointLabel(catchpoint)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseCatchpoint, v2.Log)
	}

	err = v2.Node.AbortCatchup(catchpoint)
	if err != nil {
		return internalError(ctx, err, fmt.Sprintf(errFailedToAbortCatchup, err), v2.Log)
	}

	return ctx.JSON(http.StatusOK, private.CatchpointAbortResponse{
		CatchupMessage: catchpoint,
	})
}

// GetPendingTransactions returns the list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/transactions/pending)
func (v2 *Handlers) GetPendingTransactions(ctx echo.Context, params generated.GetPendingTransactionsParams) error {
	return v2.getPendingTransactions(ctx, params.Max, params.Format, nil)
}

// GetApplicationByID returns application information by app idx.
// (GET /v2/applications/{application-id})
func (v2 *Handlers) GetApplicationByID(ctx echo.Context, applicationID uint64) error {
	appIdx := basics.AppIndex(applicationID)
	ledger := v2.Node.Ledger()
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(appIdx), basics.AppCreatable)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if !ok {
		return notFound(ctx, errors.New(errAppDoesNotExist), errAppDoesNotExist, v2.Log)
	}

	lastRound := ledger.Latest()
	record, err := ledger.Lookup(lastRound, creator)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	appParams, ok := record.AppParams[appIdx]
	if !ok {
		return notFound(ctx, errors.New(errAppDoesNotExist), errAppDoesNotExist, v2.Log)
	}
	app := AppParamsToApplication(creator.String(), appIdx, &appParams)
	response := generated.ApplicationResponse(app)
	return ctx.JSON(http.StatusOK, response)
}

// GetAssetByID returns application information by app idx.
// (GET /v2/assets/{asset-id})
func (v2 *Handlers) GetAssetByID(ctx echo.Context, assetID uint64) error {
	assetIdx := basics.AssetIndex(assetID)
	ledger := v2.Node.Ledger()
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(assetIdx), basics.AssetCreatable)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	if !ok {
		return notFound(ctx, errors.New(errAssetDoesNotExist), errAssetDoesNotExist, v2.Log)
	}

	lastRound := ledger.Latest()
	record, err := ledger.Lookup(lastRound, creator)
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	assetParams, ok := record.AssetParams[assetIdx]
	if !ok {
		return notFound(ctx, errors.New(errAssetDoesNotExist), errAssetDoesNotExist, v2.Log)
	}

	asset := AssetParamsToAsset(creator.String(), assetIdx, &assetParams)
	response := generated.AssetResponse(asset)
	return ctx.JSON(http.StatusOK, response)
}

// GetPendingTransactionsByAddress takes an Algorand address and returns its associated list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/accounts/{address}/transactions/pending)
func (v2 *Handlers) GetPendingTransactionsByAddress(ctx echo.Context, addr string, params generated.GetPendingTransactionsByAddressParams) error {
	return v2.getPendingTransactions(ctx, params.Max, params.Format, &addr)
}

// StartCatchup Given a catchpoint, it starts catching up to this catchpoint
// (POST /v2/catchup/{catchpoint})
func (v2 *Handlers) StartCatchup(ctx echo.Context, catchpoint string) error {
	return v2.startCatchup(ctx, catchpoint)
}

// AbortCatchup Given a catchpoint, it aborts catching up to this catchpoint
// (DELETE /v2/catchup/{catchpoint})
func (v2 *Handlers) AbortCatchup(ctx echo.Context, catchpoint string) error {
	return v2.abortCatchup(ctx, catchpoint)
}

// TealCompile compiles TEAL code to binary, return both binary and hash
// (POST /v2/teal/compile)
func (v2 *Handlers) TealCompile(ctx echo.Context) error {
	// return early if teal compile is not allowed in node config
	if !v2.Node.Config().EnableDeveloperAPI {
		return ctx.String(http.StatusNotFound, "/teal/compile was not enabled in the configuration file by setting the EnableDeveloperAPI to true")
	}
	buf := new(bytes.Buffer)
	ctx.Request().Body = http.MaxBytesReader(nil, ctx.Request().Body, maxTealSourceBytes)
	buf.ReadFrom(ctx.Request().Body)
	source := buf.String()
	program, err := logic.AssembleString(source)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	pd := logic.HashProgram(program)
	addr := basics.Address(pd)
	response := generated.CompileResponse{
		Hash:   addr.String(),
		Result: base64.StdEncoding.EncodeToString(program),
	}
	return ctx.JSON(http.StatusOK, response)
}
