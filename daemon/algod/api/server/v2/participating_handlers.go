package v2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v1/routes"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	pprivate "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/participating/private"
	ppublic "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/participating/public"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

// ParticipatingHandlers is an implementation to the V2 route handler interface defined by the generated code.
// Corresponding methods in the oapi spec are tagged as `participating`
type ParticipatingHandlers struct {
	NonParticipatingHandlers
	Node node.ParticipatingNodeInterface
}

// Register implements route registration for the HandlerInterface
func (v2 *ParticipatingHandlers) Register(e *echo.Echo, publicAuth echo.MiddlewareFunc, privateAuth echo.MiddlewareFunc) {
	ppublic.RegisterHandlers(e, v2, publicAuth)
	pprivate.RegisterHandlers(e, v2, privateAuth)
	ctx := lib.ReqContext{
		Node:     v2.Node,
		Log:      v2.Log,
		Shutdown: v2.Shutdown,
	}
	registerHandlers(e, routes.APIV1Tag, routes.V1Routes, ctx, publicAuth)
	registerCommon(e, v2.Node)
}

// GetNode implements the HandlerInterface
func (v2 *ParticipatingHandlers) GetNode() node.BaseNodeInterface {
	return v2.Node
}

// GetParticipationKeys Return a list of participation keys
// (GET /v2/participation)
func (v2 *ParticipatingHandlers) GetParticipationKeys(ctx echo.Context) error {
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

// AddParticipationKey Add a participation key to the node
// (POST /v2/participation)
func (v2 *ParticipatingHandlers) AddParticipationKey(ctx echo.Context) error {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(ctx.Request().Body)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}
	partKeyBinary := buf.Bytes()

	if len(partKeyBinary) == 0 {
		err := fmt.Errorf(errRESTPayloadZeroLength)
		return badRequest(ctx, err, err.Error(), v2.Log)
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
func (v2 *ParticipatingHandlers) DeleteParticipationKeyByID(ctx echo.Context, participationID string) error {

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
func (v2 *ParticipatingHandlers) GetParticipationKeyByID(ctx echo.Context, participationID string) error {

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
func (v2 *ParticipatingHandlers) AppendKeys(ctx echo.Context, participationID string) error {
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

// RawTransaction broadcasts a raw transaction to the network.
// (POST /v2/transactions)
func (v2 *ParticipatingHandlers) RawTransaction(ctx echo.Context) error {
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
	return ctx.JSON(http.StatusOK, model.PostTransactionsResponse{TxId: txid.String()})
}

// TransactionParams returns the suggested parameters for constructing a new transaction.
// (GET /v2/transactions/params)
func (v2 *ParticipatingHandlers) TransactionParams(ctx echo.Context) error {
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
		LastRound:        uint64(stat.LastRound),
		MinFee:           proto.MinTxnFee,
	}

	return ctx.JSON(http.StatusOK, response)
}

// PendingTransactionInformation returns a transaction with the specified txID
// from the transaction pool. If not found looks for the transaction in the
// last proto.MaxTxnLife rounds
// (GET /v2/transactions/pending/{txid})
func (v2 *ParticipatingHandlers) PendingTransactionInformation(ctx echo.Context, txid string, params model.PendingTransactionInformationParams) error {

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
		return badRequest(ctx, err, errNoValidTxnSpecified, v2.Log)
	}

	txn, ok := v2.Node.GetPendingTransaction(txID)

	// We didn't find it, return a failure
	if !ok {
		err := errors.New(errTransactionNotFound)
		return notFound(ctx, err, err.Error(), v2.Log)
	}

	// Encoding wasn't working well without embedding "real" objects.
	response := PreEncodedTxInfo{
		Txn:       txn.Txn,
		PoolError: txn.PoolError,
	}

	if txn.ConfirmedRound != 0 {
		r := uint64(txn.ConfirmedRound)
		response.ConfirmedRound = &r

		response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
		response.AssetClosingAmount = &txn.ApplyData.AssetClosingAmount
		response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
		response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
		response.CloseRewards = &txn.ApplyData.CloseRewards.Raw
		response.AssetIndex = computeAssetIndexFromTxn(txn, v2.Node.LedgerForAPI())
		response.ApplicationIndex = computeAppIndexFromTxn(txn, v2.Node.LedgerForAPI())
		response.LocalStateDelta, response.GlobalStateDelta = convertToDeltas(txn)
		response.Logs = convertLogs(txn)
		response.Inners = convertInners(&txn)
	}

	handle, contentType, err := getCodecHandle((*model.Format)(params.Format))
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
func (v2 *ParticipatingHandlers) getPendingTransactions(ctx echo.Context, max *uint64, format *string, addrFilter *string) error {

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

	handle, contentType, err := getCodecHandle((*model.Format)(format))
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	txnPool, err := v2.Node.GetPendingTxnsFromPool()
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpTransactionPool, v2.Log)
	}

	// MatchAddress uses this to check FeeSink, we don't care about that here.
	spec := transactions.SpecialAddresses{
		FeeSink:     basics.Address{},
		RewardsPool: basics.Address{},
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
		if addrPtr != nil && !txn.Txn.MatchAddress(*addrPtr, spec) {
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

// GetPendingTransactions returns the list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/transactions/pending)
func (v2 *ParticipatingHandlers) GetPendingTransactions(ctx echo.Context, params model.GetPendingTransactionsParams) error {
	return v2.getPendingTransactions(ctx, params.Max, (*string)(params.Format), nil)
}

// GetPendingTransactionsByAddress takes an Algorand address and returns its associated list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/accounts/{address}/transactions/pending)
func (v2 *ParticipatingHandlers) GetPendingTransactionsByAddress(ctx echo.Context, addr string, params model.GetPendingTransactionsByAddressParams) error {
	return v2.getPendingTransactions(ctx, params.Max, (*string)(params.Format), &addr)
}
