package v2

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

type V2Handlers struct {
	Node     *node.AlgorandFullNode
	Log      logging.Logger
	Shutdown <-chan struct{}
}

// Get account information.
// (GET /v2/accounts/{address})
func (v2 *V2Handlers) AccountInformation(ctx echo.Context, address string) error {
	// TODO
	return nil
}

// Get a list of unconfirmed transactions currently in the transaction pool by address.
// (GET /v2/accounts/{addr}/transactions/pending)
func (v2 *V2Handlers) GetPendingTransactionsByAddress(ctx echo.Context, addr string, params generated.GetPendingTransactionsByAddressParams) error {
	// TODO
	return nil
}

// Get the block for the given round.
// (GET /v2/blocks/{round})
func (v2 *V2Handlers) GetBlock(ctx echo.Context, round uint64, params generated.GetBlockParams) error {
	// TODO
	return nil
}

// Get the current supply reported by the ledger.
// (GET /v2/ledger/supply)
func (v2 *V2Handlers) GetSupply(ctx echo.Context) error {
	// TODO
	return nil
}

// (POST /v2/register-participation-keys/{account-id})
func (v2 *V2Handlers) PostV2RegisterParticipationKeysAccountId(ctx echo.Context, accountId string, params generated.PostV2RegisterParticipationKeysAccountIdParams) error {
	// TODO
	return nil
}

// (POST /v2/shutdown)
func (v2 *V2Handlers) PostV2Shutdown(ctx echo.Context, params generated.PostV2ShutdownParams) error {
	// TODO
	return nil
}

// Gets the current node status.
// (GET /v2/status)
func (v2 *V2Handlers) GetStatus(ctx echo.Context) error {
	// TODO
	return nil
}

// Gets the node status after waiting for the given round.
// (GET /v2/status/wait-for-block-after/{round}/)
func (v2 *V2Handlers) WaitForBlock(ctx echo.Context, round uint64) error {
	// TODO
	return nil
}

// Broadcasts a raw transaction to the network.
// (POST /v2/transactions)
func (v2 *V2Handlers) RawTransaction(ctx echo.Context) error {
	var txgroup []transactions.SignedTxn
	dec := protocol.NewDecoder(ctx.Request().Body)
	for {
		var st transactions.SignedTxn
		err := dec.Decode(&st)
		if err == io.EOF {
			break
		}
		if err != nil {
			return returnError(ctx, http.StatusBadRequest, err, v2.Log)
		}
		txgroup = append(txgroup, st)
	}

	if len(txgroup) == 0 {
		err := errors.New("empty txgroup")
		return returnError(ctx, http.StatusBadRequest, err, v2.Log)
	}

	err := v2.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		return returnError(ctx, http.StatusBadRequest, err, v2.Log)
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	return ctx.JSON(http.StatusOK, generated.PostTransactionsResponse{TxId:txid.String()})
}

// Get parameters for constructing a new transaction
// (GET /v2/transactions/params)
func (v2 *V2Handlers) TransactionParams(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, v2.Log)
	}

	gh := v2.Node.GenesisHash()

	var params generated.TransactionParams
	params.Fee = v2.Node.SuggestedFee().Raw
	params.GenesisID = v2.Node.GenesisID()
	params.GenesisHash = gh[:]
	params.LastRound = uint64(stat.LastRound)
	params.ConsensusVersion = string(stat.LastVersion)

	proto := config.Consensus[stat.LastVersion]
	params.MinFee = proto.MinTxnFee

	return ctx.JSON(http.StatusOK, params)
}

func returnError(ctx echo.Context, code int, err error, logger logging.Logger) error {
	logger.Info(err)
	return ctx.JSON(code, generated.Error{Error:err.Error()})
}

// Get a list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/transactions/pending)
func (v2 *V2Handlers) GetPendingTransactions(ctx echo.Context, params generated.GetPendingTransactionsParams) error {
	txns, err := v2.Node.GetPendingTxnsFromPool()
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, v2.Log)
	}

	handle, err := getCodecHandle(params.Format)
	if err != nil {
		return returnError(ctx, http.StatusBadRequest, err, v2.Log)
	}

	// Convert transactions to msgp / json strings
	encodedTxns := make([]string, 0)
	for idx, txn := range txns {
		if params.Max != nil && uint64(idx) >= *params.Max {
			break;
		}

		encodedTxn, err := encode(handle, txn)
		if err != nil {
			return returnError(ctx, http.StatusInternalServerError, err, v2.Log)
		}
		encodedTxns = append(encodedTxns, encodedTxn)

	}

	return ctx.JSON(http.StatusOK, generated.PendingTransactionsResponse{
		TopTransactions:   encodedTxns,
		TotalTransactions: uint64(len(txns)),
	})
}

func computeAssetIndexInPayset(tx node.TxnWithStatus, txnCounter uint64, payset []transactions.SignedTxnWithAD) (aidx *uint64) {
	// Compute transaction index in block
	offset := -1
	for idx, stxnib := range payset {
		if tx.Txn.Txn.ID() == stxnib.Txn.ID() {
			offset = idx
			break
		}
	}

	// Sanity check that txn was in fetched block
	if offset < 0 {
		return nil
	}

	// Count into block to get created asset index
	idx := txnCounter - uint64(len(payset)) + uint64(offset) + 1
	return &idx
}

// computeAssetIndexFromTxn returns the created asset index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAssetIndexFromTxn(tx node.TxnWithStatus, l *data.Ledger) (aidx *uint64) {
	// Must have ledger
	if l == nil {
		return nil
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return nil
	}
	// Transaction must be AssetConfig transaction
	if tx.Txn.Txn.AssetConfigTxnFields == (transactions.AssetConfigTxnFields{}) {
		return nil
	}
	// Transaction must be creating an asset
	if tx.Txn.Txn.AssetConfigTxnFields.ConfigAsset != 0 {
		return nil
	}

	// Look up block where transaction was confirmed
	blk, err := l.Block(tx.ConfirmedRound)
	if err != nil {
		return nil
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil
	}

	return computeAssetIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset)
}

func getCodecHandle(formatPtr *string) (codec.Handle, error) {
	format := "json"
	if formatPtr != nil {
		format = strings.ToLower(*formatPtr)
	}

	var handle codec.Handle = protocol.JSONHandle
	if format == "json" {
		handle = protocol.JSONHandle
	} else if format == "msgpack" || format == "msgp" {
		handle = protocol.CodecHandle
	} else {
		fmt.Sprintf("invalid format: %s", format)
	}

	return handle, nil
}

func encode(handle codec.Handle, obj interface{}) (string, error) {
	var output []byte
	enc := codec.NewEncoderBytes(&output, handle)

	err := enc.Encode(obj)
	if err != nil {
		return "", fmt.Errorf("failed to encode object: %v", err)
	}
	return string(output), nil
}

// Get a specific pending transaction.
// (GET /v2/transactions/pending/{txid})
func (v2 *V2Handlers) PendingTransactionInformation(ctx echo.Context, txid string, params generated.PendingTransactionInformationParams) error {
	txID := transactions.Txid{}
	if txID.UnmarshalText([]byte(txid)) != nil {
		return returnError(ctx, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), v2.Log)
	}

	if txn, ok := v2.Node.GetPendingTransaction(txID); ok {
		response := generated.PendingTransactionResponse{
			Txn:             "",
			PoolError:       "",
			ClosingAmount:   nil,
			ConfirmedRound:  nil,
			SenderRewards:   nil,
			ReceiverRewards: nil,
			CloseRewards:    nil,
		}

		handle, err := getCodecHandle(params.Format)
		if err != nil {
			return returnError(ctx, http.StatusBadRequest, err, v2.Log)
		}

		encoded, err := encode(handle, txn.Txn)
		if err != nil {
			return returnError(ctx, http.StatusInternalServerError, err, v2.Log)
		}

		response.Txn = encoded

		if txn.ConfirmedRound != 0 {
			r := uint64(txn.ConfirmedRound)
			response.ConfirmedRound = &r

			response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
			response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
			response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
			response.CloseRewards = &txn.ApplyData.CloseRewards.Raw

			response.AssetIndex = computeAssetIndexFromTxn(txn, v2.Node.Ledger())
		}

		return ctx.JSON(http.StatusOK, response)
	}

	// We didn't find it, return a failure
	return ctx.JSON(http.StatusNotFound, errors.New(errTransactionNotFound))
	//lib.ErrorResponse(w, http.StatusNotFound, errors.New(errTransactionNotFound), errTransactionNotFound, ctx.Log)
	//return
}

