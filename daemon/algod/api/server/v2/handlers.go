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
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// Handlers is an implementation to the V2 route handler interface defined by the generated code.
type Handlers struct {
	Node     *node.AlgorandFullNode
	Log      logging.Logger
	Shutdown <-chan struct{}
}

// RegisterParticipationKeys registers participation keys.
// (POST /v2/register-participation-keys/{address})
func (v2 *Handlers) RegisterParticipationKeys(ctx echo.Context, address string, params generated.RegisterParticipationKeysParams) error {
	// TODO: register participation keys endpoint
	return ctx.String(http.StatusNotImplemented, "Endpoint not implemented.")
}

// ShutdownNode shuts down the node.
// (POST /v2/shutdown)
func (v2 *Handlers) ShutdownNode(ctx echo.Context, params generated.ShutdownNodeParams) error {
	// TODO: shutdown endpoint
	return ctx.String(http.StatusNotImplemented, "Endpoint not implemented.")
}

// AccountInformation gets account information for a given account.
// (GET /v2/accounts/{address})
func (v2 *Handlers) AccountInformation(ctx echo.Context, address string) error {
	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return badRequest(ctx, err, errFailedToParseAddress, v2.Log)
	}

	myLedger := v2.Node.Ledger()
	lastRound := myLedger.Latest()
	record, err := myLedger.Lookup(lastRound, basics.Address(addr))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}
	recordWithoutPendingRewards, err := myLedger.LookupWithoutRewards(lastRound, basics.Address(addr))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	amount := record.MicroAlgos
	amountWithoutPendingRewards := recordWithoutPendingRewards.MicroAlgos
	pendingRewards, overflowed := basics.OSubA(amount, amountWithoutPendingRewards)
	if overflowed {
		return internalError(ctx, err, errInternalFailure, v2.Log)
	}

	assets := make([]generated.AssetHolding, 0)
	if len(record.Assets) > 0 {
		//assets = make(map[uint64]v1.AssetHolding)
		for curid, holding := range record.Assets {
			var creator string
			creatorAddr, err := myLedger.GetAssetCreator(curid)
			if err == nil {
				creator = creatorAddr.String()
			} else {
				// Asset may have been deleted, so we can no
				// longer fetch the creator
				creator = ""
			}

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
			VoteParticipationKey:      byteOrNil(record.VoteID[:]),
			SelectionParticipationKey: byteOrNil(record.SelectionID[:]),
			VoteFirstValid:            numOrNil(uint64(record.VoteFirstValid)),
			VoteLastValid:             numOrNil(uint64(record.VoteLastValid)),
			VoteKeyDilution:           numOrNil(uint64(record.VoteKeyDilution)),
		}
	}

	response := generated.AccountResponse{
		Type:                        nil,
		Round:                       uint64(lastRound),
		Address:                     addr.String(),
		Amount:                      amount.Raw,
		PendingRewards:              pendingRewards.Raw,
		AmountWithoutPendingRewards: amountWithoutPendingRewards.Raw,
		Rewards:                     record.RewardedMicroAlgos.Raw,
		Status:                      record.Status.String(),
		RewardBase:                  &record.RewardsBase,
		Participation:               apiParticipation,
		CreatedAssets:               &createdAssets,
		Assets:                      &assets,
	}

	return ctx.JSON(http.StatusOK, response)
}

// GetBlock gets the block for the given round.
// (GET /v2/blocks/{round})
func (v2 *Handlers) GetBlock(ctx echo.Context, round uint64, params generated.GetBlockParams) error {
	handle, err := getCodecHandle(params.Format)
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	// msgpack format will return the raw block bytes and attach some custom headers.
	if handle == protocol.CodecHandle {
		blockbytes, err := rpcs.RawBlockBytes(v2.Node.Ledger(), basics.Round(round))
		if err != nil {
			return internalError(ctx, err, err.Error(), v2.Log)
		}

		ctx.Response().Writer.Header().Add("X-Algorand-Struct", "block-v1")
		return ctx.Blob(http.StatusOK, "application/msgpack", blockbytes)
	}

	ledger := v2.Node.Ledger()
	block, _, err := ledger.BlockCert(basics.Round(round))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	response := generated.BlockResponse{}

	toCodecMap(block, &response.Block)

	return ctx.JSON(http.StatusOK, response)
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
		LastRound:                 uint64(stat.LastRound),
		LastVersion:               string(stat.LastVersion),
		NextVersion:               string(stat.NextVersion),
		NextVersionRound:          uint64(stat.NextVersionRound),
		NextVersionSupported:      stat.NextVersionSupported,
		TimeSinceLastRound:        uint64(stat.TimeSinceLastRound().Nanoseconds()),
		CatchupTime:               uint64(stat.CatchupTime.Nanoseconds()),
		StoppedAtUnsupportedRound: stat.StoppedAtUnsupportedRound,
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
	}

	if len(txgroup) == 0 {
		err := errors.New("empty txgroup")
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	err := v2.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	return ctx.JSON(http.StatusOK, generated.PostTransactionsResponse{TxId: txid.String()})
}

// TransactionParams returns the suggested parameters for constructing a new transaction.
// (GET /v2/transactions/params)
func (v2 *Handlers) TransactionParams(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return internalError(ctx, err, errFailedRetrievingNodeStatus, v2.Log)
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
	txID := transactions.Txid{}
	if err := txID.UnmarshalText([]byte(txid)); err != nil {
		return badRequest(ctx, err, errNoTxnSpecified, v2.Log)
	}

	if txn, ok := v2.Node.GetPendingTransaction(txID); ok {
		response := generated.PendingTransactionResponse{
			Txn:             nil,
			PoolError:       "",
			ClosingAmount:   nil,
			ConfirmedRound:  nil,
			SenderRewards:   nil,
			ReceiverRewards: nil,
			CloseRewards:    nil,
		}

		handle, err := getCodecHandle(params.Format)
		if err != nil {
			return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
		}

		toCodecMap(txn.Txn, &response.Txn)

		if txn.ConfirmedRound != 0 {
			r := uint64(txn.ConfirmedRound)
			response.ConfirmedRound = &r

			response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
			response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
			response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
			response.CloseRewards = &txn.ApplyData.CloseRewards.Raw

			response.AssetIndex = computeAssetIndexFromTxn(txn, v2.Node.Ledger())
		}

		if handle == protocol.CodecHandle {
			data, err := encode(handle, response)
			if err != nil {
				return internalError(ctx, err, errFailedToParseTransaction, v2.Log)
			}
			return ctx.Blob(http.StatusOK, "application/msgpack", data)
		}

		return ctx.JSON(http.StatusOK, response)
	}

	// We didn't find it, return a failure
	err := errors.New(errTransactionNotFound)
	return notFound(ctx, err, err.Error(), v2.Log)
}

// getPendingTransactions returns to the provided context a list of uncomfirmed transactions currently in the transaction pool with optional Max/Address filters.
func (v2 *Handlers) getPendingTransactions(ctx echo.Context, max *uint64, format *string, addrFilter *string) error {
	var addrPtr *basics.Address

	if addrFilter != nil {
		addr, err := basics.UnmarshalChecksumAddress(*addrFilter)
		if err != nil {
			return badRequest(ctx, err, errFailedToParseAddress, v2.Log)
		}
		addrPtr = &addr
	}

	handle, err := getCodecHandle(format)
	if err != nil {
		return badRequest(ctx, err, errFailedParsingFormatOption, v2.Log)
	}

	txns, err := v2.Node.GetPendingTxnsFromPool()
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpTransactionPool, v2.Log)
	}

	// TODO: What should I put in here? MatchAddress uses this to check the FeeSink so I think this is fine.
	spec := transactions.SpecialAddresses{
		FeeSink:     basics.Address{},
		RewardsPool: basics.Address{},
	}

	// Convert transactions to msgp / json strings
	encodedTxns := make([]map[string]interface{}, 0)
	for _, txn := range txns {
		// break out if we've reached the max number of transactions
		if max != nil && uint64(len(encodedTxns)) >= *max {
			break
		}

		// continue if we have an address filter and the address doesn't match the transaction.
		if addrPtr != nil && !txn.Txn.MatchAddress(*addrPtr, spec) {
			continue
		}

		var encodedTxn map[string]interface{}
		toCodecMap(txn, &encodedTxn)
		encodedTxns = append(encodedTxns, encodedTxn)
	}

	response := generated.PendingTransactionsResponse{
		TopTransactions:   encodedTxns,
		TotalTransactions: uint64(len(txns)),
	}

	// Encode to message pack
	if handle == protocol.CodecHandle {
		data, err := encode(handle, response)
		if err != nil {
			return internalError(ctx, err, errFailedToParseTransaction, v2.Log)
		}

		return ctx.Blob(http.StatusOK, "application/msgpack", data)
	}

	return ctx.JSON(http.StatusOK, response)
}

// GetPendingTransactions returns the list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/transactions/pending)
func (v2 *Handlers) GetPendingTransactions(ctx echo.Context, params generated.GetPendingTransactionsParams) error {
	return v2.getPendingTransactions(ctx, params.Max, params.Format, nil)
}

// GetPendingTransactionsByAddress takes an Algorand address and returns its associated list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/accounts/{address}/transactions/pending)
func (v2 *Handlers) GetPendingTransactionsByAddress(ctx echo.Context, addr string, params generated.GetPendingTransactionsByAddressParams) error {
	return v2.getPendingTransactions(ctx, params.Max, params.Format, &addr)
}
