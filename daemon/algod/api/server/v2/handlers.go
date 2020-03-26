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
	// TODO
	return nil
}

// ShutdownNode shuts down the node.
// (POST /v2/shutdown)
func (v2 *Handlers) ShutdownNode(ctx echo.Context, params generated.ShutdownNodeParams) error {
	// TODO
	return nil
}

// AccountInformation gets account information for a given account.
// (GET /v2/accounts/{address})
func (v2 *Handlers) AccountInformation(ctx echo.Context, address string) error {
	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return returnError(ctx, http.StatusBadRequest, err, errFailedToParseAddress, v2.Log)
	}

	myLedger := v2.Node.Ledger()
	lastRound := myLedger.Latest()
	record, err := myLedger.Lookup(lastRound, basics.Address(addr))
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, errFailedLookingUpLedger, v2.Log)
	}
	recordWithoutPendingRewards, err := myLedger.LookupWithoutRewards(lastRound, basics.Address(addr))
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, errFailedLookingUpLedger, v2.Log)
	}

	amount := record.MicroAlgos
	amountWithoutPendingRewards := recordWithoutPendingRewards.MicroAlgos
	pendingRewards, overflowed := basics.OSubA(amount, amountWithoutPendingRewards)
	if overflowed {
		return returnError(ctx, http.StatusInternalServerError, err, errInternalFailure, v2.Log)
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
		return returnError(ctx, http.StatusBadRequest, err, errFailedParsingFormatOption, v2.Log)
	}

	// TODO: What is raw block bytes, should I use that instead?
	//blockbytes, err := rpcs.RawBlockBytes(v2.Node.Ledger(), basics.Round(round))

	ledger := v2.Node.Ledger()
	block, _, err := ledger.BlockCert(basics.Round(round))
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, errFailedLookingUpLedger, v2.Log)
	}

	encoded, err := encode(handle, block)
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, errFailedToParseBlock, v2.Log)
	}

	return ctx.JSON(http.StatusOK, generated.BlockResponse{
		Block: encoded,
	})
}

// GetSupply gets the current supply reported by the ledger.
// (GET /v2/ledger/supply)
func (v2 *Handlers) GetSupply(ctx echo.Context) error {
	latest := v2.Node.Ledger().Latest()
	totals, err := v2.Node.Ledger().Totals(latest)
	if err != nil {
		err = fmt.Errorf("GetSupply(): round %d, failed: %v", latest, err)
		return returnError(ctx, http.StatusInternalServerError, err, errInternalFailure, v2.Log)
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
		return returnError(ctx, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, v2.Log)
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

// WaitForBlock gets the node status after waiting for the given round.
// (GET /v2/status/wait-for-block-after/{round}/)
func (v2 *Handlers) WaitForBlock(ctx echo.Context, round uint64) error {
	ledger := v2.Node.Ledger()
	latestBlkHdr, err := ledger.BlockHdr(ledger.Latest())
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, v2.Log)
	}

	// TODO: Replace this with Node.Status().StoppedAtUnsupportedRound ?
	if latestBlkHdr.NextProtocol != "" {
		if _, nextProtocolSupported := config.Consensus[latestBlkHdr.NextProtocol]; !nextProtocolSupported {
			// see if the desired protocol switch is expect to happen before or after the above point.
			if latestBlkHdr.NextProtocolSwitchOn <= basics.Round(round+1) {
				// we would never reach to this round, since this round would happen after the (unsupported) protocol upgrade.
				return returnError(ctx, http.StatusBadRequest, err, errRequestedRoundInUnsupportedRound, v2.Log)
			}
		}
	}

	// Wait
	select {
	case <-v2.Shutdown:
		return returnError(ctx, http.StatusInternalServerError, err, errServiceShuttingDown, v2.Log)
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
			return returnError(ctx, http.StatusBadRequest, err, err.Error(), v2.Log)
		}
		txgroup = append(txgroup, st)
	}

	if len(txgroup) == 0 {
		err := errors.New("empty txgroup")
		return returnError(ctx, http.StatusBadRequest, err, err.Error(), v2.Log)
	}

	err := v2.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		return returnError(ctx, http.StatusBadRequest, err, err.Error(), v2.Log)
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	return ctx.JSON(http.StatusOK, generated.PostTransactionsResponse{TxId: txid.String()})
}

// TransactionParams gets parameters for constructing a new transaction
// (GET /v2/transactions/params)
func (v2 *Handlers) TransactionParams(ctx echo.Context) error {
	stat, err := v2.Node.Status()
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, v2.Log)
	}

	gh := v2.Node.GenesisHash()

	var params generated.TransactionParams
	params.Fee = v2.Node.SuggestedFee().Raw
	params.GenesisId = v2.Node.GenesisID()
	params.GenesisHash = gh[:]
	params.LastRound = uint64(stat.LastRound)
	params.ConsensusVersion = string(stat.LastVersion)

	proto := config.Consensus[stat.LastVersion]
	params.MinFee = proto.MinTxnFee

	return ctx.JSON(http.StatusOK, params)
}

// PendingTransactionInformation gets a specific pending transaction, or looks it up in the ledger if the recently
// confirmed block is still in the ledger.
// (GET /v2/transactions/pending/{txid})
func (v2 *Handlers) PendingTransactionInformation(ctx echo.Context, txid string, params generated.PendingTransactionInformationParams) error {
	txID := transactions.Txid{}
	if err := txID.UnmarshalText([]byte(txid)); err != nil {
		return returnError(ctx, http.StatusBadRequest, err, errNoTxnSpecified, v2.Log)
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
			return returnError(ctx, http.StatusBadRequest, err, errFailedParsingFormatOption, v2.Log)
		}

		encoded, err := encode(handle, txn.Txn)
		if err != nil {
			return returnError(ctx, http.StatusInternalServerError, err, errFailedToParseTransaction, v2.Log)
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
	err := errors.New(errTransactionNotFound)
	return returnError(ctx, http.StatusNotFound, err, err.Error(), v2.Log)
}

// getPendingTransactions is a generalized version of the get pending transactions endpoints for code reuse.
func (v2 *Handlers) getPendingTransactions(ctx echo.Context, max *uint64, format *string, addrFilter *string) error {
	var addrPtr *basics.Address

	if addrFilter != nil {
		addr, err := basics.UnmarshalChecksumAddress(*addrFilter)
		if err != nil {
			return returnError(ctx, http.StatusBadRequest, err, errFailedToParseAddress, v2.Log)
		}
		addrPtr = &addr
	}

	handle, err := getCodecHandle(format)
	if err != nil {
		return returnError(ctx, http.StatusBadRequest, err, errFailedParsingFormatOption, v2.Log)
	}

	txns, err := v2.Node.GetPendingTxnsFromPool()
	if err != nil {
		return returnError(ctx, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, v2.Log)
	}

	// TODO: What should I put in here? MatchAddress uses this to check the FeeSink so I think this is fine.
	spec := transactions.SpecialAddresses{
		FeeSink:     basics.Address{},
		RewardsPool: basics.Address{},
	}

	// Convert transactions to msgp / json strings
	encodedTxns := make([]string, 0)
	for _, txn := range txns {
		// break out if we've reached the max number of transactions
		if max != nil && uint64(len(encodedTxns)) >= *max {
			break
		}

		// continue if we have an address filter and the address doesn't match the transaction.
		if addrPtr != nil && !txn.Txn.MatchAddress(*addrPtr, spec) {
			continue
		}

		// Encode the transaction and added to the results
		encodedTxn, err := encode(handle, txn)
		if err != nil {
			return returnError(ctx, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, v2.Log)
		}
		encodedTxns = append(encodedTxns, encodedTxn)
	}

	return ctx.JSON(http.StatusOK, generated.PendingTransactionsResponse{
		TopTransactions:   encodedTxns,
		TotalTransactions: uint64(len(txns)),
	})
}

// GetPendingTransactions gets a list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/transactions/pending)
func (v2 *Handlers) GetPendingTransactions(ctx echo.Context, params generated.GetPendingTransactionsParams) error {
	return v2.getPendingTransactions(ctx, params.Max, params.Format, nil)
}

// GetPendingTransactionsByAddress gets a list of unconfirmed transactions currently in the transaction pool by address.
// (GET /v2/accounts/{address}/transactions/pending)
func (v2 *Handlers) GetPendingTransactionsByAddress(ctx echo.Context, addr string, params generated.GetPendingTransactionsByAddressParams) error {
	return v2.getPendingTransactions(ctx, params.Max, params.Format, &addr)
}
