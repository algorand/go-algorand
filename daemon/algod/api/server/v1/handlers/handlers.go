// Copyright (C) 2019 Algorand, Inc.
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

package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

func nodeStatus(node *node.AlgorandFullNode) (res v1.NodeStatus, err error) {
	stat, err := node.Status()
	if err != nil {
		return v1.NodeStatus{}, err
	}

	return v1.NodeStatus{
		LastRound:            uint64(stat.LastRound),
		LastVersion:          string(stat.LastVersion),
		NextVersion:          string(stat.NextVersion),
		NextVersionRound:     uint64(stat.NextVersionRound),
		NextVersionSupported: stat.NextVersionSupported,
		TimeSinceLastRound:   stat.TimeSinceLastRound().Nanoseconds(),
		CatchupTime:          stat.CatchupTime.Nanoseconds(),
	}, nil
}

// decorateUnknownTransactionTypeError takes an error of type errUnknownTransactionType and converts it into
// either errInvalidTransactionTypeLedger or errInvalidTransactionTypePending as needed.
func decorateUnknownTransactionTypeError(err error, txs node.TxnWithStatus) error {
	if err.Error() != errUnknownTransactionType {
		return err
	}
	if txs.ConfirmedRound != basics.Round(0) {
		return fmt.Errorf(errInvalidTransactionTypeLedger, txs.Txn.Txn.Type, txs.Txn.Txn.ID().String(), txs.ConfirmedRound)
	}
	return fmt.Errorf(errInvalidTransactionTypePending, txs.Txn.Txn.Type, txs.Txn.Txn.ID().String())
}

// txEncode copies the data fields of the internal transaction object and populate the v1.Transaction accordingly.
// if unexpected transaction type is encountered, an error is returned. The caller is expected to ignore the returned
// transaction when error is non-nil.
func txEncode(tx transactions.Transaction, ad transactions.ApplyData) (v1.Transaction, error) {
	var res v1.Transaction
	switch tx.Type {
	case protocol.PaymentTx:
		res = paymentTxEncode(tx, ad)
	case protocol.KeyRegistrationTx:
		res = keyregTxEncode(tx, ad)
	case protocol.AssetConfigTx:
		res = assetConfigTxEncode(tx, ad)
	case protocol.AssetTransferTx:
		res = assetTransferTxEncode(tx, ad)
	case protocol.AssetFreezeTx:
		res = assetFreezeTxEncode(tx, ad)
	default:
		return res, errors.New(errUnknownTransactionType)
	}

	res.Type = string(tx.Type)
	res.TxID = tx.ID().String()
	res.From = tx.Src().String()
	res.Fee = tx.TxFee().Raw
	res.FirstRound = uint64(tx.First())
	res.LastRound = uint64(tx.Last())
	res.Note = tx.Aux()
	res.FromRewards = ad.SenderRewards.Raw
	res.GenesisID = tx.GenesisID
	res.GenesisHash = tx.GenesisHash[:]
	res.Group = tx.Group[:]
	return res, nil
}

func paymentTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	payment := v1.PaymentTransactionType{
		To:           tx.Receiver.String(),
		Amount:       tx.TxAmount().Raw,
		ToRewards:    ad.ReceiverRewards.Raw,
		CloseRewards: ad.CloseRewards.Raw,
	}

	if tx.CloseRemainderTo != (basics.Address{}) {
		payment.CloseRemainderTo = tx.CloseRemainderTo.String()
		payment.CloseAmount = ad.ClosingAmount.Raw
	}

	return v1.Transaction{
		Payment: &payment,
	}
}

func keyregTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	keyreg := v1.KeyregTransactionType{
		VotePK:          tx.KeyregTxnFields.VotePK[:],
		SelectionPK:     tx.KeyregTxnFields.SelectionPK[:],
		VoteFirst:       uint64(tx.KeyregTxnFields.VoteFirst),
		VoteLast:        uint64(tx.KeyregTxnFields.VoteLast),
		VoteKeyDilution: tx.KeyregTxnFields.VoteKeyDilution,
	}

	return v1.Transaction{
		Keyreg: &keyreg,
	}
}

func assetParams(creator basics.Address, params basics.AssetParams) v1.AssetParams {
	paramsModel := v1.AssetParams{
		Total:         params.Total,
		DefaultFrozen: params.DefaultFrozen,
	}

	paramsModel.UnitName = strings.TrimRight(string(params.UnitName[:]), "\x00")
	paramsModel.AssetName = strings.TrimRight(string(params.AssetName[:]), "\x00")
	paramsModel.URL = strings.TrimRight(string(params.URL[:]), "\x00")
	if params.MetadataHash != [32]byte{} {
		paramsModel.MetadataHash = params.MetadataHash[:]
	}

	if !creator.IsZero() {
		paramsModel.Creator = creator.String()
	}

	if !params.Manager.IsZero() {
		paramsModel.ManagerAddr = params.Manager.String()
	}

	if !params.Reserve.IsZero() {
		paramsModel.ReserveAddr = params.Reserve.String()
	}

	if !params.Freeze.IsZero() {
		paramsModel.FreezeAddr = params.Freeze.String()
	}

	if !params.Clawback.IsZero() {
		paramsModel.ClawbackAddr = params.Clawback.String()
	}

	return paramsModel
}

func assetConfigTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	params := assetParams(basics.Address{}, tx.AssetConfigTxnFields.AssetParams)

	config := v1.AssetConfigTransactionType{
		AssetID: uint64(tx.AssetConfigTxnFields.ConfigAsset),
		Params:  params,
	}

	return v1.Transaction{
		AssetConfig: &config,
	}
}

func assetTransferTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	xfer := v1.AssetTransferTransactionType{
		AssetID:  uint64(tx.AssetTransferTxnFields.XferAsset),
		Amount:   tx.AssetTransferTxnFields.AssetAmount,
		Receiver: tx.AssetTransferTxnFields.AssetReceiver.String(),
	}

	if !tx.AssetTransferTxnFields.AssetSender.IsZero() {
		xfer.Sender = tx.AssetTransferTxnFields.AssetSender.String()
	}

	if !tx.AssetTransferTxnFields.AssetCloseTo.IsZero() {
		xfer.CloseTo = tx.AssetTransferTxnFields.AssetCloseTo.String()
	}

	return v1.Transaction{
		AssetTransfer: &xfer,
	}
}

func assetFreezeTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	freeze := v1.AssetFreezeTransactionType{
		AssetID:         uint64(tx.AssetFreezeTxnFields.FreezeAsset),
		Account:         tx.AssetFreezeTxnFields.FreezeAccount.String(),
		NewFreezeStatus: tx.AssetFreezeTxnFields.AssetFrozen,
	}

	return v1.Transaction{
		AssetFreeze: &freeze,
	}
}

func txWithStatusEncode(tr node.TxnWithStatus) (v1.Transaction, error) {
	s, err := txEncode(tr.Txn.Txn, tr.ApplyData)
	if err != nil {
		err = decorateUnknownTransactionTypeError(err, tr)
		return v1.Transaction{}, err
	}
	s.ConfirmedRound = uint64(tr.ConfirmedRound)
	s.PoolError = tr.PoolError
	return s, nil
}

func computeAssetIndexInPayset(tx node.TxnWithStatus, txnCounter uint64, payset []transactions.SignedTxnWithAD) (aidx uint64) {
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
		return 0
	}

	// Count into block to get created asset index
	return txnCounter - uint64(len(payset)) + uint64(offset) + 1
}

// computeAssetIndexFromTxn returns the created asset index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAssetIndexFromTxn(tx node.TxnWithStatus, l *data.Ledger) (aidx uint64) {
	// Must have ledger
	if l == nil {
		return 0
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return 0
	}
	// Transaction must be AssetConfig transaction
	if tx.Txn.Txn.AssetConfigTxnFields == (transactions.AssetConfigTxnFields{}) {
		return 0
	}
	// Transaction must be creating an asset
	if tx.Txn.Txn.AssetConfigTxnFields.ConfigAsset != 0 {
		return 0
	}

	// Look up block where transaction was confirmed
	blk, err := l.Block(tx.ConfirmedRound)
	if err != nil {
		return 0
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return 0
	}

	return computeAssetIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset)
}

func blockEncode(b bookkeeping.Block, c agreement.Certificate) (v1.Block, error) {
	block := v1.Block{
		Hash:              crypto.Digest(b.Hash()).String(),
		PreviousBlockHash: crypto.Digest(b.Branch).String(),
		Seed:              crypto.Digest(b.Seed()).String(),
		Proposer:          c.Proposal.OriginalProposer.String(),
		Round:             uint64(b.Round()),
		TransactionsRoot:  b.TxnRoot.String(),
		RewardsRate:       b.RewardsRate,
		RewardsLevel:      b.RewardsLevel,
		RewardsResidue:    b.RewardsResidue,
		Timestamp:         b.TimeStamp,

		UpgradeState: v1.UpgradeState{
			CurrentProtocol:        string(b.CurrentProtocol),
			NextProtocol:           string(b.NextProtocol),
			NextProtocolApprovals:  b.NextProtocolApprovals,
			NextProtocolVoteBefore: uint64(b.NextProtocolVoteBefore),
			NextProtocolSwitchOn:   uint64(b.NextProtocolSwitchOn),
		},
		UpgradeVote: v1.UpgradeVote{
			UpgradePropose: string(b.UpgradePropose),
			UpgradeApprove: b.UpgradeApprove,
		},
	}

	// Transactions
	var txns []v1.Transaction
	payset, err := b.DecodePaysetFlat()
	if err != nil {
		return v1.Block{}, err
	}

	for _, txn := range payset {
		tx := node.TxnWithStatus{
			Txn:            txn.SignedTxn,
			ConfirmedRound: b.Round(),
			ApplyData:      txn.ApplyData,
		}

		encTx, err := txWithStatusEncode(tx)
		if err != nil {
			return v1.Block{}, err
		}

		txns = append(txns, encTx)
	}

	block.Transactions = v1.TransactionList{Transactions: txns}

	return block, nil
}

// Status is an httpHandler for route GET /v1/status
func Status(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/status GetStatus
	//---
	//     Summary: Gets the current node status.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         "$ref": '#/responses/StatusResponse'
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	nodeStatus, err := nodeStatus(ctx.Node)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	response := StatusResponse{&nodeStatus}
	SendJSON(response, w, ctx.Log)
}

// WaitForBlock is an httpHandler for route GET /v1/status/wait-for-block-after/{round:[0-9]+}
func WaitForBlock(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/status/wait-for-block-after/{round}/ WaitForBlock
	// ---
	//     Summary: Gets the node status after waiting for the given round.
	//     Description: Waits for a block to appear after round {round} and returns the node's status at the time.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: round
	//         in: path
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: true
	//         description: The round to wait until returning status
	//     Responses:
	//       200:
	//         "$ref": '#/responses/StatusResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	queryRound, err := strconv.ParseUint(mux.Vars(r)["round"], 10, 64)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
		return
	}

	select {
	case <-time.After(1 * time.Minute):
	case <-ctx.Node.Ledger().Wait(basics.Round(queryRound + 1)):
	}

	nodeStatus, err := nodeStatus(ctx.Node)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	response := StatusResponse{&nodeStatus}
	SendJSON(response, w, ctx.Log)
}

// RawTransaction is an httpHandler for route POST /v1/transactions
func RawTransaction(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/transactions RawTransaction
	// ---
	//     Summary: Broadcasts a raw transaction to the network.
	//     Produces:
	//     - application/json
	//     Consumes:
	//     - application/x-binary
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: rawtxn
	//         in: body
	//         schema:
	//           type: string
	//           format: binary
	//         required: true
	//         description: The byte encoded signed transaction to broadcast to network
	//     Responses:
	//       200:
	//         "$ref": "#/responses/TransactionIDResponse"
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	var txgroup []transactions.SignedTxn
	dec := protocol.NewDecoder(r.Body)
	for {
		var st transactions.SignedTxn
		err := dec.Decode(&st)
		if err == io.EOF {
			break
		}
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
			return
		}
		txgroup = append(txgroup, st)
	}

	if len(txgroup) == 0 {
		err := errors.New("empty txgroup")
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	err := ctx.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	SendJSON(TransactionIDResponse{&v1.TransactionID{TxID: txid.String()}}, w, ctx.Log)
}

// AccountInformation is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]{KeyLength}}
func AccountInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{address} AccountInformation
	// ---
	//     Summary: Get account information.
	//     Description: Given a specific account public key, this call returns the accounts status, balance and spendable amounts
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: address
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//     Responses:
	//       200:
	//         "$ref": '#/responses/AccountInformationResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	queryAddr := mux.Vars(r)["addr"]

	if queryAddr == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoAccountSpecified), errNoAccountSpecified, ctx.Log)
		return
	}

	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAddress, ctx.Log)
		return
	}

	myLedger := ctx.Node.Ledger()
	lastRound := myLedger.Latest()
	record, err := myLedger.Lookup(lastRound, basics.Address(addr))
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
		return
	}
	recordWithoutPendingRewards, err := myLedger.LookupWithoutRewards(lastRound, basics.Address(addr))
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
		return
	}

	amount := record.MicroAlgos
	amountWithoutPendingRewards := recordWithoutPendingRewards.MicroAlgos
	pendingRewards, overflowed := basics.OSubA(amount, amountWithoutPendingRewards)
	if overflowed {
		err = fmt.Errorf("overflowed pending rewards: %v - %v", amount, amountWithoutPendingRewards)
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
		return
	}

	var assets map[uint64]v1.AssetHolding
	if len(record.Assets) > 0 {
		assets = make(map[uint64]v1.AssetHolding)
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
			assets[uint64(curid)] = v1.AssetHolding{
				Creator: creator,
				Amount:  holding.Amount,
				Frozen:  holding.Frozen,
			}
		}
	}

	var thisAssetParams map[uint64]v1.AssetParams
	if len(record.AssetParams) > 0 {
		thisAssetParams = make(map[uint64]v1.AssetParams)
		for idx, params := range record.AssetParams {
			thisAssetParams[uint64(idx)] = assetParams(addr, params)
		}
	}

	apiParticipation := v1.Participation{
		ParticipationPK: record.VoteID[:],
		VRFPK:           record.SelectionID[:],
		VoteFirst:       uint64(record.VoteFirstValid),
		VoteLast:        uint64(record.VoteLastValid),
		VoteKeyDilution: record.VoteKeyDilution,
	}
	accountInfo := v1.Account{
		Round:                       uint64(lastRound),
		Address:                     addr.String(),
		Amount:                      amount.Raw,
		PendingRewards:              pendingRewards.Raw,
		AmountWithoutPendingRewards: amountWithoutPendingRewards.Raw,
		Rewards:                     record.RewardedMicroAlgos.Raw,
		Status:                      record.Status.String(),
		Participation:               apiParticipation,
		AssetParams:                 thisAssetParams,
		Assets:                      assets,
	}

	SendJSON(AccountInformationResponse{&accountInfo}, w, ctx.Log)
}

// TransactionInformation is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]{KeyLength}}/transaction/{txid:[A-Z0-9]+}
func TransactionInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{address}/transaction/{txid} TransactionInformation
	// ---
	//     Summary: Get a specific confirmed transaction.
	//     Description: >
	//       Given a wallet address and a transaction id, it returns the confirmed transaction
	//       information. This call scans up to <CurrentProtocol>.MaxTxnLife blocks in the past.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: address
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//       - name: txid
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]+"
	//         required: true
	//         description: A transaction id
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       404:
	//         description: Transaction Not Found
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryTxID := mux.Vars(r)["txid"]
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	txID := transactions.Txid{}
	if txID.UnmarshalText([]byte(queryTxID)) != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	queryAddr := mux.Vars(r)["addr"]
	if queryAddr == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoAccountSpecified), errNoAccountSpecified, ctx.Log)
		return
	}

	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedToParseAddress), errFailedToParseAddress, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	latestRound := ledger.Latest()
	stat, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}
	proto := config.Consensus[stat.LastVersion]
	// non-Archival nodes keep proto.MaxTxnLife blocks around,
	// so without the + 1 in the below calculation,
	// Node.GetTransaction will query 1 round more than is kept around
	start := latestRound - basics.Round(proto.MaxTxnLife) + 1
	if latestRound < basics.Round(proto.MaxTxnLife) {
		start = 0
	}

	if txn, ok := ctx.Node.GetTransaction(addr, txID, start, latestRound); ok {
		var responseTxs v1.Transaction
		responseTxs, err = txWithStatusEncode(txn)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}

		response := TransactionResponse{
			Body: &responseTxs,
		}

		SendJSON(response, w, ctx.Log)
		return
	}

	// We didn't find it, return a failure
	lib.ErrorResponse(w, http.StatusNotFound, errors.New(errTransactionNotFound), errTransactionNotFound, ctx.Log)
	return
}

// PendingTransactionInformation is an httpHandler for route GET /v1/transactions/pending/{txid:[A-Z0-9]+}
func PendingTransactionInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/pending/{txid} PendingTransactionInformation
	// ---
	//     Summary: Get a specific pending transaction.
	//     Description: >
	//       Given a transaction id of a recently submitted transaction, it returns information
	//       about it.  There are several cases when this might succeed:
	//
	//       - transaction committed (committed round > 0)
	//       - transaction still in the pool (committed round = 0, pool error = "")
	//       - transaction removed from pool due to error (committed round = 0, pool error != "")
	//
	//       Or the transaction may have happened sufficiently long ago that the
	//       node no longer remembers it, and this will return an error.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: txid
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]+"
	//         required: true
	//         description: A transaction id
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       404:
	//         description: Transaction Not Found
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryTxID := mux.Vars(r)["txid"]
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	txID := transactions.Txid{}
	if txID.UnmarshalText([]byte(queryTxID)) != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	if txn, ok := ctx.Node.GetPendingTransaction(txID); ok {
		ledger := ctx.Node.Ledger()
		responseTxs, err := txWithStatusEncode(txn)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}

		responseTxs.TransactionResults = &v1.TransactionResults{
			// This field will be omitted for transactions that did not
			// create an asset (or for which we could not look up the block
			// it was created in), because computeAssetIndexFromTxn will
			// return 0 in that case.
			CreatedAssetIndex: computeAssetIndexFromTxn(txn, ledger),
		}

		response := TransactionResponse{
			Body: &responseTxs,
		}

		SendJSON(response, w, ctx.Log)
		return
	}

	// We didn't find it, return a failure
	lib.ErrorResponse(w, http.StatusNotFound, errors.New(errTransactionNotFound), errTransactionNotFound, ctx.Log)
	return
}

// GetPendingTransactions is an httpHandler for route GET /v1/transactions/pending.
func GetPendingTransactions(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/pending GetPendingTransactions
	// ---
	//     Summary: Get a list of unconfirmed transactions currently in the transaction pool.
	//     Description: >
	//       Get the list of pending transactions, sorted by priority,
	//       in decreasing order, truncated at the end at MAX. If MAX = 0,
	//       returns all pending transactions.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: max
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Truncated number of transactions to display. If max=0, returns all pending txns.
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/PendingTransactionsResponse'
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	max, err := strconv.ParseUint(r.FormValue("max"), 10, 64)
	if err != nil {
		max = 0
	}

	txs, err := ctx.Node.GetPendingTxnsFromPool()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
		return
	}

	totalTxns := uint64(len(txs))
	if max > 0 && totalTxns > max {
		// we expose this truncating mechanism for the client only, for the flexibility
		// to avoid dumping the whole pool over REST or in a cli. There is no need to optimize
		// fetching a smaller transaction set at a lower level.
		txs = txs[:max]
	}

	responseTxs := make([]v1.Transaction, len(txs))
	for i, twr := range txs {
		responseTxs[i], err = txEncode(twr.Txn, transactions.ApplyData{})
		if err != nil {
			// update the error as needed
			err = decorateUnknownTransactionTypeError(err, node.TxnWithStatus{Txn: twr})
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
			return
		}
	}

	response := PendingTransactionsResponse{
		Body: &v1.PendingTransactions{
			TruncatedTxns: v1.TransactionList{
				Transactions: responseTxs,
			},
			TotalTxns: totalTxns,
		},
	}

	SendJSON(response, w, ctx.Log)
}

// GetPendingTransactionsByAddress is an httpHandler for route GET /v1/account/addr:[A-Z0-9]{KeyLength}}/transactions/pending.
func GetPendingTransactionsByAddress(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{addr}/transactions/pending GetPendingTransactionsByAddress
	// ---
	//     Summary: Get a list of unconfirmed transactions currently in the transaction pool by address.
	//     Description: >
	//       Get the list of pending transactions by address, sorted by priority,
	//       in decreasing order, truncated at the end at MAX. If MAX = 0,
	//       returns all pending transactions.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: addr
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//       - name: max
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Truncated number of transactions to display. If max=0, returns all pending txns.
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/PendingTransactionsResponse'
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryMax := r.FormValue("max")
	max, err := strconv.ParseUint(queryMax, 10, 64)
	if queryMax != "" && err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedToParseMaxValue), errFailedToParseMaxValue, ctx.Log)
		return
	}

	queryAddr := mux.Vars(r)["addr"]
	if queryAddr == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoAccountSpecified), errNoAccountSpecified, ctx.Log)
		return
	}

	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAddress, ctx.Log)
		return
	}

	txs, err := ctx.Node.GetPendingTxnsFromPool()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
		return
	}

	responseTxs := make([]v1.Transaction, 0)
	for i, twr := range txs {
		if twr.Txn.Sender == addr || twr.Txn.Receiver == addr {
			// truncate in case max was passed
			if max > 0 && uint64(i) > max {
				break
			}

			tx, err := txEncode(twr.Txn, transactions.ApplyData{})
			responseTxs = append(responseTxs, tx)
			if err != nil {
				// update the error as needed
				err = decorateUnknownTransactionTypeError(err, node.TxnWithStatus{Txn: twr})
				lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
				return
			}
		}
	}

	response := PendingTransactionsResponse{
		Body: &v1.PendingTransactions{
			TruncatedTxns: v1.TransactionList{
				Transactions: responseTxs,
			},
			TotalTxns: uint64(len(responseTxs)),
		},
	}

	SendJSON(response, w, ctx.Log)
}

// AssetInformation is an httpHandler for route GET /v1/asset/{index:[0-9]+}
func AssetInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/asset/{index} AssetInformation
	// ---
	//     Summary: Get asset information.
	//     Description: >
	//       Given the asset's unique index, this call returns the asset's creator,
	//       manager, reserve, freeze, and clawback addresses
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: index
	//         in: path
	//         type: integer
	//         format: int64
	//         required: true
	//         description: Asset index
	//     Responses:
	//       200:
	//         "$ref": '#/responses/AssetInformationResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	queryIndex, err := strconv.ParseUint(mux.Vars(r)["index"], 10, 64)

	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAssetIndex, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	aidx := basics.AssetIndex(queryIndex)
	creator, err := ledger.GetAssetCreator(aidx)
	if err != nil {
		lib.ErrorResponse(w, http.StatusNotFound, err, errFailedToGetAssetCreator, ctx.Log)
		return
	}

	lastRound := ledger.Latest()
	record, err := ledger.Lookup(lastRound, creator)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
		return
	}

	if asset, ok := record.AssetParams[aidx]; ok {
		thisAssetParams := assetParams(creator, asset)
		SendJSON(AssetInformationResponse{&thisAssetParams}, w, ctx.Log)
	} else {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedRetrievingAsset), errFailedRetrievingAsset, ctx.Log)
		return
	}
}

// Assets is an httpHandler for route GET /v1/assets
func Assets(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/assets Assets
	// ---
	//     Summary: List assets
	//     Description: Returns list of up to `max` assets, where the maximum assetIdx is <= `assetIdx`
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: assetIdx
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Fetch assets with asset index <= assetIdx. If zero, fetch most recent assets.
	//       - name: max
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         maximum: 100
	//         required: false
	//         description: Fetch no more than this many assets
	//     Responses:
	//       200:
	//         "$ref": '#/responses/AssetsResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	const maxAssetsToList = 100

	// Parse max assets to fetch from db
	max, err := strconv.ParseInt(r.FormValue("max"), 10, 64)
	if err != nil || max < 0 || max > maxAssetsToList {
		err := fmt.Errorf(errFailedParsingMaxAssetsToList, 0, maxAssetsToList)
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	// Parse maximum asset idx
	assetIdx, err := strconv.ParseInt(r.FormValue("assetIdx"), 10, 64)
	if err != nil || assetIdx < 0 {
		errs := errFailedParsingAssetIdx
		lib.ErrorResponse(w, http.StatusBadRequest, errors.New(errs), errs, ctx.Log)
		return
	}

	// If assetIdx is 0, we want the most recent assets, so make it intmax
	if assetIdx == 0 {
		assetIdx = (1 << 63) - 1
	}

	// Query asset range from the database
	ledger := ctx.Node.Ledger()
	alocs, err := ledger.ListAssets(basics.AssetIndex(assetIdx), uint64(max))
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingAsset, ctx.Log)
		return
	}

	// Fill in the asset models
	lastRound := ledger.Latest()
	var result v1.AssetList
	for _, aloc := range alocs {
		// Fetch the asset parameters
		creatorRecord, err := ledger.Lookup(lastRound, aloc.Creator)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
			return
		}

		// Ensure no race with asset deletion
		rp, ok := creatorRecord.AssetParams[aloc.Index]
		if !ok {
			continue
		}

		// Append the result
		params := assetParams(aloc.Creator, rp)
		result.Assets = append(result.Assets, v1.Asset{
			AssetIndex:  uint64(aloc.Index),
			AssetParams: params,
		})
	}

	SendJSON(AssetsResponse{&result}, w, ctx.Log)
}

// SuggestedFee is an httpHandler for route GET /v1/transactions/fee
func SuggestedFee(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/fee SuggestedFee
	// ---
	//     Summary: Get the suggested fee
	//     Description: >
	//       Suggested Fee is returned in units of micro-Algos per byte.
	//       Suggested Fee may fall to zero but submitted transactions
	//       must still have a fee of at least MinTxnFee for the current
	//       network protocol.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/TransactionFeeResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	fee := v1.TransactionFee{Fee: ctx.Node.SuggestedFee().Raw}
	SendJSON(TransactionFeeResponse{&fee}, w, ctx.Log)
}

// SuggestedParams is an httpHandler for route GET /v1/transactions/params
func SuggestedParams(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/params TransactionParams
	// ---
	//     Summary: Get parameters for constructing a new transaction
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/TransactionParamsResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	stat, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	gh := ctx.Node.GenesisHash()

	var params v1.TransactionParams
	params.Fee = ctx.Node.SuggestedFee().Raw
	params.GenesisID = ctx.Node.GenesisID()
	params.GenesisHash = gh[:]
	params.LastRound = uint64(stat.LastRound)
	params.ConsensusVersion = string(stat.LastVersion)

	proto := config.Consensus[stat.LastVersion]
	params.MinTxnFee = proto.MinTxnFee

	SendJSON(TransactionParamsResponse{&params}, w, ctx.Log)
}

// GetBlock is an httpHandler for route GET /v1/block/{round}
func GetBlock(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/block/{round} GetBlock
	// ---
	//     Summary: Get the block for the given round.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: round
	//         in: path
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: true
	//         description: The round from which to fetch block information.
	//     Responses:
	//       200:
	//         "$ref": '#/responses/BlockResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	queryRound, err := strconv.ParseUint(mux.Vars(r)["round"], 10, 64)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	b, c, err := ledger.BlockCert(basics.Round(queryRound))
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
		return
	}
	block, err := blockEncode(b, c)

	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
		return
	}

	SendJSON(BlockResponse{&block}, w, ctx.Log)
}

// GetSupply is an httpHandler for route GET /v1/ledger/supply
func GetSupply(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/ledger/supply GetSupply
	//---
	//     Summary: Get the current supply reported by the ledger.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         "$ref": '#/responses/SupplyResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	latest := ctx.Node.Ledger().Latest()
	totals, err := ctx.Node.Ledger().Totals(latest)
	if err != nil {
		err = fmt.Errorf("GetSupply(): round %d failed: %v", latest, err)
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
		return
	}
	supply := v1.Supply{
		Round:       uint64(latest),
		TotalMoney:  totals.Participating().Raw,
		OnlineMoney: totals.Online.Money.Raw,
	}
	SendJSON(SupplyResponse{&supply}, w, ctx.Log)
}

func parseTime(t string) (res time.Time, err error) {
	// check for just date
	res, err = time.Parse("2006-01-02", t)
	if err == nil {
		return
	}

	// check for date and time
	res, err = time.Parse(time.RFC3339, t)
	if err == nil {
		return
	}

	return
}

// Transactions is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]+}/transactions
func Transactions(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{address}/transactions Transactions
	// ---
	//     Summary: Get a list of confirmed transactions.
	//     Description: Returns the list of confirmed transactions between within a date range. This call is available only when the indexer is running.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: address
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//       - name: firstRound
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Do not fetch any transactions before this round.
	//       - name: lastRound
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Do not fetch any transactions after this round.
	//       - name: fromDate
	//         in: query
	//         type: string
	//         format: date
	//         required: false
	//         description: Do not fetch any transactions before this date. (enabled only with indexer)
	//       - name: toDate
	//         in: query
	//         type: string
	//         format: date
	//         required: false
	//         description: Do not fetch any transactions after this date. (enabled only with indexer)
	//       - name: max
	//         in: query
	//         type: integer
	//         format: int64
	//         required: false
	//         description: maximum transactions to show (default to 100)
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionsResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryAddr := mux.Vars(r)["addr"]
	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAddress, ctx.Log)
		return
	}

	max, err := strconv.ParseUint(r.FormValue("max"), 10, 64)
	if err != nil {
		max = 100
	}

	// Get different params
	firstRound := r.FormValue("firstRound")
	lastRound := r.FormValue("lastRound")
	fromDate := r.FormValue("fromDate")
	toDate := r.FormValue("toDate")

	var rounds []uint64
	var txs []node.TxnWithStatus
	// Were rounds provided?
	if firstRound != "" && lastRound != "" {
		// Are they valid?
		fR, err := strconv.ParseUint(firstRound, 10, 64)
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
			return
		}

		lR, err := strconv.ParseUint(lastRound, 10, 64)
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
			return
		}

		txs, err = ctx.Node.ListTxns(addr, basics.Round(fR), basics.Round(lR))
		if err != nil {
			switch err.(type) {
			case ledger.ErrNoEntry:
				if !ctx.Node.IsArchival() {
					lib.ErrorResponse(w, http.StatusInternalServerError, err, errBlockHashBeenDeletedArchival, ctx.Log)
					return
				}
			}

			lib.ErrorResponse(w, http.StatusInternalServerError, err, err.Error(), ctx.Log)
			return
		}

	} else {
		// is indexer on?
		indexer, err := ctx.Node.Indexer()
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, errNoRoundsSpecified, ctx.Log)
			return
		}

		// Were dates provided?
		if fromDate != "" && toDate != "" {
			fd, err := parseTime(fromDate)
			if err != nil {
				lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
				return
			}

			td, err := parseTime(toDate)
			if err != nil {
				lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
				return
			}

			rounds, err = indexer.GetRoundsByAddressAndDate(addr.String(), max, fd.Unix(), td.Unix())
			if err != nil {
				lib.ErrorResponse(w, http.StatusInternalServerError, err, err.Error(), ctx.Log)
				return
			}

		} else {
			// return last [max] transactions
			rounds, err = indexer.GetRoundsByAddress(addr.String(), max)
			if err != nil {
				lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedGettingInformationFromIndexer, ctx.Log)
				return
			}
		}
	}

	if len(rounds) > 0 {
		for _, rnd := range rounds {
			txns, _ := ctx.Node.ListTxns(addr, basics.Round(rnd), basics.Round(rnd))
			txs = append(txs, txns...)

			// They may be more txns in the round than requested, break.
			if uint64(len(txs)) > max {
				break
			}
		}
	}

	// clip length to [max]
	if uint64(len(txs)) > max {
		txs = txs[:max]
	}

	responseTxs := make([]v1.Transaction, len(txs))
	for i, twr := range txs {
		responseTxs[i], err = txWithStatusEncode(twr)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}
	}

	response := TransactionsResponse{
		&v1.TransactionList{
			Transactions: responseTxs,
		},
	}

	SendJSON(response, w, ctx.Log)
}

// GetTransactionByID is an httpHandler for route GET /v1/transaction/{txid}
func GetTransactionByID(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transaction/{txid} Transaction
	// ---
	//     Summary: Get an information of a single transaction.
	//     Description: Returns the transaction information of the given txid. Works only if the indexer is enabled.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: txid
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]+"
	//         required: true
	//         description: A transaction id
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       404:
	//         description: Transaction Not Found
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	indexer, err := ctx.Node.Indexer()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errIndexerNotRunning, ctx.Log)
		return
	}

	queryTxID := mux.Vars(r)["txid"]
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	var txID transactions.Txid
	if err := txID.UnmarshalText([]byte(queryTxID)); err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	rnd, err := indexer.GetRoundByTXID(queryTxID)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedGettingInformationFromIndexer, ctx.Log)
		return
	}

	if txn, err := ctx.Node.GetTransactionByID(txID, basics.Round(rnd)); err == nil {
		var responseTxs v1.Transaction
		responseTxs, err = txWithStatusEncode(txn)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}

		response := TransactionResponse{
			Body: &responseTxs,
		}

		SendJSON(response, w, ctx.Log)
		return
	}

	// We didn't find it, return a failure
	lib.ErrorResponse(w, http.StatusNotFound, errors.New(errTransactionNotFound), errTransactionNotFound, ctx.Log)
	return
}
