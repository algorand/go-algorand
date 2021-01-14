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

package handlers

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

func getNodeStatus(node *node.AlgorandFullNode) (res v1.NodeStatus, err error) {
	stat, err := node.Status()
	if err != nil {
		return v1.NodeStatus{}, err
	}

	return v1.NodeStatus{
		LastRound:                 uint64(stat.LastRound),
		LastVersion:               string(stat.LastVersion),
		NextVersion:               string(stat.NextVersion),
		NextVersionRound:          uint64(stat.NextVersionRound),
		NextVersionSupported:      stat.NextVersionSupported,
		TimeSinceLastRound:        stat.TimeSinceLastRound().Nanoseconds(),
		CatchupTime:               stat.CatchupTime.Nanoseconds(),
		StoppedAtUnsupportedRound: stat.StoppedAtUnsupportedRound,
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
	case protocol.ApplicationCallTx:
		res = applicationCallTxEncode(tx, ad)
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

	if tx.Group != (crypto.Digest{}) {
		res.Group = tx.Group[:]
	}

	if tx.Lease != ([32]byte{}) {
		res.Lease = tx.Lease[:]
	}

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

func participationKeysEncode(r basics.AccountData) *v1.Participation {
	var apiParticipation v1.Participation
	apiParticipation.ParticipationPK = r.VoteID[:]
	apiParticipation.VRFPK = r.SelectionID[:]
	apiParticipation.VoteFirst = uint64(r.VoteFirstValid)
	apiParticipation.VoteLast = uint64(r.VoteLastValid)
	apiParticipation.VoteKeyDilution = r.VoteKeyDilution

	return &apiParticipation
}

func modelAssetParams(creator basics.Address, params basics.AssetParams) v1.AssetParams {
	paramsModel := v1.AssetParams{
		Total:         params.Total,
		DefaultFrozen: params.DefaultFrozen,
		Decimals:      params.Decimals,
	}

	paramsModel.UnitName = strings.TrimRight(params.UnitName[:], "\x00")
	paramsModel.AssetName = strings.TrimRight(params.AssetName[:], "\x00")
	paramsModel.URL = strings.TrimRight(params.URL[:], "\x00")
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

func modelSchema(schema basics.StateSchema) *v1.StateSchema {
	return &v1.StateSchema{
		NumUint:      schema.NumUint,
		NumByteSlice: schema.NumByteSlice,
	}
}

func modelValue(v basics.TealValue) v1.TealValue {
	return v1.TealValue{
		Type:  v.Type.String(),
		Bytes: base64.StdEncoding.EncodeToString([]byte(v.Bytes)),
		Uint:  v.Uint,
	}
}

func modelTealKeyValue(kv basics.TealKeyValue) map[string]v1.TealValue {
	b64 := base64.StdEncoding
	res := make(map[string]v1.TealValue, len(kv))
	for key, value := range kv {
		kenc := b64.EncodeToString([]byte(key))
		res[kenc] = modelValue(value)
	}
	return res
}

func modelAppParams(creator basics.Address, params basics.AppParams) v1.AppParams {
	b64 := base64.StdEncoding
	res := v1.AppParams{
		ApprovalProgram:   b64.EncodeToString(params.ApprovalProgram),
		ClearStateProgram: b64.EncodeToString(params.ClearStateProgram),
		GlobalStateSchema: modelSchema(params.GlobalStateSchema),
		LocalStateSchema:  modelSchema(params.LocalStateSchema),
		GlobalState:       modelTealKeyValue(params.GlobalState),
	}
	if !creator.IsZero() {
		res.Creator = creator.String()
	}
	return res
}

func modelAppLocalState(s basics.AppLocalState) v1.AppLocalState {
	return v1.AppLocalState{
		Schema:   modelSchema(s.Schema),
		KeyValue: modelTealKeyValue(s.KeyValue),
	}
}

func assetConfigTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	params := modelAssetParams(basics.Address{}, tx.AssetConfigTxnFields.AssetParams)

	config := v1.AssetConfigTransactionType{
		AssetID: uint64(tx.AssetConfigTxnFields.ConfigAsset),
		Params:  params,
	}

	return v1.Transaction{
		AssetConfig: &config,
	}
}

func applicationCallTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	b64 := base64.StdEncoding
	app := v1.ApplicationCallTransactionType{
		ApplicationID:     uint64(tx.ApplicationID),
		ApprovalProgram:   b64.EncodeToString(tx.ApprovalProgram),
		ClearStateProgram: b64.EncodeToString(tx.ClearStateProgram),
		LocalStateSchema:  modelSchema(tx.LocalStateSchema),
		GlobalStateSchema: modelSchema(tx.GlobalStateSchema),
		OnCompletion:      tx.OnCompletion.String(),
	}

	encodedAccounts := make([]string, 0, len(tx.Accounts))
	for _, addr := range tx.Accounts {
		encodedAccounts = append(encodedAccounts, addr.String())
	}

	encodedForeignApps := make([]uint64, 0, len(tx.ForeignApps))
	for _, aidx := range tx.ForeignApps {
		encodedForeignApps = append(encodedForeignApps, uint64(aidx))
	}

	encodedForeignAssets := make([]uint64, 0, len(tx.ForeignAssets))
	for _, aidx := range tx.ForeignAssets {
		encodedForeignAssets = append(encodedForeignAssets, uint64(aidx))
	}

	encodedArgs := make([]string, 0, len(tx.ApplicationArgs))
	for _, arg := range tx.ApplicationArgs {
		encodedArgs = append(encodedArgs, b64.EncodeToString(arg))
	}

	app.Accounts = encodedAccounts
	app.ApplicationArgs = encodedArgs
	app.ForeignApps = encodedForeignApps
	app.ForeignAssets = encodedForeignAssets
	return v1.Transaction{
		ApplicationCall: &app,
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

func computeCreatableIndexInPayset(tx node.TxnWithStatus, txnCounter uint64, payset []transactions.SignedTxnWithAD) (aidx uint64) {
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

	return computeCreatableIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset)
}

// computeAppIndexFromTxn returns the created app index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAppIndexFromTxn(tx node.TxnWithStatus, l *data.Ledger) (aidx uint64) {
	// Must have ledger
	if l == nil {
		return 0
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return 0
	}
	// Transaction must be ApplicationCall transaction
	if tx.Txn.Txn.ApplicationCallTxnFields.Empty() {
		return 0
	}
	// Transaction must be creating an application
	if tx.Txn.Txn.ApplicationCallTxnFields.ApplicationID != 0 {
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

	return computeCreatableIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset)
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
func Status(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer

	nodeStatus, err := getNodeStatus(ctx.Node)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	response := StatusResponse{&nodeStatus}
	SendJSON(response, w, ctx.Log)
}

// WaitForBlock is an httpHandler for route GET /v1/status/wait-for-block-after/{round:[0-9]+}
func WaitForBlock(ctx lib.ReqContext, context echo.Context) {
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
	//       401: { description: Invalid API Token }
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       503:
	//         description: Service
	//         schema: {type: string}
	//       default: { description: Unknown Error }

	w := context.Response().Writer

	queryRound, err := strconv.ParseUint(context.Param("round"), 10, 64)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	latestBlkHdr, err := ledger.BlockHdr(ledger.Latest())
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}
	if latestBlkHdr.NextProtocol != "" {
		if _, nextProtocolSupported := config.Consensus[latestBlkHdr.NextProtocol]; !nextProtocolSupported {
			// see if the desired protocol switch is expect to happen before or after the above point.
			if latestBlkHdr.NextProtocolSwitchOn <= basics.Round(queryRound+1) {
				// we would never reach to this round, since this round would happen after the (unsupported) protocol upgrade.
				lib.ErrorResponse(w, http.StatusBadRequest, err, errRequestedRoundInUnsupportedRound, ctx.Log)
				return
			}
		}
	}

	internalNodeStatus, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
	}

	if internalNodeStatus.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		lib.ErrorResponse(w, http.StatusServiceUnavailable, fmt.Errorf("WaitForBlock failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, ctx.Log)
		return
	}

	select {
	case <-ctx.Shutdown:
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errServiceShuttingDown, ctx.Log)
		return
	case <-time.After(1 * time.Minute):
	case <-ledger.Wait(basics.Round(queryRound + 1)):
	}

	nodeStatus, err := getNodeStatus(ctx.Node)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	response := StatusResponse{&nodeStatus}
	SendJSON(response, w, ctx.Log)
}

// RawTransaction is an httpHandler for route POST /v1/transactions
func RawTransaction(ctx lib.ReqContext, context echo.Context) {
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
	//       401: { description: Invalid API Token }
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       503:
	//         description: Service Unavailable
	//         schema: {type: string}
	//       default: { description: Unknown Error }

	w := context.Response().Writer
	r := context.Request()

	stat, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		lib.ErrorResponse(w, http.StatusServiceUnavailable, fmt.Errorf("RawTransaction failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, ctx.Log)
		return
	}
	proto := config.Consensus[stat.LastVersion]

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

		if len(txgroup) > proto.MaxTxGroupSize {
			err := fmt.Errorf("max group size is %d", proto.MaxTxGroupSize)
			lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
			return
		}
	}

	if len(txgroup) == 0 {
		err := errors.New("empty txgroup")
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	err = ctx.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	SendJSON(TransactionIDResponse{&v1.TransactionID{TxID: txid.String()}}, w, ctx.Log)
}

// AccountInformation is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]{KeyLength}}
func AccountInformation(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer

	queryAddr := context.Param("addr")

	if queryAddr == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoAccountSpecified), errNoAccountSpecified, ctx.Log)
		return
	}

	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAddress, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	lastRound := ledger.Latest()
	record, err := ledger.Lookup(lastRound, addr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
		return
	}
	recordWithoutPendingRewards, _, err := ledger.LookupWithoutRewards(lastRound, addr)
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
			creatorAddr, ok, err := ledger.GetCreator(basics.CreatableIndex(curid), basics.AssetCreatable)
			if err == nil && ok {
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

	var assetParams map[uint64]v1.AssetParams
	if len(record.AssetParams) > 0 {
		assetParams = make(map[uint64]v1.AssetParams, len(record.AssetParams))
		for idx, params := range record.AssetParams {
			assetParams[uint64(idx)] = modelAssetParams(addr, params)
		}
	}

	var apps map[uint64]v1.AppLocalState
	if len(record.AppLocalStates) > 0 {
		apps = make(map[uint64]v1.AppLocalState, len(record.AppLocalStates))
		for idx, state := range record.AppLocalStates {
			apps[uint64(idx)] = modelAppLocalState(state)
		}
	}

	var appParams map[uint64]v1.AppParams
	if len(record.AppParams) > 0 {
		appParams = make(map[uint64]v1.AppParams, len(record.AppParams))
		for idx, params := range record.AppParams {
			appParams[uint64(idx)] = modelAppParams(addr, params)
		}
	}

	var apiParticipation *v1.Participation
	if record.VoteID != (crypto.OneTimeSignatureVerifier{}) {
		apiParticipation = participationKeysEncode(record)
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
		AssetParams:                 assetParams,
		Assets:                      assets,
		AppParams:                   appParams,
		AppLocalStates:              apps,
	}

	SendJSON(AccountInformationResponse{&accountInfo}, w, ctx.Log)
}

// TransactionInformation is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]{KeyLength}}/transaction/{txid:[A-Z0-9]+}
func TransactionInformation(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer

	queryTxID := context.Param("txid")
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	txID := transactions.Txid{}
	if txID.UnmarshalText([]byte(queryTxID)) != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	queryAddr := context.Param("addr")
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
func PendingTransactionInformation(ctx lib.ReqContext, context echo.Context) {
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
	//       503:
	//         description: Service Unavailable
	//         schema: {type: string}
	//       default: { description: Unknown Error }

	w := context.Response().Writer

	queryTxID := context.Param("txid")
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	txID := transactions.Txid{}
	if txID.UnmarshalText([]byte(queryTxID)) != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	internalNodeStatus, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
	}
	if internalNodeStatus.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		lib.ErrorResponse(w, http.StatusServiceUnavailable, fmt.Errorf("PendingTransactionInformation failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, ctx.Log)
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
			// create an app/asset (or for which we could not look up the
			// block it was created in), because compute{App|Asset}IndexFromTxn
			// will return 0 in that case.
			CreatedAssetIndex: computeAssetIndexFromTxn(txn, ledger),
			CreatedAppIndex:   computeAppIndexFromTxn(txn, ledger),
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
func GetPendingTransactions(ctx lib.ReqContext, context echo.Context) {
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
	//       401: { description: Invalid API Token }
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       503:
	//         description: Service Unavailable
	//         schema: {type: string}
	//       default: { description: Unknown Error }

	w := context.Response().Writer
	r := context.Request()

	max, err := strconv.ParseUint(r.FormValue("max"), 10, 64)
	if err != nil {
		max = 0
	}

	internalNodeStatus, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
	}
	if internalNodeStatus.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		lib.ErrorResponse(w, http.StatusServiceUnavailable, fmt.Errorf("GetPendingTransactions failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, ctx.Log)
		return
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
func GetPendingTransactionsByAddress(ctx lib.ReqContext, context echo.Context) {
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
	//       401: { description: Invalid API Token }
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       503:
	//         description: Service Unavailable
	//         schema: {type: string}
	//       default: { description: Unknown Error }

	w := context.Response().Writer
	r := context.Request()

	queryMax := r.FormValue("max")
	max, err := strconv.ParseUint(queryMax, 10, 64)
	if queryMax != "" && err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedToParseMaxValue), errFailedToParseMaxValue, ctx.Log)
		return
	}

	queryAddr := context.Param("addr")
	if queryAddr == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoAccountSpecified), errNoAccountSpecified, ctx.Log)
		return
	}

	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAddress, ctx.Log)
		return
	}

	internalNodeStatus, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
	}

	if internalNodeStatus.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		lib.ErrorResponse(w, http.StatusServiceUnavailable, fmt.Errorf("GetPendingTransactionsByAddress failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, ctx.Log)
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
func AssetInformation(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer

	queryIndex, err := strconv.ParseUint(context.Param("index"), 10, 64)

	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAssetIndex, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	aidx := basics.AssetIndex(queryIndex)
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(aidx), basics.AssetCreatable)
	if err != nil || !ok {
		// Treat a database error and a nonexistent application the
		// same to avoid changing API behavior
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
		thisAssetParams := modelAssetParams(creator, asset)
		SendJSON(AssetInformationResponse{&thisAssetParams}, w, ctx.Log)
	} else {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedRetrievingAsset), errFailedRetrievingAsset, ctx.Log)
		return
	}
}

// Assets is an httpHandler for route GET /v1/assets
func Assets(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer
	r := context.Request()

	const maxAssetsToList = 100

	var err error
	var max int64 = maxAssetsToList
	var assetIdx int64 = 0

	// Parse max assets to fetch from db
	if r.PostFormValue("max") != "" {
		max, err = strconv.ParseInt(r.FormValue("max"), 10, 64)
		if err != nil || max < 0 || max > maxAssetsToList {
			err := fmt.Errorf(errFailedParsingMaxAssetsToList, 0, maxAssetsToList)
			lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
			return
		}
	}

	// Parse maximum asset idx
	if r.PostFormValue("assetIdx") != "" {
		assetIdx, err = strconv.ParseInt(r.FormValue("assetIdx"), 10, 64)
		if err != nil || assetIdx < 0 {
			errs := errFailedParsingAssetIdx
			lib.ErrorResponse(w, http.StatusBadRequest, errors.New(errs), errs, ctx.Log)
			return
		}
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
		rp, ok := creatorRecord.AssetParams[basics.AssetIndex(aloc.Index)]
		if !ok {
			continue
		}

		// Append the result
		params := modelAssetParams(aloc.Creator, rp)
		result.Assets = append(result.Assets, v1.Asset{
			AssetIndex:  uint64(aloc.Index),
			AssetParams: params,
		})
	}

	SendJSON(AssetsResponse{&result}, w, ctx.Log)
}

// SuggestedFee is an httpHandler for route GET /v1/transactions/fee
func SuggestedFee(ctx lib.ReqContext, context echo.Context) {
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
	//       503:
	//         description: Service Unavailable
	//         schema: {type: string}
	//       default: { description: Unknown Error }

	w := context.Response().Writer

	internalNodeStatus, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
	}

	if internalNodeStatus.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		lib.ErrorResponse(w, http.StatusServiceUnavailable, fmt.Errorf("SuggestedFee failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, ctx.Log)
		return
	}

	fee := v1.TransactionFee{Fee: ctx.Node.SuggestedFee().Raw}
	SendJSON(TransactionFeeResponse{&fee}, w, ctx.Log)
}

// SuggestedParams is an httpHandler for route GET /v1/transactions/params
func SuggestedParams(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer

	stat, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}
	if stat.Catchpoint != "" {
		// node is currently catching up to the requested catchpoint.
		lib.ErrorResponse(w, http.StatusServiceUnavailable, fmt.Errorf("SuggestedParams failed as the node was catchpoint catchuping"), errOperationNotAvailableDuringCatchup, ctx.Log)
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
func GetBlock(ctx lib.ReqContext, context echo.Context) {
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
	//       - name: raw
	//         in: query
	//         type: integer
	//         format: int64
	//         required: false
	//         description: Return raw msgpack block bytes
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

	w := context.Response().Writer
	r := context.Request()

	queryRound, err := strconv.ParseUint(context.Param("round"), 10, 64)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
		return
	}

	// raw msgpack option:
	rawstr := r.FormValue("raw")
	if rawstr != "" {
		rawint, err := strconv.ParseUint(rawstr, 10, 64)
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRawOption, ctx.Log)
			return
		}
		if rawint != 0 {
			blockbytes, err := rpcs.RawBlockBytes(ctx.Node.Ledger(), basics.Round(queryRound))
			if err != nil {
				lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
				return
			}
			w.Header().Set("Content-Type", rpcs.BlockResponseContentType)
			w.Header().Set("Content-Length", strconv.Itoa(len(blockbytes)))
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(blockbytes)
			if err != nil {
				ctx.Log.Warnf("algod failed to write an object to the response stream: %v", err)
			}
			return
		}
	}

	// decoded json-reencoded default:
	ledger := ctx.Node.Ledger()
	b, c, err := ledger.BlockCert(basics.Round(queryRound))
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
		return
	}

	if len(c.Votes) == 0 && c.Round > basics.Round(0) {
		lib.ErrorResponse(w, http.StatusNotFound, err, errCertificateIsMissingFromBlock, ctx.Log)
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
func GetSupply(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer

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
func Transactions(ctx lib.ReqContext, context echo.Context) {
	// swagger:operation GET /v1/account/{address}/transactions Transactions
	// ---
	//     Summary: Get a list of confirmed transactions.
	//     Description: Returns the list of confirmed transactions between within a date range. When indexer is disabled this call requires firstRound and lastRound and returns an error if firstRound is not available to the node. The transaction results start from the oldest round.
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

	w := context.Response().Writer
	r := context.Request()

	queryAddr := context.Param("addr")
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
			case ledgercore.ErrNoEntry:
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
func GetTransactionByID(ctx lib.ReqContext, context echo.Context) {
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

	w := context.Response().Writer

	indexer, err := ctx.Node.Indexer()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errIndexerNotRunning, ctx.Log)
		return
	}

	queryTxID := context.Param("txid")
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
	if err == sql.ErrNoRows {
		lib.ErrorResponse(w, http.StatusNotFound, err, errTransactionNotFound, ctx.Log)
		return
	}
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
