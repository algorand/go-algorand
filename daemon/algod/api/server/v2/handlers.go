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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/private"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
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
	InstallParticipationKey(partKeyBinary []byte) (account.ParticipationID, error)
	ListParticipationKeys() ([]account.ParticipationRecord, error)
	GetParticipationKey(account.ParticipationID) (account.ParticipationRecord, error)
	RemoveParticipationKey(account.ParticipationID) error
}

func roundToPtrOrNil(value basics.Round) *uint64 {
	if value == 0 {
		return nil
	}
	result := uint64(value)
	return &result
}

func convertParticipationRecord(record account.ParticipationRecord) generated.ParticipationKey {
	participationKey := generated.ParticipationKey{
		Id:      record.ParticipationID.String(),
		Address: record.Account.String(),
		Key: generated.AccountParticipation{
			VoteFirstValid:  uint64(record.FirstValid),
			VoteLastValid:   uint64(record.LastValid),
			VoteKeyDilution: record.KeyDilution,
		},
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
		zero := uint64(0)
		participationKey.EffectiveFirstValid = &zero
	} else {
		participationKey.EffectiveFirstValid = roundToPtrOrNil(record.EffectiveFirst)
	}
	participationKey.EffectiveLastValid = roundToPtrOrNil(record.EffectiveLast)
	participationKey.LastVote = roundToPtrOrNil(record.LastVote)
	participationKey.LastBlockProposal = roundToPtrOrNil(record.LastBlockProposal)
	participationKey.LastVote = roundToPtrOrNil(record.LastVote)
	participationKey.LastStateProof = roundToPtrOrNil(record.LastStateProof)

	return participationKey
}

// GetParticipationKeys Return a list of participation keys
// (GET /v2/participation)
func (v2 *Handlers) GetParticipationKeys(ctx echo.Context) error {
	partKeys, err := v2.Node.ListParticipationKeys()

	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	var response []generated.ParticipationKey

	for _, participationRecord := range partKeys {
		response = append(response, convertParticipationRecord(participationRecord))
	}

	return ctx.JSON(http.StatusOK, response)
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
		err := fmt.Errorf(errRESTPayloadZeroLength)
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	partID, err := v2.Node.InstallParticipationKey(partKeyBinary)

	if err != nil {
		return badRequest(ctx, err, err.Error(), v2.Log)
	}

	response := generated.PostParticipationResponse{PartId: partID.String()}
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

	consensus, err := myLedger.ConsensusParams(lastRound)
	if err != nil {
		return internalError(ctx, err, fmt.Sprintf("could not retrieve consensus information for last round (%d)", lastRound), v2.Log)
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

	account, err := AccountDataToAccount(address, &record, assetsCreators, lastRound, &consensus, amountWithoutPendingRewards)
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

// GetProof generates a Merkle proof for a transaction in a block.
// (GET /v2/blocks/{round}/transactions/{txid}/proof)
func (v2 *Handlers) GetProof(ctx echo.Context, round uint64, txid string, params generated.GetProofParams) error {
	var txID transactions.Txid
	err := txID.UnmarshalText([]byte(txid))
	if err != nil {
		return badRequest(ctx, err, errNoTxnSpecified, v2.Log)
	}

	ledger := v2.Node.Ledger()
	block, _, err := ledger.BlockCert(basics.Round(round))
	if err != nil {
		return internalError(ctx, err, errFailedLookingUpLedger, v2.Log)
	}

	proto := config.Consensus[block.CurrentProtocol]
	if proto.PaysetCommit != config.PaysetCommitMerkle {
		return notFound(ctx, err, "protocol does not support Merkle proofs", v2.Log)
	}

	txns, err := block.DecodePaysetFlat()
	if err != nil {
		return internalError(ctx, err, "decoding transactions", v2.Log)
	}

	for idx := range txns {
		if txns[idx].Txn.ID() == txID {
			tree, err := block.TxnMerkleTree()
			if err != nil {
				return internalError(ctx, err, "building Merkle tree", v2.Log)
			}

			proof, err := tree.Prove([]uint64{uint64(idx)})
			if err != nil {
				return internalError(ctx, err, "generating proof", v2.Log)
			}

			proofconcat := make([]byte, 0)
			for _, proofelem := range proof {
				proofconcat = append(proofconcat, proofelem[:]...)
			}

			stibhash := block.Payset[idx].Hash()

			response := generated.ProofResponse{
				Proof:    proofconcat,
				Stibhash: stibhash[:],
				Idx:      uint64(idx),
			}

			return ctx.JSON(http.StatusOK, response)
		}
	}

	err = errors.New(errTransactionNotFound)
	return notFound(ctx, err, err.Error(), v2.Log)
}

// GetSupply gets the current supply reported by the ledger.
// (GET /v2/ledger/supply)
func (v2 *Handlers) GetSupply(ctx echo.Context) error {
	latest, totals, err := v2.Node.Ledger().LatestTotals()
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
	err := decode(protocol.JSONStrictHandle, data, &gdr)
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

type preEncodedTxInfo struct {
	AssetIndex         *uint64                        `codec:"asset-index,omitempty"`
	AssetClosingAmount *uint64                        `codec:"asset-closing-amount,omitempty"`
	ApplicationIndex   *uint64                        `codec:"application-index,omitempty"`
	CloseRewards       *uint64                        `codec:"close-rewards,omitempty"`
	ClosingAmount      *uint64                        `codec:"closing-amount,omitempty"`
	ConfirmedRound     *uint64                        `codec:"confirmed-round,omitempty"`
	GlobalStateDelta   *generated.StateDelta          `codec:"global-state-delta,omitempty"`
	LocalStateDelta    *[]generated.AccountStateDelta `codec:"local-state-delta,omitempty"`
	PoolError          string                         `codec:"pool-error"`
	ReceiverRewards    *uint64                        `codec:"receiver-rewards,omitempty"`
	SenderRewards      *uint64                        `codec:"sender-rewards,omitempty"`
	Txn                transactions.SignedTxn         `codec:"txn"`
	Logs               *[][]byte                      `codec:"logs,omitempty"`
	Inners             *[]preEncodedTxInfo            `codec:"inner-txns,omitempty"`
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
	response := preEncodedTxInfo{
		Txn: txn.Txn,
	}

	if txn.ConfirmedRound != 0 {
		r := uint64(txn.ConfirmedRound)
		response.ConfirmedRound = &r

		response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
		response.AssetClosingAmount = &txn.ApplyData.AssetClosingAmount
		response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
		response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
		response.CloseRewards = &txn.ApplyData.CloseRewards.Raw
		response.AssetIndex = computeAssetIndexFromTxn(txn, v2.Node.Ledger())
		response.ApplicationIndex = computeAppIndexFromTxn(txn, v2.Node.Ledger())
		response.LocalStateDelta, response.GlobalStateDelta = convertToDeltas(txn)
		response.Logs = convertLogs(txn)
		response.Inners = convertInners(&txn)
	}

	handle, contentType, err := getCodecHandle(params.Format)
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

// startCatchup Given a catchpoint, it starts catching up to this catchpoint
func (v2 *Handlers) startCatchup(ctx echo.Context, catchpoint string) error {
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

	return ctx.JSON(code, private.CatchpointStartResponse{
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
	record, _, err := ledger.LookupWithoutRewards(lastRound, creator)
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
	record, _, err := ledger.LookupWithoutRewards(lastRound, creator)
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
	ops, err := logic.AssembleString(source)
	if err != nil {
		sb := strings.Builder{}
		ops.ReportProblems("", &sb)
		return badRequest(ctx, err, sb.String(), v2.Log)
	}
	pd := logic.HashProgram(ops.Program)
	addr := basics.Address(pd)
	response := generated.CompileResponse{
		Hash:   addr.String(),
		Result: base64.StdEncoding.EncodeToString(ops.Program),
	}
	return ctx.JSON(http.StatusOK, response)
}
