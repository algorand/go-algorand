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
	"context"
	"errors"
	"math"

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

// max compiled teal program is currently 8k
// but we allow for comments, spacing, and repeated consts
// in the source teal, allow up to 200kb
const maxTealSourceBytes = 200_000

// With the ability to hold unlimited assets DryrunRequests can
// become quite large, allow up to 1mb
const maxTealDryrunBytes = 1_000_000

// HandlerInterface provides the methods necessary for route implementations
type HandlerInterface interface {
	Register(e *echo.Echo, publicAuth echo.MiddlewareFunc, privateAuth echo.MiddlewareFunc)
	GetNode() node.BaseNodeInterface
}

func roundToPtrOrNil(value basics.Round) *uint64 {
	if value == 0 {
		return nil
	}
	result := uint64(value)
	return &result
}

func convertParticipationRecord(record account.ParticipationRecord) model.ParticipationKey {
	participationKey := model.ParticipationKey{
		Id:      record.ParticipationID.String(),
		Address: record.Account.String(),
		Key: model.AccountParticipation{
			VoteFirstValid:  uint64(record.FirstValid),
			VoteLastValid:   uint64(record.LastValid),
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

// ErrNoStateProofForRound returned when a state proof transaction could not be found
var ErrNoStateProofForRound = errors.New("no state proof can be found for that round")

// ErrTimeout indicates a task took too long, and the server canceled it.
var ErrTimeout = errors.New("timed out on request")

// ErrShutdown represents the error for the string errServiceShuttingDown
var ErrShutdown = errors.New(errServiceShuttingDown)

// GetStateProofTransactionForRound searches for a state proof transaction that can be used to prove on the given round (i.e the round is within the
// attestation period). the latestRound should be provided as an upper bound for the search
func GetStateProofTransactionForRound(ctx context.Context, txnFetcher ledger.LedgerForAPI, round, latestRound basics.Round, stop <-chan struct{}) (transactions.Transaction, error) {
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

		txns, err := txnFetcher.AddressTxns(transactions.StateProofSender, i)
		if err != nil {
			return transactions.Transaction{}, err
		}
		for _, txn := range txns {
			if txn.Txn.Type != protocol.StateProofTx {
				continue
			}

			if txn.Txn.StateProofTxnFields.Message.FirstAttestedRound <= uint64(round) &&
				uint64(round) <= txn.Txn.StateProofTxnFields.Message.LastAttestedRound {
				return txn.Txn, nil
			}
		}
	}
	return transactions.Transaction{}, ErrNoStateProofForRound
}

// PreEncodedTxInfo represents the PendingTransaction response before it is
// encoded to a format.
type PreEncodedTxInfo struct {
	AssetIndex         *uint64                    `codec:"asset-index,omitempty"`
	AssetClosingAmount *uint64                    `codec:"asset-closing-amount,omitempty"`
	ApplicationIndex   *uint64                    `codec:"application-index,omitempty"`
	CloseRewards       *uint64                    `codec:"close-rewards,omitempty"`
	ClosingAmount      *uint64                    `codec:"closing-amount,omitempty"`
	ConfirmedRound     *uint64                    `codec:"confirmed-round,omitempty"`
	GlobalStateDelta   *model.StateDelta          `codec:"global-state-delta,omitempty"`
	LocalStateDelta    *[]model.AccountStateDelta `codec:"local-state-delta,omitempty"`
	PoolError          string                     `codec:"pool-error"`
	ReceiverRewards    *uint64                    `codec:"receiver-rewards,omitempty"`
	SenderRewards      *uint64                    `codec:"sender-rewards,omitempty"`
	Txn                transactions.SignedTxn     `codec:"txn"`
	Logs               *[][]byte                  `codec:"logs,omitempty"`
	Inners             *[]PreEncodedTxInfo        `codec:"inner-txns,omitempty"`
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

// CompileResponseWithSourceMap overrides the sourcemap field in
// the CompileResponse for JSON marshalling.
type CompileResponseWithSourceMap struct {
	model.CompileResponse
	Sourcemap *logic.SourceMap `json:"sourcemap,omitempty"`
}
