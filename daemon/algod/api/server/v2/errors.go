// Copyright (C) 2019-2025 Algorand, Inc.
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

var (
	errAppDoesNotExist                         = "application does not exist"
	errAssetDoesNotExist                       = "asset does not exist"
	errAccountAppDoesNotExist                  = "account application info not found"
	errAccountAssetDoesNotExist                = "account asset info not found"
	errBoxDoesNotExist                         = "box not found"
	errFailedLookingUpLedger                   = "failed to retrieve information from the ledger"
	errFailedLookingUpTransactionPool          = "failed to retrieve information from the transaction pool"
	errFailedRetrievingStateDelta              = "failed retrieving State Delta: %v"
	errFailedRetrievingNodeStatus              = "failed retrieving node status"
	errFailedRetrievingLatestBlockHeaderStatus = "failed retrieving latest block header"
	errFailedRetrievingTimeStampOffset         = "failed retrieving timestamp offset from node: %v"
	errFailedSettingTimeStampOffset            = "failed to set timestamp offset on the node: %v"
	errFailedRetrievingSyncRound               = "failed retrieving sync round from ledger"
	errFailedSettingSyncRound                  = "failed to set sync round on the ledger"
	errFailedParsingFormatOption               = "failed to parse the format option"
	errFailedToGetPeers                        = "failed to get connected peers from node"
	errFailedToParseAddress                    = "failed to parse the address"
	errFailedToParseExclude                    = "failed to parse exclude"
	errFailedToEncodeResponse                  = "failed to encode response"
	errInternalFailure                         = "internal failure"
	errNoValidTxnSpecified                     = "no valid transaction ID was specified"
	errInvalidHashType                         = "invalid hash type"
	errTransactionNotFound                     = "could not find the transaction in the transaction pool or in the last 1000 confirmed rounds"
	errServiceShuttingDown                     = "operation aborted as server is shutting down"
	errRequestedRoundInUnsupportedRound        = "requested round would reach only after the protocol upgrade which isn't supported"
	errFailedToParseCatchpoint                 = "failed to parse catchpoint"
	errFailedToAbortCatchup                    = "failed to abort catchup : %v"
	errFailedToStartCatchup                    = "failed to start catchup : %v"
	errCatchpointWouldNotInitialize            = "the node has already been initialized"
	errOperationNotAvailableDuringCatchup      = "operation not available during catchup"
	errRESTPayloadZeroLength                   = "payload was of zero length"
	errRoundGreaterThanTheLatest               = "given round is greater than the latest round"
	errFailedRetrievingTracer                  = "failed retrieving the expected tracer from ledger"
)
