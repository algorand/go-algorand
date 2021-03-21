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

var (
	errAppDoesNotExist                         = "application does not exist"
	errAssetDoesNotExist                       = "asset does not exist"
	errFailedLookingUpLedger                   = "failed to retrieve information from the ledger"
	errFailedLookingUpTransactionPool          = "failed to retrieve information from the transaction pool"
	errFailedRetrievingNodeStatus              = "failed retrieving node status"
	errFailedRetrievingLatestBlockHeaderStatus = "failed retrieving latests block header"
	errFailedParsingFormatOption               = "failed to parse the format option"
	errFailedToParseAddress                    = "failed to parse the address"
	errFailedToParseTransaction                = "failed to parse transaction"
	errFailedToParseBlock                      = "failed to parse block"
	errFailedToParseCert                       = "failed to parse cert"
	errFailedToEncodeResponse                  = "failed to encode response"
	errInternalFailure                         = "internal failure"
	errNoTxnSpecified                          = "no transaction ID was specified"
	errTransactionNotFound                     = "could not find the transaction in the transaction pool or in the last 1000 confirmed rounds"
	errServiceShuttingDown                     = "operation aborted as server is shutting down"
	errRequestedRoundInUnsupportedRound        = "requested round would reach only after the protocol upgrade which isn't supported"
	errRequestedBlockRoundIsNotAvailable       = "requested block for round %d is not available"
	errFailedToParseCatchpoint                 = "failed to parse catchpoint"
	errFailedToAbortCatchup                    = "failed to abort catchup : %v"
	errFailedToStartCatchup                    = "failed to start catchup : %v"
	errOperationNotAvailableDuringCatchup      = "operation not available during catchup"
)
