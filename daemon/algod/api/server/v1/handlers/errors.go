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

var (
	errBlockHashBeenDeletedArchival        = "this is a non-archival node and the requested block has been already deleted"
	errFailedGettingInformationFromIndexer = "failed retrieving information from the indexer"
	errFailedLookingUpLedger               = "failed to retrieve information from the ledger"
	errFailedLookingUpTransactionPool      = "failed to retrieve information from the transaction pool"
	errFailedRetrievingNodeStatus          = "failed retrieving node status"
	errFailedParsingRoundNumber            = "failed to parse the round number"
	errFailedToParseAddress                = "failed to parse the address"
	errFailedToParseTransaction            = "failed to parse transaction"
	errInternalFailure                     = "internal failure"
	errIndexerNotRunning                   = "indexer isn't running, this call is disabled"
	errInvalidTransactionTypeLedger        = "a transaction with invalid type field was found in ledger - type %s, transaction #%s, round %d"
	errInvalidTransactionTypePending       = "a transaction with invalid type field was found in transaction pool - type %s, transaction #%s"
	errNoAccountSpecified                  = "no address was specified"
	errNoRoundsSpecified                   = "Indexer is not enabled, firstRound and lastRound must be specified"
	errNoTxnSpecified                      = "no transaction ID was specified"
	errTransactionNotFound                 = "couldn't find the required transaction in the required range"
	errUnknownTransactionType              = "found a transaction with an unknown type"
)
