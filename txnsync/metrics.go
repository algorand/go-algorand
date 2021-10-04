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

package txnsync

import (
	"github.com/algorand/go-algorand/util/metrics"
)

var txsyncIncomingMessagesTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_txsync_incoming_messages_total", Description: "total number of incoming transaction sync messages"})
var txsyncUnprocessedIncomingMessagesTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_txsync_unprocessed_incoming_messages_total", Description: "total number of incoming transaction sync messages that were not processed"})
var txsyncDecodedBloomFiltersTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_txsync_decoded_bloom_filters_total", Description: "total number of decoded bloom filters"})
var txsyncCreatedPeersTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_txsync_created_peers_total", Description: "total number of created peers"})
var txsyncOutgoingMessagesTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_txsync_outgoing_messages_total", Description: "total number of outgoing transaction sync messages"})
var txsyncEncodedBloomFiltersTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_txsync_encoded_bloom_filters_total", Description: "total number of bloom filters encoded"})
