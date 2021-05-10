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

package telemetryspec

import (
	"strconv"
	"strings"
	"time"
)

// Telemetry metrics

// Metric is the type used to identify metrics
// We want these to be stable and easy to find / document so we can create queries against them.
type Metric string

// MetricDetails is an interface to be implemented by structs containing metrics for a specific identifier.
// The identifier is queried directly from the MetricDetails to simplify things.
type MetricDetails interface {
	Identifier() Metric
}

//-------------------------------------------------------
// AssembleBlock

// AssembleBlockStats is the set of stats captured when we compute AssemblePayset
type AssembleBlockStats struct {
	StartCount                int
	IncludedCount             int // number of transactions that are included in a block
	InvalidCount              int // number of transaction groups that are included in a block
	MinFee                    uint64
	MaxFee                    uint64
	AverageFee                uint64
	MinLength                 int
	MaxLength                 int
	MinPriority               uint64
	MaxPriority               uint64
	CommittedCount            int // number of transaction blocks that are included in a block
	StopReason                string
	TotalLength               uint64
	EarlyCommittedCount       uint64 // number of transaction groups that were pending on the transaction pool but have been included in previous block
	Nanoseconds               int64
	ProcessingTime            transactionProcessingTimeDistibution
	BlockGenerationDuration   uint64
	TransactionsLoopStartTime int64
}

// AssembleBlockTimeout represents AssemblePayset exiting due to timeout
const AssembleBlockTimeout = "timeout"

// AssembleBlockFull represents AssemblePayset exiting due to block being full
const AssembleBlockFull = "block-full"

// AssembleBlockEmpty represents AssemblePayset exiting due to no more txns
const AssembleBlockEmpty = "pool-empty"

// AssembleBlockAbandon represents the block generation being abandoned since it won't be needed.
const AssembleBlockAbandon = "block-abandon"

const assembleBlockMetricsIdentifier Metric = "AssembleBlock"

// AssembleBlockMetrics is the set of metrics captured when we compute AssemblePayset
type AssembleBlockMetrics struct {
	AssembleBlockStats
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m AssembleBlockMetrics) Identifier() Metric {
	return assembleBlockMetricsIdentifier
}

const transactionSyncProfilingMetricsIdentifier Metric = "SyncProfile"

// TransactionSyncProfilingMetrics is the profiling metrics of the recent transaction sync activity
type TransactionSyncProfilingMetrics struct {
	TotalOps                     uint64
	IdleOps                      uint64
	TransactionPoolChangedOps    uint64
	NewRoundOps                  uint64
	PeerStateOps                 uint64
	IncomingMsgOps               uint64
	OutgoingMsgOps               uint64
	NextOffsetOps                uint64
	GetTxnGroupsOps              uint64
	AssembleMessageOps           uint64
	SendMessageOps               uint64
	MakeBloomFilterOps           uint64
	SelectPendingTransactionsOps uint64

	TotalDuration                    uint64
	IdlePercent                      float64
	TransactionPoolChangedPercent    float64
	NewRoundPercent                  float64
	PeerStatePercent                 float64
	IncomingMsgPercent               float64
	OutgoingMsgPercent               float64
	NextOffsetPercent                float64
	GetTxnGroupsPercent              float64
	AssembleMessagePercent           float64
	SendMessagePercent               float64
	MakeBloomFilterPercent           float64
	SelectPendingTransactionsPercent float64
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m TransactionSyncProfilingMetrics) Identifier() Metric {
	return transactionSyncProfilingMetricsIdentifier
}

//-------------------------------------------------------
// ProcessBlock

const processBlockMetricsIdentifier Metric = "ProcessBlock"

// ProcessBlockMetrics is the set of metrics captured when we process OnNewBlock
type ProcessBlockMetrics struct {
	KnownCommittedCount   uint
	UnknownCommittedCount uint
	ExpiredCount          uint
	RemovedInvalidCount   uint
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m ProcessBlockMetrics) Identifier() Metric {
	return processBlockMetricsIdentifier
}

//-------------------------------------------------------
// RoundTiming

const roundTimingMetricsIdentifier Metric = "RoundTiming"

// RoundTimingMetrics contain timing details for common message types.
// All times (except round start time) are offset times, in int64 ns
// precision relative to RoundTimingMetrics.LRoundStart.
type RoundTimingMetrics struct {
	// We keep track of timingInfo for period 0 step <= 3 only, for brevity
	Round          uint64 `json:"round"`
	ConcludingStep uint64 `json:"laststep"`

	// Local Timings. Eventually, we could
	// attach timing information at the network layer to messages - but that is a
	// larger change I'd rather avoid for now. However, this means right now we
	// can only recover transit time information through telemetry, so we'll save
	// logging more thorough delivery distributions for a second pass. (-ben)
	LRoundStart time.Time `json:"lroundstart"`

	// LVotes contains times this player (would have) sent corresponding votes,
	// and times this player receives votes.
	LVotes map[uint64]LocalMsgTiming `json:"lvotes"`

	// LPayload contains times this player received payloads relevant to this round.
	LPayload LocalMsgTiming `json:"lpayload"`

	// BlockAssemble time specifies the duration from start of Round to Block Assembly completion
	BlockAssemble time.Duration `json:"lblockassemble"`

	// Payload Validation time contains the event times for Payload validation, once for each account
	PayloadValidation LocalMsgTiming `json:"lpayloadvalidation"`
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m RoundTimingMetrics) Identifier() Metric {
	return roundTimingMetricsIdentifier
}

//-------------------------------------------------------
// AccountsUpdate
const accountsUpdateMetricsIdentifier Metric = "AccountsUpdate"

// AccountsUpdateMetrics is the set of metrics captured when we process accountUpdates.commitRound
type AccountsUpdateMetrics struct {
	StartRound                uint64
	RoundsCount               uint64
	OldAccountPreloadDuration time.Duration
	MerkleTrieUpdateDuration  time.Duration
	AccountsWritingDuration   time.Duration
	DatabaseCommitDuration    time.Duration
	MemoryUpdatesDuration     time.Duration
	UpdatedAccountsCount      uint64
	UpdatedCreatablesCount    uint64
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m AccountsUpdateMetrics) Identifier() Metric {
	return accountsUpdateMetricsIdentifier
}

type transactionProcessingTimeDistibution struct {
	// 10 buckets: 0-100Kns, 100Kns-200Kns .. 900Kns-1ms
	// 9 buckets: 1ms-2ms .. 9ms-10ms
	// 9 buckets: 10ms-20ms .. 90ms-100ms
	// 9 buckets: 100ms-200ms .. 900ms-1s
	// 1 bucket: 1s+
	transactionBuckets [38]int
}

// MarshalJSON supports json.Marshaler interface
// generate comma delimited text representing the transaction processing timing
func (t transactionProcessingTimeDistibution) MarshalJSON() ([]byte, error) {
	var outStr strings.Builder
	outStr.WriteString("[")
	for i, bucket := range t.transactionBuckets {
		outStr.WriteString(strconv.Itoa(bucket))
		if i != len(t.transactionBuckets)-1 {
			outStr.WriteString(",")
		}
	}
	outStr.WriteString("]")
	return []byte(outStr.String()), nil
}

func (t *transactionProcessingTimeDistibution) AddTransaction(duration time.Duration) {
	var idx int64
	if duration < 10*time.Millisecond {
		if duration < time.Millisecond {
			idx = int64(duration / (100000 * time.Nanosecond))
		} else {
			idx = int64(10 + duration/(1*time.Millisecond))
		}
	} else {
		if duration < 100*time.Millisecond {
			idx = int64(19 + duration/(10*time.Millisecond))
		} else if duration < time.Second {
			idx = int64(28 + duration/(100*time.Millisecond))
		} else {
			idx = 37
		}
	}
	if idx >= 0 && idx <= 37 {
		t.transactionBuckets[idx]++
	}
}
